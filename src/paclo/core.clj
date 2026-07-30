(ns paclo.core
  "Public, data-first facade for Paclo.

  Main entry points:
  - `packets` for live/offline capture as lazy sequences
  - `packet-xf` for composable packet decoding and flow projection
  - `reduce-packets` for synchronous, low-allocation reduction
  - `reduce-packets-report` for synchronous results plus execution statistics
  - `start-capture` for explicitly managed capture lifecycles
  - `bpf` for BPF DSL -> string conversion
  - `write-pcap!` for writing packet byte sequences"
  (:require
   [clojure.string :as str]
   [paclo.capture :as capture]
   [paclo.decode-ext :as decode-ext]
   [paclo.flow :as flow]
   [paclo.parse :as parse]
   [paclo.pcap  :as pcap])
  (:import
   [java.io Closeable]
   [java.util.concurrent.atomic LongAdder]))

;; BPF DSL -> string
(defn ^:private paren [s] (str "(" s ")"))

(defn bpf
  "Convert a BPF DSL value into a libpcap filter string.

  Accepted input:
  - `nil` -> `nil`
  - string -> returned as-is
  - keyword protocol (`:udp`, `:tcp`, `:icmp`, `:icmp6`, `:arp`, `:ip`, `:ipv4`, `:ip6`, `:ipv6`)
  - vector DSL form (`:and`, `:or`, `:not`, `:proto`, host/net/port forms)

  Throws `ex-info` for unsupported forms/operators/keywords."
  [form]
  (letfn [(kw-proto [k]
            (case k
              :udp "udp" :tcp "tcp" :icmp "icmp" :icmp6 "icmp6" :arp "arp"
              :ip "ip" :ipv4 "ip" :ip4 "ip"
              :ip6 "ip6" :ipv6 "ip6"
              (throw (ex-info "unknown proto keyword" {:proto k}))))
          (as-int [x]
            (if (number? x)
              (int x)
              (Integer/parseInt (str x))))]
    (cond
      (nil? form) nil
      (string? form) form

      (keyword? form)
      (kw-proto form)

      (vector? form)
      (let [[op & args] form]
        (case op
          ;; Logic
          :and (->> args (map bpf) (map paren) (str/join " and "))
          :or  (->> args (map bpf) (map paren) (str/join " or "))
          :not (str "not " (paren (bpf (first args))))

          ;; Protocol selector
          :proto (kw-proto (first args))

          ;; Host/net
          :host     (str "host "     (first args))
          :src-host (str "src host " (first args))
          :dst-host (str "dst host " (first args))
          :net      (str "net "      (first args))
          :src-net  (str "src net "  (first args))
          :dst-net  (str "dst net "  (first args))

          ;; Single port
          :port     (str "port "     (as-int (first args)))
          :src-port (str "src port " (as-int (first args)))
          :dst-port (str "dst port " (as-int (first args)))

          ;; Port range
          :port-range
          (let [[a b] args] (str "portrange " (as-int a) "-" (as-int b)))
          :src-port-range
          (let [[a b] args] (str "src portrange " (as-int a) "-" (as-int b)))
          :dst-port-range
          (let [[a b] args] (str "dst portrange " (as-int a) "-" (as-int b)))

          ;; Compatibility: allow top-level keyword forms in vectors too
          :udp "udp" :tcp "tcp" :icmp "icmp" :icmp6 "icmp6" :arp "arp"
          :ip "ip" :ipv4 "ip" :ip4 "ip" :ip6 "ip6" :ipv6 "ip6"

          (throw (ex-info "unknown op in bpf" {:form form :op op}))))
      :else
      (throw (ex-info "unsupported bpf form" {:form form})))))

;; Stream API
(def ^:private ETH_MIN_HDR 14)

(defn ^:private decode-result
  "Call `parse/packet->clj` and return a tagged result map."
  [^bytes ba]
  (try
    {:ok true :value (parse/packet->clj ba)}
    (catch Throwable e
      {:ok false :error (or (.getMessage e) (str e))})))

(defn ^:private decode-packet
  [m]
  (let [ba ^bytes (:bytes m)]
    (if (and ba (>= (long (alength ba)) (long ETH_MIN_HDR)))
      (let [{:keys [ok value error]} (decode-result ba)
            m' (cond-> m
                 ok       (assoc :decoded value)
                 (not ok) (assoc :decode-error error))]
        (if (contains? m' :decoded)
          (decode-ext/apply! m')
          m'))
      (assoc m :decode-error
             (str "frame too short: " (when ba (alength ba)) " bytes")))))

(defn ^:private normalize-filter [filter]
  (cond
    (string? filter) filter
    (or (keyword? filter) (vector? filter)) (bpf filter)
    (nil? filter) nil
    :else (throw (ex-info "invalid :filter" {:filter filter}))))

(defn ^:private flow-packet [packet]
  (try
    (flow/project-packet packet)
    (catch Throwable error
      {:ts-sec (:ts-sec packet)
       :ts-usec (:ts-usec packet)
       :caplen (:caplen packet)
       :len (:len packet)
       :decode-error (or (.getMessage error) (str error))})))

(defn ^:private apply-xform
  "Apply transducer `xf` with `sequence` when present; otherwise return `s`."
  [s xf]
  (if (some? xf) (sequence xf s) s))

(defn ^:private validate-decode-opts
  [{:keys [decode? decode-mode]}]
  (when (and decode? decode-mode)
    (throw (ex-info ":decode? and :decode-mode cannot be combined"
                    {:decode? decode? :decode-mode decode-mode})))
  (when-not (contains? #{nil :flow} decode-mode)
    (throw (ex-info "unsupported :decode-mode"
                    {:decode-mode decode-mode}))))

(defn packet-xf
  "Return a transducer that applies Paclo's packet transformation contract.

   Options:
   - `:decode? true` performs the compatible full decode
   - `:decode-mode :flow` projects packets to flat, numeric flow maps

   The two options are mutually exclusive. Decode failures are returned as
   packet maps containing `:decode-error`."
  [{:keys [decode? decode-mode] :as opts}]
  (validate-decode-opts opts)
  (cond
    (= decode-mode :flow) (map flow-packet)
    decode? (map decode-packet)
    :else identity))

(defn ^:private packet-pipeline-xf
  "Compose Paclo's packet transform before subsequent transducers.

   Return nil for the raw pass-through path so capture reduction retains its
   existing zero-wrapper fast path."
  [{:keys [decode? decode-mode] :as opts} & xforms]
  (let [decode-xf (packet-xf opts)
        xforms* (remove nil? xforms)]
    (when (or decode? decode-mode (seq xforms*))
      (apply comp decode-xf xforms*))))

(defn ^:private normalized-opts
  [{:keys [filter] :as opts}]
  (validate-decode-opts opts)
  (let [filter* (normalize-filter filter)]
    (cond-> opts (some? filter*) (assoc :filter filter*))))

(defn packets
  "Return packets as a lazy sequence.

  Key opts:
  - source: `:path` (offline) or `:device` (live)
  - `:filter`: BPF string, protocol keyword, or BPF DSL vector
  - `:decode?`: when true, add `:decoded` or `:decode-error` to each packet map
  - `:decode-mode :flow`: project packets to flat, numeric flow maps
  - `:xform`: transducer applied to output stream via `sequence`
  - live queue: `:queue-cap`, opt-in `:queue-mode :dropping`, and
    `:on-queue-stats`

  Throws `ex-info` when `:filter` has an unsupported type."
  [{:keys [xform] :as opts}]
  (let [opts* (normalized-opts opts)
        stream-xf (packet-pipeline-xf opts* xform)
        base (pcap/capture->seq opts*)]
    (apply-xform base stream-xf)))

(defn reduce-packets
  "Synchronously reduce live or offline packets without an intermediate seq.

   `(reduce-packets opts rf init)` accepts the same source, BPF, decode,
   transducer, stopping, and error options as `packets`. The transducer in
   `:xform` is fused into the reducing function. Returning `reduced` from `rf`
   stops capture immediately."
  [{:keys [xform] :as opts} rf init]
  (let [opts* (normalized-opts opts)
        complete-rf (completing rf)
        stream-xf (packet-pipeline-xf opts* xform)
        transformed-rf (if stream-xf
                         (stream-xf complete-rf)
                         complete-rf)
        result (pcap/reduce-capture opts* transformed-rf init)]
    (transformed-rf result)))

(defn reduce-packets-report
  "Synchronously reduce packets and return `{:result value :stats map}`.

   Processing behavior matches `reduce-packets`. The statistics map has a
   schema version, source, timing, packet counts, optional live libpcap
   counters, the stop reason, and a data-only error description."
  [{:keys [xform] :as opts} rf init]
  (let [opts* (normalized-opts opts)
        decode-errors (LongAdder.)
        complete-rf (completing rf)
        stats-xf
        (map
         (fn [packet]
           (when (:decode-error packet)
             (.increment decode-errors))
           packet))
        stream-xf (packet-pipeline-xf opts* stats-xf xform)
        transformed-rf (stream-xf complete-rf)
        {:keys [result stats]}
        (pcap/reduce-capture-report opts* transformed-rf init)]
    {:result (transformed-rf result)
     :stats (assoc-in stats
                      [:packets :decode-errors]
                      (.sum decode-errors))}))

(deftype ^:private Capture
         [managed
          opts
          ^LongAdder processed
          ^LongAdder decode-errors]
  Closeable
  (close [_]
    (.close ^Closeable managed)))

(defn start-capture
  "Start a managed live or offline capture.

   The returned opaque handle implements `java.io.Closeable` and should be
   owned by `with-open`. Startup is synchronous through source open and BPF
   installation. Packet delivery is single-consumer."
  [opts]
  (let [opts* (normalized-opts opts)]
    (Capture. (capture/start opts*)
              opts*
              (LongAdder.)
              (LongAdder.))))

(defn ^:private ensure-capture [value]
  (when-not (instance? Capture value)
    (throw (ex-info "not a paclo capture" {:capture value})))
  value)

(defn capture-packets
  "Return the single-consumer packet stream for a managed capture.

   The stream must be consumed within the capture's `with-open` scope. Calling
   this function more than once for the same capture throws `ex-info`."
  [value]
  (let [^Capture managed-capture (ensure-capture value)
        opts (.-opts managed-capture)
        processed (.-processed managed-capture)
        decode-errors (.-decode-errors managed-capture)
        stats-xf
        (map
         (fn [packet]
           (.increment ^LongAdder processed)
           (when (:decode-error packet)
             (.increment ^LongAdder decode-errors))
           packet))
        xform (:xform opts)
        stream-xf (packet-pipeline-xf opts stats-xf xform)]
    (sequence stream-xf
              (capture/packet-seq (.-managed managed-capture)))))

(defn stop-capture!
  "Request asynchronous, idempotent termination of a managed capture."
  [value]
  (let [^Capture managed-capture (ensure-capture value)]
    (capture/stop! (.-managed managed-capture))))

(defn capture-stats
  "Return a data-only execution snapshot for a managed capture.

   The final snapshot remains available after the capture is closed."
  [value]
  (let [^Capture managed-capture (ensure-capture value)
        stats (capture/stats (.-managed managed-capture))]
    (-> stats
        (assoc-in [:packets :processed]
                  (.sum ^LongAdder (.-processed managed-capture)))
        (assoc-in [:packets :decode-errors]
                  (.sum ^LongAdder (.-decode-errors managed-capture))))))

;; Writer
(defn write-pcap!
  "Write packet bytes to a PCAP file.

  `packets` can contain:
  - `byte-array`
  - map with `:bytes` and optional `:sec`/`:usec` timestamps"
  [packets out]
  (pcap/bytes-seq->pcap! packets {:out out}))

(defn list-devices
  "Return available capture devices as
  `{:name <string> :desc <string|nil>}` maps."
  []
  (pcap/list-devices))

(defn -main
  "Repository-local convenience entrypoint.
   Paclo is a library; use example commands for executable workflows."
  [& _]
  (println "Paclo is a Clojure library (no single standalone app entrypoint).")
  (println "Try one of these commands:")
  (println "  clojure -M:test")
  (println "  clojure -M:dev -m examples.pcap-stats <in.pcap>")
  (println "  clojure -M:dev:dns-ext -m examples.dns-topn <in.pcap>"))
