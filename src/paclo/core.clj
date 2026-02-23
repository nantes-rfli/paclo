(ns paclo.core
  "Public, data-first facade for Paclo.

  Main entry points:
  - `packets` for live/offline capture as lazy sequences
  - `bpf` for BPF DSL -> string conversion
  - `write-pcap!` for writing packet byte sequences"
  (:require
   [clojure.string :as str]
   [paclo.decode-ext :as decode-ext]
   [paclo.parse :as parse]
   [paclo.pcap  :as pcap]))

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

(defn ^:private apply-xform
  "Apply transducer `xf` with `sequence` when present; otherwise return `s`."
  [s xf]
  (if (some? xf) (sequence xf s) s))

(defn packets
  "Return packets as a lazy sequence.

  Key opts:
  - source: `:path` (offline) or `:device` (live)
  - `:filter`: BPF string, protocol keyword, or BPF DSL vector
  - `:decode?`: when true, add `:decoded` or `:decode-error` to each packet map
  - `:xform`: transducer applied to output stream via `sequence`

  Throws `ex-info` when `:filter` has an unsupported type."
  [{:keys [filter decode? xform] :as opts}]
  (let [filter* (cond
                  (string? filter) filter
                  (or (keyword? filter) (vector? filter)) (bpf filter)
                  (nil? filter) nil
                  :else (throw (ex-info "invalid :filter" {:filter filter})))
        opts*   (cond-> opts (some? filter*) (assoc :filter filter*))
        base    (pcap/capture->seq opts*)
        stream  (if decode?
                  (map (fn [m]
                         (let [ba ^bytes (:bytes m)]
                           (if (and ba (>= (long (alength ba)) (long ETH_MIN_HDR)))
                             (let [{:keys [ok value error]} (decode-result ba)
                                   m' (cond-> m
                                        ok       (assoc :decoded value)
                                        (not ok) (assoc :decode-error error))]
                               ;; Run post-decode hooks only for successfully decoded packets.
                               (if (contains? m' :decoded)
                                 (decode-ext/apply! m')
                                 m'))
                             (assoc m :decode-error (str "frame too short: " (when ba (alength ba)) " bytes")))))
                       base)
                  base)]
    (apply-xform stream xform)))

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
