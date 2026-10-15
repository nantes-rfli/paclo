(ns paclo.flow
  "Pure, bounded flow analysis over numeric flow projection packets."
  (:refer-clojure :exclude [key]))

(defn- uint? [value maximum]
  (and (integer? value) (<= 0 value maximum)))

(defn- signed-word? [value]
  (and (integer? value) (<= Long/MIN_VALUE value Long/MAX_VALUE)))

(defn- ipv6? [address]
  (and (vector? address) (= 2 (count address))
       (signed-word? (nth address 0)) (signed-word? (nth address 1))))

(defn- valid-flow? [{:keys [ip-version protocol src-ip dst-ip src-port dst-port]
                     :as packet}]
  (and (map? packet)
       (not (contains? packet :decode-error))
       (not-any? #(= :flow (:stage %)) (:diagnostics packet))
       (uint? protocol 255)
       (case ip-version
         4 (and (uint? src-ip 4294967295) (uint? dst-ip 4294967295))
         6 (and (ipv6? src-ip) (ipv6? dst-ip))
         false)
       (contains? packet :src-port) (contains? packet :dst-port)
       (if (contains? #{6 17} protocol)
         (and (or (nil? src-port) (uint? src-port 65535))
              (or (nil? dst-port) (uint? dst-port 65535)))
         (and (nil? src-port) (nil? dst-port)))))

(defn- address-compare [version a b]
  (if (= 4 version)
    (compare a b)
    (let [high (Long/compareUnsigned (long (nth a 0)) (long (nth b 0)))]
      (if (zero? high)
        (Long/compareUnsigned (long (nth a 1)) (long (nth b 1)))
        high))))

(defn- endpoint-compare [version a-ip a-port b-ip b-port]
  (let [address (address-compare version a-ip b-ip)]
    (if (zero? address)
      (compare (or a-port -1) (or b-port -1))
      address)))

(defn- direction! [{:keys [direction] :or {direction :unidir}}]
  (when-not (contains? #{:unidir :bidir} direction)
    (throw (ex-info ":direction must be :unidir or :bidir" {:direction direction})))
  direction)

(defn- packet-key [packet direction]
  (when (valid-flow? packet)
    (let [{:keys [ip-version protocol src-ip src-port dst-ip dst-port]} packet
          reverse? (and (= :bidir direction)
                        (pos? (endpoint-compare ip-version src-ip src-port dst-ip dst-port)))]
      {:ip-version ip-version :protocol protocol
       :src-ip (if reverse? dst-ip src-ip) :src-port (if reverse? dst-port src-port)
       :dst-ip (if reverse? src-ip dst-ip) :dst-port (if reverse? src-port dst-port)})))

(defn key
  "Return a canonical six-field numeric flow key, or nil for invalid input.

   Accepts flow projection packets, requiring both port keys (nil is unknown).
   IPv4 uses unsigned integers; IPv6 uses two signed long words. Protocol is
   numeric. :direction defaults to :unidir; :bidir orders endpoints by unsigned
   address then port, with nil before zero. IP version precedes protocol in
   ordering across keys. Metadata is excluded; decode-error or flow diagnostics
   make the input ineligible. Does not decode bytes or convert full-decode keys."
  ([packet] (key packet {}))
  ([packet opts] (packet-key packet (direction! opts))))

(defn- lengths! [{:keys [caplen len]}]
  (when-not (and (uint? caplen 4294967295) (uint? len 4294967295) (<= caplen len))
    (throw (ex-info "flow aggregation requires valid :caplen and :len"
                    {:reason :invalid-lengths :caplen caplen :len len}))))

(defn aggregate-rf
  "Return a standard 0/1/2-arity reducing function with immutable map state.

   Requires positive integer :max-flows; :direction defaults to :unidir.
   State is {:flows {key {:packets n :captured-bytes n :wire-bytes n}}
             :summary {:seen n :aggregated n :skipped n}}.
   Invalid keys are skipped. Eligible packets require integer lengths in
   0..4294967295 with caplen <= len, otherwise throw ex-info. A new key beyond
   the bound throws ex-info (:reason :max-flows); existing keys still update.
   Counters promote to arbitrary precision integers on overflow. Completion
   returns state unchanged. No state is retained between reductions."
  [{:keys [max-flows] :as opts}]
  (let [direction (direction! opts)]
    (when-not (and (integer? max-flows) (pos? max-flows))
      (throw (ex-info ":max-flows must be a positive integer" {:max-flows max-flows})))
    (fn
      ([] {:flows {} :summary {:seen 0 :aggregated 0 :skipped 0}})
      ([state] state)
      ([state packet]
       (if-let [fk (packet-key packet direction)]
         (do
           (lengths! packet)
           (let [flows (:flows state)
                 previous (get flows fk)]
             (when (and (nil? previous) (>= (count flows) max-flows))
               (throw (ex-info "flow cardinality limit exceeded"
                               {:reason :max-flows :max-flows max-flows :flow fk})))
             ;; Single-key assoc avoids the variadic assoc argument sequences.
             ;; Keep every published step persistent, including caller metadata.
             (let [summary (:summary state)]
               (-> state
                   (assoc :flows (assoc flows fk
                                        {:packets (inc' (or (:packets previous) 0))
                                         :captured-bytes (+' (or (:captured-bytes previous) 0) (:caplen packet))
                                         :wire-bytes (+' (or (:wire-bytes previous) 0) (:len packet))}))
                   (assoc :summary (-> summary
                                       (assoc :seen (inc' (:seen summary)))
                                       (assoc :aggregated (inc' (:aggregated summary)))))))))
         (let [summary (:summary state)]
           (assoc state :summary (-> summary
                                     (assoc :seen (inc' (:seen summary)))
                                     (assoc :skipped (inc' (:skipped summary)))))))))))

(defn- key-compare [a b]
  (let [version (compare (:ip-version a) (:ip-version b))
        protocol (compare (:protocol a) (:protocol b))]
    (cond
      (not (zero? version)) version
      (not (zero? protocol)) protocol
      :else (let [source (endpoint-compare (:ip-version a)
                                           (:src-ip a) (:src-port a) (:src-ip b) (:src-port b))]
              (if (zero? source)
                (endpoint-compare (:ip-version a)
                                  (:dst-ip a) (:dst-port a) (:dst-ip b) (:dst-port b))
                source)))))

(defn top-n
  "Return a vector of {:flow canonical-key :packets n :captured-bytes n :wire-bytes n}.

   :metric defaults to :packets; also accepts :captured-bytes or :wire-bytes.
   :n defaults to 10 and must be a nonnegative integer. Sorts descending by
   metric, then ascending by canonical key (version, protocol, endpoints).
   Ties are independent of input order, including mixed IPv4/IPv6 and nil ports.
   Accepts aggregate-rf results; exact sorting costs O(F log F) for F flows."
  [result {:keys [metric n] :or {metric :packets n 10}}]
  (when-not (contains? #{:packets :captured-bytes :wire-bytes} metric)
    (throw (ex-info "unsupported flow metric" {:metric metric})))
  (when-not (and (integer? n) (<= 0 n))
    (throw (ex-info ":n must be a nonnegative integer" {:n n})))
  (->> (:flows result)
       (sort (fn [[a av] [b bv]]
               (let [ranking (compare (get bv metric) (get av metric))]
                 (if (zero? ranking) (key-compare a b) ranking))))
       (take n)
       (mapv (fn [[fk counts]] (assoc counts :flow fk)))))
