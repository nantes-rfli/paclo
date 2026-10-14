(ns paclo.dns
  "Pure UDP DNS event projection and bounded ordered-stream correlation."
  (:require
   [clojure.string :as str]
   [paclo.linktype :as linktype])
  (:import
   [java.util Locale]))

(defn- fail! [reason]
  (throw (ex-info (name reason) {:reason reason})))

(defn- uint? [value maximum]
  (and (integer? value) (<= 0 value maximum)))

(defn- time! [value]
  (when-not (integer? value) (fail! :invalid-time))
  value)

(defn packet-time-us
  "Convert native :ts-sec/:ts-usec to exact integer epoch microseconds.
   Seconds may be negative; usec must be 0..999999. No legacy/clock fallback.
   Missing/noninteger components throw :invalid-time; arithmetic promotes."
  [{:keys [ts-sec ts-usec]}]
  (when-not (and (integer? ts-sec) (uint? ts-usec 999999)) (fail! :invalid-time))
  (+' (*' ts-sec 1000000) ts-usec))

(defn- ip [version value]
  ;; Numeric text only; never resolve names. Normalize the decoder's full IPv6
  ;; representation and dotted IPv4. Compressed IPv6 is outside this contract.
  (when (string? value)
    (let [parts (str/split value (if (= version 4) #"\." #":") -1)]
      (try
        (case version
          4 (when (and (= 4 (count parts)) (every? #(re-matches #"[0-9]{1,3}" %) parts))
              (let [octets (mapv #(Integer/parseInt %) parts)]
                (when (every? #(<= 0 % 255) octets) (str/join "." octets))))
          6 (when (and (= 8 (count parts)) (every? #(re-matches #"[0-9a-fA-F]{1,4}" %) parts))
              (str/join ":" (map #(Integer/toHexString (Integer/parseInt % 16)) parts)))
          nil)
        (catch NumberFormatException _ nil)))))

(defn- normalize-event [event]
  (time! (:time-us event))
  (let [{:keys [kind id protocol ip-version src dst qname qtype qclass rcode]} event
        source (ip ip-version (:ip src)) destination (ip ip-version (:ip dst))]
    (when-not (and (contains? #{:query :response} kind) (uint? id 65535)
                   (= :udp protocol) (contains? #{4 6} ip-version)
                   source destination (uint? (:port src) 65535) (uint? (:port dst) 65535)
                   (= 53 (:port (if (= kind :query) dst src)))
                   (or (nil? qname) (string? qname))
                   (or (nil? qtype) (uint? qtype 65535))
                   (or (nil? qclass) (uint? qclass 65535))
                   (or (nil? rcode) (uint? rcode 15)))
      (fail! :invalid-event))
    (cond-> {:time-us (:time-us event) :kind kind :id id :protocol protocol :ip-version ip-version
             :src {:ip source :port (:port src)} :dst {:ip destination :port (:port dst)}}
      (some? qname) (assoc :qname (.toLowerCase ^String qname Locale/ROOT))
      (some? qtype) (assoc :qtype qtype)
      (some? qclass) (assoc :qclass qclass)
      (some? rcode) (assoc :rcode rcode))))

(defn packet->event
  "Project existing full-decode DNS data to EDN, or nil for ineligible packets.
   Supports unfragmented standard UDP/53 messages with 0 or 1 question.
   Reject decode-error, any diagnostics, unsupported linktype, short DNS/UDP,
   fragments and unsupported opcodes. Reuses parsed headers, never reads bytes.
   Optional dns-ext annotation supplies question fields. Eligible bad timestamps
   throw :invalid-time. Missing questions remain events for explicit ambiguity."
  [packet]
  (let [l3 (get-in packet [:decoded :l3]) l4 (:l4 l3) app (:app l4)]
    (when (and (map? packet) (not (contains? packet :decode-error))
               (empty? (:diagnostics packet))
               (not (linktype/unsupported? packet))
               (contains? #{:ipv4 :ipv6} (:type l3)) (not (:frag? l3))
               (= :udp (:type l4)) (or (= 53 (:src-port l4)) (= 53 (:dst-port l4)))
               (integer? (:length l4)) (integer? (:data-len l4))
               (<= 20 (:length l4)) (= (:length l4) (+' 8 (:data-len l4)))
               (= :dns (:type app)) (uint? (:id app) 65535)
               (boolean? (:qr? app)) (uint? (:flags-raw app) 65535)
               (uint? (:rcode app) 15) (= 0 (:opcode app)) (uint? (:qdcount app) 1))
      (normalize-event
       (merge (select-keys app [:id :qname :qtype :qclass :rcode])
              {:time-us (packet-time-us packet) :kind (if (:qr? app) :response :query)
               :protocol :udp :ip-version (if (= :ipv4 (:type l3)) 4 6)
               :src {:ip (:src l3) :port (:src-port l4)}
               :dst {:ip (:dst l3) :port (:dst-port l4)}})))))

(defn init
  "Create bounded immutable state. Requires positive integer :timeout-us,
   :max-pending and :max-retired. :reuse-delay-us defaults to timeout (positive).
   Pending queries expire at first time+timeout. Retired keys remain quarantined
   until that deadline+reuse delay, released only by an explicit watermark."
  [{:keys [timeout-us max-pending max-retired reuse-delay-us]
    :as opts}]
  (let [reuse-delay-us (if (contains? opts :reuse-delay-us) reuse-delay-us timeout-us)]
    (doseq [value [timeout-us max-pending max-retired reuse-delay-us]]
      (when-not (and (integer? value) (pos? value)) (fail! :invalid-options)))
    {:options {:timeout-us timeout-us :max-pending max-pending
               :max-retired max-retired :reuse-delay-us reuse-delay-us}
     :watermark-us nil :pending {} :retired {} :finished? false}))

(defn- open! [state]
  (when (:finished? state) (fail! :finished)))

(defn- transaction-key [{:keys [kind id protocol ip-version src dst qname qtype qclass]}]
  (when (and (some? qname) (some? qtype) (some? qclass))
    {:id id :protocol protocol :ip-version ip-version
     :client (if (= kind :query) src dst) :server (if (= kind :query) dst src)
     :qname qname :qtype qtype :qclass qclass}))

(defn- key-order [k]
  [(:ip-version k) (:protocol k) (get-in k [:client :ip]) (get-in k [:client :port])
   (get-in k [:server :ip]) (get-in k [:server :port]) (:id k) (:qname k) (:qtype k) (:qclass k)])

(defn- ordered [pending]
  (sort-by (fn [[k v]] [(:deadline-us v) (key-order k)]) pending))

(defn- retire [state k entry]
  (let [until (+' (:deadline-us entry) (get-in state [:options :reuse-delay-us]))]
    (when (and (or (nil? (:watermark-us state)) (> until (:watermark-us state)))
               (>= (count (:retired state)) (get-in state [:options :max-retired])))
      (fail! :max-retired))
    (cond-> (update state :pending dissoc k)
      (or (nil? (:watermark-us state)) (> until (:watermark-us state)))
      (assoc-in [:retired k] until))))

(defn- query-result [kind k entry]
  {:kind kind :transaction k :query (:query entry) :deadline-us (:deadline-us entry)
   :retransmissions (:retransmissions entry)})

(defn step
  "Process a normalized DNS event; return {:state map :events vector}.
   Missing question fields emit :ambiguous-question. Responses before queries
   emit :unmatched-response and are not retained. Identical pending queries are
   retries: RTT uses earliest query time; retries never extend timeout. Different
   questions have distinct keys. Retired-key reuse emits :id-reuse, without a pair.
   Events before watermark emit :late-event. Negative RTT emits :negative-rtt;
   responses at/after deadline emit :timeout and :unmatched-response. Bound errors
   throw ex-info, leaving the original state unchanged. Unknown keys are dropped."
  [state input]
  (open! state)
  (let [event (normalize-event input) t (:time-us event) k (transaction-key event)
        entry (get (:pending state) k) query? (= :query (:kind event))
        diagnostic (fn [kind] {:state state :events [{:kind kind :event event}]})]
    (cond
      (and (:watermark-us state) (< t (:watermark-us state))) (diagnostic :late-event)
      (nil? k) (diagnostic :ambiguous-question)
      (contains? (:retired state) k) (diagnostic (if query? :id-reuse :duplicate-or-expired-response))
      query?
      (if entry
        (if (>= t (:deadline-us entry))
          (diagnostic :expiry-required)
          (let [query (if (< t (get-in entry [:query :time-us])) event (:query entry))]
            {:state (assoc-in state [:pending k]
                              {:query query :deadline-us (+' (:time-us query) (get-in state [:options :timeout-us]))
                               :retransmissions (inc' (:retransmissions entry))})
             :events []}))
        (do
          (when (>= (count (:pending state)) (get-in state [:options :max-pending])) (fail! :max-pending))
          {:state (assoc-in state [:pending k]
                            {:query event :deadline-us (+' t (get-in state [:options :timeout-us]))
                             :retransmissions 0})
           :events []}))
      (nil? entry) (diagnostic :unmatched-response)
      :else
      (let [next-state (retire state k entry)]
        (if (>= t (:deadline-us entry))
          {:state next-state :events [(query-result :timeout k entry)
                                      {:kind :unmatched-response :reason :outside-timeout :event event}]}
          (let [rtt (-' t (get-in entry [:query :time-us]))]
            {:state next-state
             :events [(assoc (query-result (if (neg? rtt) :negative-rtt :match) k entry)
                             :response event :rtt-us rtt)]}))))))

(defn advance
  "Advance a monotonic integer watermark. Expire pending at deadline <= watermark
   as :timeout events (deadline/key order); release quarantine at until <= watermark.
   No implicit expiry on unrelated input, no unbounded output/history retention."
  [state watermark-us]
  (open! state)
  (time! watermark-us)
  (when (and (:watermark-us state) (< watermark-us (:watermark-us state))) (fail! :watermark-regression))
  (let [state (assoc state :watermark-us watermark-us
                     :retired (reduce-kv (fn [retained k until]
                                           (if (<= until watermark-us) (dissoc retained k) retained))
                                         (:retired state) (:retired state)))
        expired (filter (fn [[_ entry]] (<= (:deadline-us entry) watermark-us)) (ordered (:pending state)))]
    {:state (reduce (fn [s [k entry]] (retire s k entry)) state expired)
     :events (mapv (fn [[k entry]] (query-result :timeout k entry)) expired)}))

(defn finish
  "Emit :unfinished queries in deadline/key order; clear pending and retired.
   Idempotent and terminal. Does not fabricate responses, timeouts or a watermark."
  [state]
  {:state (assoc state :pending {} :retired {} :finished? true)
   :events (mapv (fn [[k entry]] (query-result :unfinished k entry)) (ordered (:pending state)))})
