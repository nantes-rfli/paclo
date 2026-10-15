(ns paclo.pcapng.cursor
  "Internal bounded, synchronous PCAPNG block cursor. No capture/native I/O."
  (:import
   [java.nio ByteBuffer ByteOrder]
   [java.nio.channels FileChannel]
   [java.util Arrays]))

(def defaults
  {:max-block-bytes (* 16 1024 1024)
   :max-packet-bytes (* 8 1024 1024)
   :max-options-bytes (* 1024 1024)
   :max-options-per-block 4096
   :max-interfaces-per-section 4096
   :max-section-metadata-bytes (* 8 1024 1024)
   :max-opaque-block-bytes (* 1024 1024)})

(defn fail! [location reason data]
  (throw (ex-info (str "PCAPNG " (name reason))
                  (merge location {:phase :pcapng-read :reason reason} data))))

(defn limit! [opts location field actual]
  (when (> actual (get opts field))
    (fail! location :limit-exceeded {:field field :actual actual :limit (get opts field)})))

(defn validate-options [opts]
  (when-not (map? opts)
    (fail! {} :invalid-source-options {}))
  (when (or (not (contains? opts :path)) (nil? (:path opts)))
    (fail! {} :invalid-source-options {:field :path}))
  (doseq [k (keys opts)]
    (when-not (or (= k :path) (contains? defaults k))
      (fail! {} :invalid-source-options {:field :unknown-option})))
  (doseq [[k v] (dissoc opts :path)]
    (let [ceiling (if (#{:max-options-per-block :max-interfaces-per-section} k)
                    65536 (- Integer/MAX_VALUE 8))]
      (when-not (and (integer? v) (<= 1 v ceiling))
        (fail! {} :invalid-source-options {:field k :limit ceiling}))))
  (merge defaults opts))

(defn initial-state []
  {:file-offset 0 :block-index 0 :section-id -1 :interfaces []
   :metadata-bytes 0 :section-end nil :byte-order nil})

(defn- order ^ByteOrder [byte-order]
  (if (= byte-order :little-endian) ByteOrder/LITTLE_ENDIAN ByteOrder/BIG_ENDIAN))

(defn- allocate-buffer ^ByteBuffer [n]
  (ByteBuffer/allocate (int n)))

(defn- u16 [^ByteBuffer b offset] (bit-and 0xffff (.getShort b (int offset))))
(defn- u32 [^ByteBuffer b offset] (Integer/toUnsignedLong (.getInt b (int offset))))
(defn- padded [n] (* 4 (quot (+ n 3) 4)))
(defn- octets [^ByteBuffer b start n]
  (Arrays/copyOfRange (.array b) (int start) (int (+ start n))))

(defn read-buffer!
  "Fill a buffer. EOF is allowed only before any byte of an inter-block header."
  [^FileChannel channel ^ByteBuffer buffer location eof-ok?]
  (loop []
    (if (.hasRemaining buffer)
      (let [n (.read channel buffer)]
        (if (= -1 n)
          (if (and eof-ok? (zero? (.position buffer)))
            nil
            (fail! location :truncated-block {}))
          (recur)))
      buffer)))

(defn- minimum! [^ByteBuffer body location n]
  (when (< (.limit body) n)
    (fail! location :invalid-block-length {:expected n :actual (.limit body)})))

;; Draft 06 lengths and multiplicity, including repeatable EPB process/thread IDs.
;; IDB address options 4/5 are repeatable; their fixed lengths still apply.
(def ^:private singleton
  {:section #{2 3 4}
   :interface #{2 3 6 7 8 9 10 11 12 13 14 15 16 17 18}
   :packet #{2 4 5 6}})
(def ^:private fixed-lengths
  {:interface {4 8, 5 17, 6 6, 7 8, 8 8, 9 1, 10 4, 13 1, 14 8, 16 8, 17 8}
   :packet {2 4, 4 8, 5 8, 6 4, 8 8}})

(defn- option-length! [^ByteBuffer body kind code start n location]
  (let [fixed (get-in fixed-lengths [kind code])
        minimum (cond
                  (#{2988 2989 19372 19373} code) 4
                  (and (= kind :interface) (= code 11)) 1
                  (and (= kind :packet) (#{3 7} code)) 1
                  :else 0)]
    (when (or (and fixed (not= fixed n)) (< n minimum))
      (fail! location :invalid-option-length {:field code :actual n :expected (or fixed minimum)}))
    (when (and (= kind :packet) (#{3 7} code) (pos? n))
      (let [tag (bit-and 255 (.get body (int start)))
            size (if (= code 3) ({2 5, 3 17, 4 21, 5 5} tag) ({1 9, 2 9} tag))]
        (when (and size (not= size n))
          (fail! location :invalid-option-length {:field code :actual n :expected size}))))))

(defn- options!
  [^ByteBuffer body start kind opts location metadata-base]
  (let [end (.limit body)
        size (- end start)]
    (limit! opts location :max-options-bytes size)
    (when metadata-base
      (limit! opts location :max-section-metadata-bytes (+ metadata-base size)))
    ;; First validate all extents/counts/accounting; only then copy option values.
    (loop [pos start seen #{} entries []]
      (if (= pos end)
        {:options (mapv (fn [[code p n]]
                          (cond-> {:code code :value (octets body p n)}
                            (#{2988 2989} code) (assoc :copy-policy :copyable)
                            (#{19372 19373} code) (assoc :copy-policy :never))) entries)
         :metadata-bytes (when metadata-base (+ metadata-base size (* 32 (count entries))))}
        (do
          (when (> (+ pos 4) end)
            (fail! location :invalid-option-length {}))
          (let [code (u16 body pos) n (u16 body (+ pos 2)) next (+ pos 4 (padded n))]
            (when (> next end)
              (fail! location :invalid-option-length {:field code :actual n}))
            (if (zero? code)
              (do
                (when (or (pos? n) (not= next end))
                  (fail! location :invalid-option-length {:field :end-of-options}))
                (recur end seen entries))
              (do
                (limit! opts location :max-options-per-block (inc (count entries)))
                (when metadata-base
                  (limit! opts location :max-section-metadata-bytes
                          (+ metadata-base size (* 32 (inc (count entries))))))
                (when (and (contains? (get singleton kind) code) (contains? seen code))
                  (fail! location :duplicate-option {:field code}))
                (option-length! body kind code (+ pos 4) n location)
                (recur next (conj seen code) (conj entries [code (+ pos 4) n]))))))))))

(defn projection
  "Exact integer floor to legacy microseconds; input ticks are unsigned."
  [ticks {:keys [base exponent]} offset]
  (let [d (reduce *' 1N (repeat exponent base))
        q (quot ticks d) r (rem ticks d)]
    {:ts-sec (+' offset q) :ts-usec (quot (*' r 1000000) d)}))

(defn- native-linktype [file-linktype]
  (when (#{"Linux" "Mac OS X"} (System/getProperty "os.name"))
    ({0 0, 1 1, 101 12, 108 108, 113 113, 276 276} file-linktype)))

(defn- section! [state ^ByteBuffer body opts location byte-order total]
  (minimum! body location 16)
  (let [version [(u16 body 4) (u16 body 6)] length (.getLong body 8)]
    (when-not (= version [1 0])
      (fail! location :unsupported-section-version {:actual version}))
    (when (< length -1)
      (fail! location :invalid-section-length {:actual length}))
    (let [{:keys [options metadata-bytes]} (options! body 16 :section opts location 256)
          id (inc' (:section-id state))
          descriptor {:id id :byte-order byte-order :version version
                      :section-length (when-not (= length -1) length) :options options}]
      [(assoc state :section-id id :byte-order byte-order :interfaces []
              :metadata-bytes metadata-bytes
              :section-end (when-not (= length -1) (+' (:file-offset state) total length)))
       {:type :section :section descriptor :section-id id}])))

(defn- interface! [state ^ByteBuffer body opts location]
  (minimum! body location 8)
  (let [id (count (:interfaces state))]
    (limit! opts location :max-interfaces-per-section (inc id))
    (let [{:keys [options metadata-bytes]}
          (options! body 8 :interface opts location (+ 256 (:metadata-bytes state)))
          values (into {} (map (juxt :code :value)) options)
          resolution (if-let [^bytes bytes (get values 9)]
                       (let [v (bit-and 255 (aget bytes 0))]
                         {:base (if (bit-test v 7) 2 10) :exponent (bit-and v 127)})
                       {:base 10 :exponent 6})
          offset (if-let [^bytes bytes (get values 14)]
                   (.getLong (.order (ByteBuffer/wrap bytes) (.order body))) 0)
          file-linktype (u16 body 0)
          descriptor {:id id :section-id (:section-id state) :file-linktype file-linktype
                      :linktype (native-linktype file-linktype) :snaplen (u32 body 4)
                      :timestamp-resolution resolution :timestamp-offset-sec offset :options options}]
      [(-> state (update :interfaces conj descriptor) (assoc :metadata-bytes metadata-bytes))
       {:type :interface :interface descriptor}])))

(defn- interface-ref! [state id location]
  (or (get (:interfaces state) id)
      (fail! location :undefined-interface {:interface-id id})))

(defn- packet-layout! [state ^ByteBuffer prefix opts location simple? body-bytes]
  (let [id (if simple? 0 (u32 prefix 0))
        interface (interface-ref! state id location)
        len (u32 prefix (if simple? 0 16))
        snaplen (:snaplen interface)
        caplen (if simple? (if (zero? snaplen) len (min len snaplen)) (u32 prefix 12))
        start (if simple? 4 20)
        end (+ start (padded caplen))]
    (limit! opts location :max-packet-bytes caplen)
    (when (or (> caplen len) (and (pos? snaplen) (> caplen snaplen))
              (> end body-bytes) (and simple? (not= end body-bytes)))
      (fail! location :invalid-packet-length {:actual caplen :expected len :interface-id id}))
    {:id id :interface interface :len len :caplen caplen :start start :end end}))

(defn- packet-prefix! [channel state opts location type body-bytes byte-order]
  (when (#{3 6} type)
    (let [size (if (= type 3) 4 20)]
      (when (< body-bytes size)
        (fail! location :invalid-block-length {:expected size :actual body-bytes}))
      (let [prefix (.order (allocate-buffer size) (order byte-order))]
        (read-buffer! channel prefix location false)
        {:prefix prefix :layout (packet-layout! state prefix opts location (= type 3) body-bytes)}))))

(defn- packet! [state ^ByteBuffer body opts location simple? layout]
  (let [{:keys [id interface len caplen start end]} layout
        options (if simple? [] (:options (options! body end :packet opts location nil)))
        ticks (when-not simple? (+' (*' (u32 body 4) 4294967296N) (u32 body 8)))
        packet (cond-> {:bytes (octets body start caplen) :caplen caplen :len len
                        :linktype (:linktype interface)
                        :pcapng {:section-id (:section-id state) :interface-id id
                                 :block-type (if simple? :simple-packet :enhanced-packet)
                                 :timestamp (when-not simple? {:ticks ticks}) :options options}}
                 (not simple?) (merge (projection ticks (:timestamp-resolution interface)
                                                  (:timestamp-offset-sec interface))))]
    [state {:type :packet :packet packet}]))

(defn accept-body
  "Validate an encoded body for the writer; return bounded state and event."
  [state ^ByteBuffer body opts type byte-order total]
  (let [location (select-keys state [:file-offset :block-index :section-id])
        [next-state event]
        (case type
          0x0a0d0d0a (section! state body opts location byte-order total)
          1 (interface! state body opts location)
          6 (packet! state body opts location false
                     (packet-layout! state body opts location false (.limit body)))
          3 (packet! state body opts location true
                     (packet-layout! state body opts location true (.limit body)))
          (do
            (case type
              4 (minimum! body location 4)
              5 (minimum! body location 12)
              (0x00000bad 0x40000bad) (minimum! body location 4)
              nil)
            [state nil]))]
    [(-> next-state (update :block-index inc') (update :file-offset +' total)) event]))

(defn next-block!
  "Read and validate one block. Return [new-state event], or nil at valid EOF."
  [^FileChannel channel state opts]
  (let [location (select-keys state [:file-offset :block-index :section-id])
        header (allocate-buffer 8)]
    (if-not (read-buffer! channel header location true)
      (do
        (when (or (neg? (:section-id state))
                  (and (:section-end state) (not= (:file-offset state) (:section-end state))))
          (fail! location :invalid-section-length {}))
        nil)
      (let [shb? (= 0x0a0d0d0a (.getInt header 0))
            magic (when shb? (read-buffer! channel (allocate-buffer 4) location false))
            byte-order (if shb?
                         (case (.getInt ^ByteBuffer magic 0)
                           0x1a2b3c4d :big-endian
                           0x4d3c2b1a :little-endian
                           (fail! location :invalid-section-magic {}))
                         (:byte-order state))]
        (when-not byte-order (fail! location :missing-section {}))
        (.order header (order byte-order))
        (let [total (u32 header 4) type (u32 header 0)
              location (assoc location :block-type type)]
          (when (or (< total (if shb? 28 12)) (not (zero? (mod total 4))))
            (fail! location :invalid-block-length {:actual total}))
          (limit! opts location :max-block-bytes total)
          (when-let [section-end (:section-end state)]
            (when (if shb? (not= (:file-offset state) section-end)
                      (> (+' (:file-offset state) total) section-end))
              (fail! location :invalid-section-length {:expected section-end})))
          (case type
            2 (fail! location :unsupported-packet-block {})
            10 (fail! location :unsupported-sensitive-block {})
            nil)
          (when-not (#{0x0a0d0d0a 1 6 3} type)
            (limit! opts location :max-opaque-block-bytes (- total 12)))
          ;; Check packet length policy using only the fixed prefix. In particular,
          ;; an absent/short oversized payload must fail before any body allocation.
          (let [{:keys [prefix layout]} (packet-prefix! channel state opts location type (- total 12) byte-order)
                body (.order (allocate-buffer (- total 8)) (order byte-order))]
            (when shb? (.put body (.array ^ByteBuffer magic)))
            (when prefix (.put body (.array ^ByteBuffer prefix)))
            (read-buffer! channel body location false)
            (when-not (= total (u32 body (- total 12)))
              (fail! location :invalid-block-length {:field :trailer :expected total
                                                     :actual (u32 body (- total 12))}))
            (.limit body (int (- total 12)))
            (let [[next-state event]
                  (case type
                    0x0a0d0d0a (section! state body opts location byte-order total)
                    1 (interface! state body opts location)
                    6 (packet! state body opts location false layout)
                    3 (packet! state body opts location true layout)
                    (do
                      (case type
                        4 (minimum! body location 4)
                        5 (minimum! body location 12)
                        (0x00000bad 0x40000bad) (minimum! body location 4)
                        nil)
                      [state {:type :opaque-block
                              :block {:block-type type :body (octets body 0 (.limit body))
                                      :byte-order byte-order
                                      :copy-policy (cond
                                                     (= type 0x40000bad) :never
                                                     (#{4 5 0x00000bad} type) :copyable
                                                     :else :unknown)}}]))]
              [(-> next-state (update :block-index inc') (update :file-offset +' total))
               (merge (dissoc location :block-type) {:section-id (:section-id next-state)} event)])))))))
