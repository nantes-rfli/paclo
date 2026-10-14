(ns paclo.linktype
  "Link-header interpretation shared by full decoding and numeric projection.
   Native DLT values are not arbitrary savefile LINKTYPE values."
  (:import
   [java.nio ByteBuffer]))

(defn unsupported?
  "Absence retains legacy Ethernet input; explicit values must be supported DLTs."
  [packet]
  (let [dlt (:linktype packet)]
    (if (nil? dlt)
      (contains? packet :linktype)
      (not (and (integer? dlt) (or (= dlt 1) (contains? #{113 276} dlt)))))))

(defn packet-dlt
  [packet]
  (when (unsupported? packet)
    (throw (ex-info "unsupported linktype"
                    {:reason :unsupported-linktype :linktype (:linktype packet)})))
  (if (contains? packet :linktype) (:linktype packet) 1))

(defn- u8 ^long [^bytes frame ^long offset]
  (bit-and (aget frame (int offset)) 0xff))

(defn- u16 ^long [^bytes frame ^long offset]
  (bit-or (bit-shift-left (u8 frame offset) 8) (u8 frame (inc offset))))

(defn header-size ^long [^long dlt]
  (cond
    (= dlt 1) 14
    (= dlt 113) 16
    (= dlt 276) 20
    :else (throw (ex-info "unsupported linktype" {:reason :unsupported-linktype :linktype dlt}))))

(defn require-link-header!
  "Validate the minimum link header before invoking either parser."
  ^long [^bytes frame ^long dlt]
  (let [required (header-size dlt)]
    (when (or (nil? frame) (< (alength frame) required))
      (throw (ex-info (case dlt 1 "truncated ethernet header" 113 "truncated SLL header"
                            276 "truncated SLL2 header")
                      {:reason :short-frame :offset 0 :required required
                       :available (if frame (alength frame) 0)})))
    required))

(defn- require-address! [^bytes frame ^long offset ^long width ^long length]
  (when (> length 8)
    (throw (ex-info "invalid cooked address length"
                    {:reason :malformed-packet :field :address-length :value length
                     :offset offset :required width :available (- (alength frame) offset)}))))

(defn- packed ^long [^long offset ^long protocol]
  (bit-or (bit-shift-left offset 32) protocol))

(defn vlan-protocol? [^long protocol]
  (case protocol (0x8100 0x88a8 0x9100 0x9200) true false))

(defn payload
  "Return packed unsigned L3 offset (high 32 bits) and protocol (low 32 bits).
   Checks framing only; throws classified errors at absolute packet offsets.
   No input copying or link-detail map allocation on the successful fast path."
  ^long [^bytes frame ^long dlt]
  (require-link-header! frame dlt)
  (cond
    (= dlt 1) (loop [offset 14 protocol (u16 frame 12)]
                (if (vlan-protocol? protocol)
                  (if (< (- (alength frame) offset) 4)
              ;; Full decode retains its legacy partial VLAN wrapper. Only the
              ;; failure path allocates data describing the completed framing.
                    (throw (ex-info "truncated VLAN header"
                                    {:reason :truncated-header :offset offset :required 4
                                     :available (- (alength frame) offset)
                                     :framing (packed offset protocol)}))
                    (recur (+ offset 4) (u16 frame (+ offset 2))))
                  (bit-or (bit-shift-left (long offset) 32) (long protocol))))
    (= dlt 113) (do
                  (require-address! frame 4 2 (u16 frame 4))
                  (packed 16 (u16 frame 14)))
    (= dlt 276) (do
                  (require-address! frame 11 1 (u8 frame 11))
                  (packed 20 (u16 frame 0)))
    :else (throw (ex-info "unsupported linktype" {:reason :unsupported-linktype :linktype dlt}))))

(def ^:private hex-digits "0123456789abcdef")

(defn- address [^ByteBuffer buffer ^long offset ^long length]
  (.position buffer (int offset))
  (if (zero? length)
    ""
    (let [result (char-array (dec (* length 3)))]
      (dotimes [index length]
        (let [value (bit-and (.get buffer) 0xff) output (* index 3)]
          (aset-char result output (.charAt ^String hex-digits (int (bit-shift-right value 4))))
          (aset-char result (inc output) (.charAt ^String hex-digits (int (bit-and value 15))))
          (when (< index (dec length)) (aset-char result (+ output 2) \:))))
      (String. result))))

(defn header
  "Build full-decode link fields after payload has validated framing.
   Ethernet VLAN fields are read from the already established L3 offset."
  [^ByteBuffer buffer dlt ^long framing l3]
  (let [frame (.array buffer)
        protocol (bit-and framing 0xffffffff)]
    (cond
      (= dlt 1) (let [offset (unsigned-bit-shift-right framing 32)
                      result {:type :ethernet :dst (address buffer 0 6)
                              :src (address buffer 6 6) :eth protocol :l3 l3}]
                  (if (> offset 14)
                    (assoc result :vlan-tags
                           (loop [position 14 tags (transient [])]
                             (if (= position offset)
                               (persistent! tags)
                               (let [tci (u16 frame position)]
                                 (recur (+ position 4)
                                        (conj! tags {:tpid (u16 frame (- position 2))
                                                     :pcp (bit-and (bit-shift-right tci 13) 7)
                                                     :dei (pos? (bit-and tci 0x1000))
                                                     :vid (bit-and tci 0x0fff)}))))))
                    result))
      (= dlt 113) (let [length (u16 frame 4)]
                    {:type :linux-sll :packet-type (u16 frame 0) :hardware-type (u16 frame 2)
                     :address-length length :address (address buffer 6 length) :protocol protocol :l3 l3})
      (= dlt 276) (let [length (u8 frame 11)]
                    {:type :linux-sll2 :protocol protocol :reserved (u16 frame 2)
                     :interface-index (bit-or (bit-shift-left (u16 frame 4) 16) (u16 frame 6))
                     :hardware-type (u16 frame 8) :packet-type (u8 frame 10)
                     :address-length length :address (address buffer 12 length) :l3 l3}))))
