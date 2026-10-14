(ns paclo.linktype
  "Link framing shared by full decoding and numeric projection.
   Native DLT values are not arbitrary savefile LINKTYPE values."
  (:import
   [java.nio ByteBuffer]))

(def ^:private native-ip-supported?
  ;; P08-A/D2 measured DLT_RAW=12, NULL=0, LOOP=108 on Linux/macOS.
  ;; OpenBSD uses RAW=14 and LOOP=12;
  ;; savefiles use LINKTYPE_RAW=101. Leave unverified platforms unsupported.
  (contains? #{"Linux" "Mac OS X"} (System/getProperty "os.name")))

(defn unsupported?
  "Absence retains legacy Ethernet input; explicit values must be supported DLTs."
  [packet]
  (let [dlt (:linktype packet)]
    (if (nil? dlt)
      (contains? packet :linktype)
      (not (and (integer? dlt)
                (or (= dlt 1) (contains? #{113 276} dlt)
                    (and (= dlt 12) native-ip-supported?)
                    (and (or (= dlt 0) (= dlt 108)) native-ip-supported?)))))))

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

(defn- loopback-size ^long [^long dlt]
  (if (and (or (= dlt 0) (= dlt 108)) native-ip-supported?)
    4
    (throw (ex-info "unsupported linktype" {:reason :unsupported-linktype :linktype dlt}))))

(defn minimum-size
  "Minimum framing bytes; Raw IP needs a version byte, NULL/LOOP need four AF bytes."
  ^long [^long dlt]
  (cond
    (= dlt 1) 14
    (= dlt 113) 16
    (= dlt 276) 20
    (and (= dlt 12) native-ip-supported?) 1
    :else (loopback-size dlt)))

(defn- short-frame-message [^long dlt]
  (case dlt 1 "truncated ethernet header" 113 "truncated SLL header"
        276 "truncated SLL2 header" 12 "empty Raw IP packet"
        0 "truncated NULL header" 108 "truncated LOOP header"))

(defn require-framing!
  "Validate the minimum framing bytes; bare IP needs one version byte."
  ^long [^bytes frame ^long dlt]
  (let [required (minimum-size dlt)]
    (when (or (nil? frame) (< (alength frame) required))
      (throw (ex-info (short-frame-message dlt)
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

(defn- raw-protocol ^long [^bytes frame]
  ;; Reuse IP dispatch tokens internally, without a synthetic link field.
  (let [version (unsigned-bit-shift-right (u8 frame 0) 4)]
    (case version
      4 0x0800
      6 0x86dd
      (throw (ex-info "invalid Raw IP version"
                      {:reason :malformed-packet :field :ip-version :value version
                       :offset 0 :required 1 :available (alength frame)})))))

(defn- known-family? [^long family]
  (case family (2 24 28 30) true false))

(defn- address-family ^long [^bytes frame ^long dlt]
  (let [big (bit-or (bit-shift-left (u16 frame 0) 16) (u16 frame 2))]
    ;; Byte reversal of every supported AF is outside the supported set. Thus
    ;; both orders cannot match: no container state or version sniff is needed.
    (if (known-family? big)
      big
      (let [little (when (= dlt 0)
                     (bit-and (long (Integer/reverseBytes (unchecked-int big))) 0xffffffff))]
        (if (and little (known-family? little))
          (long little)
          (throw (ex-info "unsupported address family"
                          (cond-> {:reason :unsupported-address-family
                                   :field :address-family :value big
                                   :offset 0 :required 4 :available (alength frame)}
                            little (assoc :little-endian-value little)))))))))

(defn- loopback-protocol ^long [^bytes frame ^long dlt]
  (let [family (address-family frame dlt)
        available (- (alength frame) 4)]
    (when (zero? available)
      (throw (ex-info "truncated NULL/LOOP IP version"
                      {:reason :truncated-header :offset 4 :required 1 :available 0})))
    (let [version (unsigned-bit-shift-right (u8 frame 4) 4)
          expected (if (= family 2) 4 6)]
      (when-not (or (= version 4) (= version 6))
        (throw (ex-info "invalid NULL/LOOP IP version"
                        {:reason :malformed-packet :field :ip-version :value version
                         :offset 4 :required 1 :available available})))
      (when-not (= version expected)
        (throw (ex-info "address family/IP version mismatch"
                        {:reason :address-family-mismatch :field :ip-version :value version
                         :address-family family :expected-version expected
                         :offset 4 :required 1 :available available})))
      (if (= expected 4) 0x0800 0x86dd))))

(defn payload
  "Return packed unsigned L3 offset (high 32 bits) and protocol (low 32 bits).
   Checks framing only; throws classified errors at absolute packet offsets.
   No input copying or link-detail map allocation on the successful fast path."
  ^long [^bytes frame ^long dlt]
  (require-framing! frame dlt)
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
    (= dlt 12) (raw-protocol frame)
    (or (= dlt 0) (= dlt 108)) (packed 4 (loopback-protocol frame dlt))
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
                     :address-length length :address (address buffer 12 length) :l3 l3})
      (= dlt 12) {:type :raw-ip :l3 l3}
      (or (= dlt 0) (= dlt 108))
      {:type (if (= dlt 0) :null :loop) :address-family (address-family frame dlt) :l3 l3})))
