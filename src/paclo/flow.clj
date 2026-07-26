(ns paclo.flow
  "Internal low-allocation flow projection for Ethernet IP packets.")

(def ^:private ethernet-header-bytes 14)

(defn- u8 ^long [^bytes frame ^long offset]
  (bit-and (aget frame (int offset)) 0xff))

(defn- u16 ^long [^bytes frame ^long offset]
  (bit-or (bit-shift-left (u8 frame offset) 8)
          (u8 frame (inc offset))))

(defn- u32 ^long [^bytes frame ^long offset]
  (bit-or (bit-shift-left (u8 frame offset) 24)
          (bit-shift-left (u8 frame (+ offset 1)) 16)
          (bit-shift-left (u8 frame (+ offset 2)) 8)
          (u8 frame (+ offset 3))))

(defn- i64 ^long [^bytes frame ^long offset]
  (loop [index 0
         result (long 0)]
    (if (= index 8)
      result
      (recur (inc index)
             (bit-or (bit-shift-left result 8)
                     (u8 frame (+ offset index)))))))

(defn- require-bytes!
  [^bytes frame ^long offset ^long required reason]
  (when (> (+ offset required) (alength frame))
    (throw (ex-info reason
                    {:offset offset
                     :required required
                     :available (max 0 (- (alength frame) offset))}))))

(defn- vlan-tpid? [^long ethertype]
  (case ethertype
    0x8100 true
    0x88a8 true
    0x9100 true
    0x9200 true
    false))

(defn- ethernet-payload
  ^long
  [^bytes frame]
  (require-bytes! frame 0 ethernet-header-bytes "truncated ethernet header")
  (loop [offset ethernet-header-bytes
         ethertype (u16 frame 12)]
    (if (vlan-tpid? ethertype)
      (do
        (require-bytes! frame offset 4 "truncated VLAN header")
        (recur (+ offset 4) (u16 frame (+ offset 2))))
      (bit-or (bit-shift-left (long offset) 32)
              (long ethertype)))))

(defn- packed-ports
  [^bytes frame ^long offset ^long protocol non-first-fragment?]
  (when (and (not non-first-fragment?)
             (or (= protocol 6) (= protocol 17)))
    (require-bytes! frame offset 4 "truncated transport header")
    (bit-or (bit-shift-left (u16 frame offset) 16)
            (u16 frame (+ offset 2)))))

(defn- flow-map
  [packet ip-version protocol src-ip dst-ip packed]
  (let [src-port (when packed (bit-shift-right packed 16))
        dst-port (when packed (bit-and packed 0xffff))]
    (if packet
      (array-map
       :ts-sec (:ts-sec packet)
       :ts-usec (:ts-usec packet)
       :caplen (:caplen packet)
       :len (:len packet)
       :ip-version ip-version
       :protocol protocol
       :src-ip src-ip
       :dst-ip dst-ip
       :src-port src-port
       :dst-port dst-port)
      (array-map
       :ip-version ip-version
       :protocol protocol
       :src-ip src-ip
       :dst-ip dst-ip
       :src-port src-port
       :dst-port dst-port))))

(defn- ipv4-flow
  [^bytes frame ^long offset packet]
  (require-bytes! frame offset 20 "truncated IPv4 header")
  (let [version-ihl (u8 frame offset)
        version (bit-shift-right version-ihl 4)
        header-length (* 4 (bit-and version-ihl 0x0f))]
    (when-not (= version 4)
      (throw (ex-info "invalid IPv4 version" {:version version})))
    (when (< header-length 20)
      (throw (ex-info "invalid IPv4 header length"
                      {:header-length header-length})))
    (require-bytes! frame offset header-length "truncated IPv4 options")
    (let [protocol (u8 frame (+ offset 9))
          flags-fragment (u16 frame (+ offset 6))
          non-first-fragment? (pos? (bit-and flags-fragment 0x1fff))
          packed (packed-ports frame
                               (+ offset header-length)
                               protocol
                               non-first-fragment?)]
      (flow-map packet
                4
                protocol
                (u32 frame (+ offset 12))
                (u32 frame (+ offset 16))
                packed))))

(defn- ipv6-transport
  [^bytes frame ^long initial-offset ^long initial-next-header]
  (loop [offset initial-offset
         next-header initial-next-header
         non-first-fragment? false
         remaining-headers 16]
    (when (zero? remaining-headers)
      (throw (ex-info "too many IPv6 extension headers" {})))
    (case next-header
      (0 43 60)
      (do
        (require-bytes! frame offset 2 "truncated IPv6 extension header")
        (let [following (u8 frame offset)
              header-bytes (* 8 (inc (u8 frame (inc offset))))]
          (require-bytes! frame offset header-bytes
                          "truncated IPv6 extension body")
          (recur (+ offset header-bytes)
                 following
                 non-first-fragment?
                 (dec remaining-headers))))

      44
      (do
        (require-bytes! frame offset 8 "truncated IPv6 fragment header")
        (let [following (u8 frame offset)
              fragment-field (u16 frame (+ offset 2))]
          (recur (+ offset 8)
                 following
                 (pos? (bit-and fragment-field 0xfff8))
                 (dec remaining-headers))))

      51
      (do
        (require-bytes! frame offset 2 "truncated IPv6 AH header")
        (let [following (u8 frame offset)
              header-bytes (* 4 (+ 2 (u8 frame (inc offset))))]
          (require-bytes! frame offset header-bytes "truncated IPv6 AH body")
          (recur (+ offset header-bytes)
                 following
                 non-first-fragment?
                 (dec remaining-headers))))

      {:offset offset
       :protocol next-header
       :non-first-fragment? non-first-fragment?})))

(defn- ipv6-flow
  [^bytes frame ^long offset packet]
  (require-bytes! frame offset 40 "truncated IPv6 header")
  (let [version (bit-shift-right (u8 frame offset) 4)]
    (when-not (= version 6)
      (throw (ex-info "invalid IPv6 version" {:version version})))
    (let [{:keys [protocol non-first-fragment?]
           transport-offset :offset}
          (ipv6-transport frame (+ offset 40) (u8 frame (+ offset 6)))
          packed (packed-ports frame
                               transport-offset
                               protocol
                               non-first-fragment?)]
      (flow-map packet
                6
                protocol
                [(i64 frame (+ offset 8))
                 (i64 frame (+ offset 16))]
                [(i64 frame (+ offset 24))
                 (i64 frame (+ offset 32))]
                packed))))

(defn- project
  [^bytes frame packet]
  (let [ethernet (ethernet-payload frame)
        offset (unsigned-bit-shift-right ethernet 32)
        ethertype (bit-and ethernet 0xffffffff)]
    (case ethertype
      0x0800 (ipv4-flow frame offset packet)
      0x86dd (ipv6-flow frame offset packet)
      (throw (ex-info "unsupported flow ethertype"
                      {:ethertype ethertype})))))

(defn packet->flow
  "Project Ethernet IPv4/IPv6 bytes into numeric flow fields.

   IPv4 addresses are unsigned values in longs. IPv6 addresses are
   `[high-long low-long]` pairs. Throws `ex-info` for unsupported or truncated
  packets so the public facade can represent the failure as data."
  [^bytes frame]
  (project frame nil))

(defn project-packet
  "Project a capture packet map into metadata plus numeric flow fields.

   The returned array-map deliberately excludes the raw bytes."
  [packet]
  (project ^bytes (:bytes packet) packet))
