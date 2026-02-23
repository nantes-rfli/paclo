(ns paclo.dev
  "Quick REPL helpers for debugging and packet inspection.

   - (parse-hex s)      ; hex string -> packet map
   - (summarize pktmap) ; print concise summary
   - (hexd pktmap)      ; render :bytes as hex

   Example:
   (-> HBH-OK parse-hex summarize)
   (-> HBH-BAD parse-hex summarize)"
  (:require
   [clojure.string :as str]
   [paclo.parse :as parse]
   [paclo.pcap :as pcap]))

;; Minimal hex parser without test utility dependencies.
(defn hex->bytes ^bytes [^String s]
  (let [cleaned (-> s
                    str/lower-case
                    ;; Strip line comments and C-style blocks.
                    (str/replace #"(?m);.*$" "")
                    (str/replace #"(?s)/\*.*?\*/" "")
                    ;; Keep only hex digits.
                    (str/replace #"[^0-9a-f]" ""))]
    (when (odd? (count cleaned))
      (throw (ex-info "Odd number of hex digits" {:len (count cleaned)})))
    (byte-array
     (map (fn [[a b]]
            (unchecked-byte (Integer/parseInt (str a b) 16)))
          (partition 2 cleaned)))))

(defn parse-hex
  "Parse hex string `s` into a packet map."
  [^String s]
  (parse/packet->clj (hex->bytes s)))

(defn- fmt-bytes
  "Render byte[] as a string like: xx xx xx ..."
  [^bytes bs]
  (->> bs
       (map (fn [b]
              (let [i (int b)]
                (format "%02x" (bit-and 0xFF i)))))
       (str/join " ")))

(defn hexd
  "Render packet map :bytes as hex. Returns a string."
  [pkt]
  (fmt-bytes (:bytes pkt)))

(defn fragment-note
  "Return \"frag@<offset>\" when L3 fragment metadata is present."
  [l3]
  (when (:frag? l3)
    (str "frag@" (or (:frag-offset l3) 0))))

(defn vlan-summary
  "Join VLAN tag maps into a single display string, or nil when no tags exist."
  [vlan-tags]
  (when (seq vlan-tags)
    (str "VLAN:"
         (->> vlan-tags
              (map #(str " " (pcap/vlan-tag->str %)))
              (apply str)))))

(defn summarize
  "Print a compact summary and return the original packet map."
  [pkt]
  (let [{:keys [type l3 vlan-tags]} pkt
        l3t (:type l3)
        proto (or (:protocol l3) (:next-header l3))
        l4 (:l4 l3)]
    (println "L2:" type)
    (when (= :ethernet type)
      (print "  src/dst:" (:src pkt) "->" (:dst pkt) "eth" (format "0x%04X" (:eth pkt)))
      (when-let [vline (vlan-summary vlan-tags)]
        (print "  " vline))
      (println))
    (println "L3:" l3t)
    (case l3t
      :ipv4 (println "  proto" proto
                     "src" (:src l3) "dst" (:dst l3)
                     (when-let [frag (fragment-note l3)] (str " " frag)))
      :ipv6 (println "  nh" proto
                     "src" (or (:src-compact l3) (:src l3))
                     "dst" (or (:dst-compact l3) (:dst l3))
                     (when-let [frag (fragment-note l3)] (str " " frag)))
      :arp  (println "  op" (:op l3) "spa" (:spa l3) "tpa" (:tpa l3))
      nil)
    (println "L4:" (:type l4)
             (cond
               (= :udp (:type l4)) (str (:src-port l4) "->" (:dst-port l4) " len=" (:data-len l4))
               (= :tcp (:type l4)) (str (:src-port l4) "->" (:dst-port l4)
                                        " " (or (:flags-str l4) "")
                                        " len=" (:data-len l4))
               (= :icmpv4 (:type l4)) (str (or (:summary l4) (str "type=" (:icmp-type l4) " code=" (:code l4)))
                                           " len=" (:data-len l4))
               (= :icmpv6 (:type l4)) (str (or (:summary l4) (str "type=" (:icmp-type l4) " code=" (:code l4)))
                                           " len=" (:data-len l4))
               :else ""))

    (when-let [app (:app l4)]
      (println "App:" (:type app) app))
    pkt))

;; ------------------------------------------------------------
;; Minimal vectors for HBH experiments (valid/invalid)
;; ------------------------------------------------------------

(def HBH-OK
  "Ether(IPv6) + IPv6(PL=24, NH=HBH) + HBH(16B, NextHdr=UDP) + UDP(8B)"
  "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
   60 00 00 00 00 18 00 40
   20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
   20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
   11 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   12 34 56 78 00 08 00 00")

(def HBH-BAD-OVERRUN
  "HBH TLV length overrun (len=0x0D exceeds the 14B option area by 1 byte)."
  "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
   60 00 00 00 00 18 00 40
   20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
   20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
   11 01 01 0D
   00 00 00 00 00 00 00 00 00 00 00 00
   12 34 56 78 00 08 00 00")
