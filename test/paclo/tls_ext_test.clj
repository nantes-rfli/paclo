(ns paclo.tls-ext-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is]]
   [paclo.proto.tls-ext :as tls-ext]))

(defn hex->bytes ^bytes [^String hex]
  (let [s (str/replace hex #"[^0-9A-Fa-f]" "")
        n (/ (count s) 2)]
    (byte-array
     (for [i (range n)]
       (let [idx (unchecked-multiply 2 (long i))]
         (byte (Integer/parseInt (.substring s idx (unchecked-add idx 2)) 16)))))))

(def fixture-clienthello-sni-alpn
  "TLS1.2 ClientHello with SNI=example.com and ALPN=h2"
  "
    16 03 03 00 4C   01 00 00 48   03 03
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00
    00 02   00 2F
    01   00
    00 1D
      00 00   00 10
        00 0E
          00 00 0B
            65 78 61 6D 70 6C 65 2E 63 6F 6D
      00 10   00 05
        00 03
          02 68 32
  ")

(deftest sni-extracts-example-dot-com
  (let [ba (hex->bytes fixture-clienthello-sni-alpn)]
    (is (= "example.com" (tls-ext/extract-sni ba)))))

(deftest sni-nil-when-not-clienthello
  ;; ContentType=23(アプリケーションデータ) → SNI は抽出されない
  (let [hex "17 03 03 00 01 00"
        ba  (hex->bytes hex)]
    (is (nil? (tls-ext/extract-sni ba)))))

(deftest annotate-tls-sni-attaches-app
  (let [ba (hex->bytes fixture-clienthello-sni-alpn)
        pkt {:decoded {:l3 {:l4 {:type :tcp
                                 :payload ba}}}}
        annotate (deref #'tls-ext/annotate-tls-sni)
        out (annotate pkt)]
    (is (= :tls (get-in out [:decoded :l3 :l4 :app :type])))
    (is (= "example.com" (get-in out [:decoded :l3 :l4 :app :sni])))
    (is (= ["h2"] (get-in out [:decoded :l3 :l4 :app :alpn])))
    (is (re-find #"SNI=example.com"
                 (get-in out [:decoded :l3 :l4 :app :summary])))))

(deftest annotate-tls-sni-noop-when-non-tcp
  (let [pkt {:decoded {:l3 {:l4 {:type :udp :payload (byte-array 0)}}}}
        annotate (deref #'tls-ext/annotate-tls-sni)]
    (is (= pkt (annotate pkt)))))

(deftest extract-tls-info-returns-empty-map-when-alpn-truncated
  (let [full (hex->bytes fixture-clienthello-sni-alpn)
        truncated (byte-array (dec (alength full)))
        extract (deref #'tls-ext/extract-tls-info)]
    (System/arraycopy full 0 truncated 0 (alength truncated))
    (is (= {} (extract truncated)))))

(deftest extract-tls-info-empty-when-sni-list-empty
  ;; Extensions length present but SNI list length=0 ⇒ 安全に {} を返す
  (let [hex "
    16 03 03 00 2f
    01 00 00 2b
    03 03
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00
    00 00
    00
    00 05
    00 00 00 01 00
  "
        extract (deref #'tls-ext/extract-tls-info)]
    (is (= {} (extract (hex->bytes hex))))))

(deftest extract-tls-info-sni-only-when-alpn-empty
  ;; 既存フィクスチャを改変し、ALPN extension の長さを 0 にする
  (let [ba (hex->bytes fixture-clienthello-sni-alpn)
        ba' (byte-array ba)]
    ;; extensions length 0x001d -> 0x001a (index 50-51)
    (aset-byte ba' 51 (byte 0x1A))
    ;; ALPN ext length 0x0005 -> 0x0002 (index 75)
    (aset-byte ba' 75 (byte 0x02))
    ;; ALPN protocol list length -> 0 (index 76-77)
    (aset-byte ba' 76 (byte 0x00))
    (aset-byte ba' 77 (byte 0x00))
    (let [info ((deref #'tls-ext/extract-tls-info) ba')]
      (is (= "example.com" (:sni info)))
      (is (nil? (:alpn info))))))

(deftest extract-tls-info-alpn-extension-empty
  ;; ALPN 拡張の長さフィールドを 0 にした場合も安全に SNI のみ残す
  (let [ba (hex->bytes fixture-clienthello-sni-alpn)
        ba' (byte-array ba)]
    ;; ALPN ext length => 0 (indices 72-73 hold ext type? Wait ext type at 72? Actually ALPN ext starts at 72)
    ;; Using known offsets from fixture: ext type at 72-73 = 00 10, ext len at 74-75 = 00 05
    (aset-byte ba' 74 (byte 0x00))
    (aset-byte ba' 75 (byte 0x00))
    ;; also fix extensions total len (50-51) from 0x001d -> 0x0018 (minus 5)
    (aset-byte ba' 51 (byte 0x18))
    (let [info ((deref #'tls-ext/extract-tls-info) ba')]
      (is (= "example.com" (:sni info)))
      (is (nil? (:alpn info))))))
