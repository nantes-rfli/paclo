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
