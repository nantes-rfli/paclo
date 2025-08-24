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
       (byte (Integer/parseInt (.substring s (* 2 i) (+ (* 2 i) 2)) 16))))))

(deftest sni-extracts-example-dot-com
  ;; TLS1.2 Record + ClientHello（最小構成）に SNI=example.com を埋め込み
  ;; Record(type=22, ver=03 03, len=0x0043), Handshake(type=1,len=0x00003F)
  ;; Extensions に server_name(type=0) / host_name("example.com")
  (let [hex "
    16 03 03 00 43   01 00 00 3F   03 03
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00
    00 02   00 2F
    01   00
    00 14
      00 00   00 10
        00 0E
          00 00 0B
            65 78 61 6D 70 6C 65 2E 63 6F 6D
  "
        ba (hex->bytes hex)]
    (is (= "example.com" (tls-ext/extract-sni ba)))))

(deftest sni-nil-when-not-clienthello
  ;; ContentType=23(アプリケーションデータ) → SNI は抽出されない
  (let [hex "17 03 03 00 01 00"
        ba  (hex->bytes hex)]
    (is (nil? (tls-ext/extract-sni ba)))))
