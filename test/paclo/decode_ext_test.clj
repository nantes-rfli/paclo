(ns paclo.decode-ext-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.core :as core]
   [paclo.decode-ext :as dx]
   [paclo.proto.dns-ext :as dns-ext]
   [paclo.test-util :as tu]))

(deftest post-decode-hook-annotates
  (dns-ext/register!)
  (try
    (let [pcap (-> (java.io.File/createTempFile "paclo-dx" ".pcap")
                   .getAbsolutePath)
          ;; IPv4/UDP/DNS 最小（既存 golden と同系）
          ipv4-udp-dns
          (tu/hex->bytes
           "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
            45 00 00 30 00 02 00 00 40 11 00 00
            C0 A8 01 64 08 08 08 08
            13 88 00 35 00 18 00 00
            00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00")]
      (core/write-pcap! [ipv4-udp-dns] pcap)
      (let [xs (vec (core/packets {:path pcap :decode? true}))]
        (is (= 1 (count xs)))
        (is (= "DNS message"
               (get-in (first xs) [:decoded :l3 :l4 :app :summary])))))
    (finally
      (dx/unregister! ::dns-summary))))

(deftest hooks-ignore-non-map-and-swallow-exceptions
  (let [pkt {:decoded {:l3 {:l4 {:type :udp}}}}]
    (dx/register! ::non-map (fn [_] :not-a-map))
    (dx/register! ::boom (fn [_] (throw (ex-info "boom" {}))))
    (dx/register! ::annotate (fn [m] (assoc-in m [:decoded :note] :ok)))
    (try
      (let [out (dx/apply! pkt)]
        (is (= :ok (get-in out [:decoded :note])))
        ;; 非 map 戻り値は無視されるため元のキーは保持される
        (is (= :udp (get-in out [:decoded :l3 :l4 :type]))))
      (finally
        (dx/unregister! ::annotate)
        (dx/unregister! ::boom)
        (dx/unregister! ::non-map)))))

(deftest hooks-preserve-registration-order
  (let [order (atom [])
        record (fn [k] (fn [m] (swap! order conj k) m))
        pkt {:decoded {:l3 {:l4 {:type :udp}}}}]
    (dx/register! ::a (record :a))
    (dx/register! ::b (record :b))
    ;; overwrite key moves it to the tail
    (dx/register! ::a (record :a2))
    (try
      (dx/apply! pkt)
      (is (= [:b :a2] @order))
      ;; 他テストのフックが先頭に残っていても末尾順は保証される
      (is (= [::b ::a] (vec (take-last 2 (dx/installed)))))
      (finally
        (dx/unregister! ::a)
        (dx/unregister! ::b)))))

(deftest hooks-unregister-prunes-order
  (let [pkt {:decoded {:l3 {:l4 {:type :udp}}}}
        identity-hook (fn [m] m)]
    ;; 保守のため既存を一旦クリア
    (doseq [k (dx/installed)] (dx/unregister! k))
    (try
      (dx/register! ::a identity-hook)
      (dx/register! ::b identity-hook)
      (dx/unregister! ::a)
      (is (= [::b] (vec (dx/installed))))
      ;; apply! が落ちないことも確認
      (is (= pkt (dx/apply! pkt)))
      (finally
        (doseq [k (dx/installed)] (dx/unregister! k))))))
