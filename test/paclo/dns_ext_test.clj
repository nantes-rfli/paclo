(ns paclo.dns-ext-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.proto.dns-ext :as dns]))

;; Helpers to access privates
(def decode-name #'dns/decode-name)
(def annotate-qname-qtype #'dns/annotate-qname-qtype)
(def annotate-dns #'dns/annotate-dns)

(deftest decode-name-basic-and-compressed
  ;; message: www.google.com, type A, class IN
  (let [qname-bytes (byte-array
                     [3 (byte 0x77) (byte 0x77) (byte 0x77)
                      6 (byte 0x67) (byte 0x6f) (byte 0x6f) (byte 0x67) (byte 0x6c) (byte 0x65)
                      3 (byte 0x63) (byte 0x6f) (byte 0x6d)
                      0])
        header (byte-array 12)                     ; not inspected by decode-name
        question (byte-array
                  (concat (vec qname-bytes)
                          [0 1   ; QTYPE A
                           0 1])) ; QCLASS IN
        ba (byte-array (concat (vec header) (vec question)))
        [nm off] (decode-name ba 12)]
    (is (= "www.google.com" nm))
    (is (= (+ 12 (count qname-bytes)) off)))

  (testing "compression pointer reuses earlier name"
    ;; Layout:
    ;; 12B header
    ;; 0x0c: 3www6google3com0  (original)
    ;; after that: pointer c0 0c (alias)
    (let [base-name (byte-array [3 (byte 0x77) (byte 0x77) (byte 0x77)
                                 6 (byte 0x67) (byte 0x6f) (byte 0x6f) (byte 0x67) (byte 0x6c) (byte 0x65)
                                 3 (byte 0x63) (byte 0x6f) (byte 0x6d)
                                 0])
          header (byte-array 12)
          pointer (byte-array [(unchecked-byte 0xC0) (unchecked-byte 0x0C)])
          ba (byte-array (concat (vec header) (vec base-name) (vec pointer)))
          [nm off] (decode-name ba 12)
          [nm2 off2] (decode-name ba (+ 12 (count base-name)))]
      (is (= "www.google.com" nm))
      (is (= (+ 12 (count base-name)) off))
      (is (= "www.google.com" nm2))
      ;; pointer consumes two bytes only
      (is (= (+ 12 (count base-name) 2) off2)))))

(deftest annotate-qname-qtype-populates-fields
  ;; Build minimal DNS query with one question: example.com IN A
  (let [name-bytes (byte-array [7 (byte 0x65) (byte 0x78) (byte 0x61) (byte 0x6d) (byte 0x70) (byte 0x6c) (byte 0x65)
                                3 (byte 0x63) (byte 0x6f) (byte 0x6d)
                                0])
        header (byte-array 12) ; qdcount ignored here, value taken from app map
        question (byte-array (concat (vec name-bytes) [0 1 0 1])) ; A IN
        payload (byte-array (concat (vec header) (vec question)))
        m {:decoded {:l3 {:l4 {:payload payload
                               :app {:type :dns :qdcount 1}}}}}
        out (annotate-qname-qtype m)]
    (is (= "example.com" (get-in out [:decoded :l3 :l4 :app :qname])))
    (is (= 1 (get-in out [:decoded :l3 :l4 :app :qtype])))
    (is (= :A (get-in out [:decoded :l3 :l4 :app :qtype-name])))
    (is (= 1 (get-in out [:decoded :l3 :l4 :app :qclass])))))

(deftest annotate-dns-noop-when-not-dns
  (let [m {:decoded {:l3 {:l4 {:app {:type :other}}}}}
        out (annotate-dns m)]
    (is (= m out))))
