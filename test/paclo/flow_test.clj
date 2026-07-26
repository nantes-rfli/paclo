(ns paclo.flow-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.core :as core]
   [paclo.dev.perf-data :as data]
   [paclo.flow :as flow]
   [paclo.test-util :as test-util]))

(deftest projects-ipv4-udp-with-numeric-addresses
  (is (= {:ip-version 4
          :protocol 17
          :src-ip 167772161
          :dst-ip 167772162
          :src-port 12000
          :dst-port 5300}
         (flow/packet->flow
          (data/ethernet-ipv4-frame 64 :udp)))))

(deftest projects-vlan-ipv4
  (let [packet
        (test-util/hex->bytes
         "FF FF FF FF FF FF 00 00 00 00 00 01 81 00 00 64 08 00
          45 00 00 1C 00 02 00 00 40 11 00 00
          C0 A8 01 64 08 08 08 08
          13 88 00 35 00 08 00 00")]
    (is (= {:ip-version 4
            :protocol 17
            :src-ip 3232235876
            :dst-ip 134744072
            :src-port 5000
            :dst-port 53}
           (flow/packet->flow packet)))))

(deftest projects-ipv6-extension-header
  (let [packet
        (test-util/hex->bytes
         "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
          60 00 00 00 00 18 00 40
          20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
          20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
          11 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
          12 34 56 78 00 08 00 00")
        result (flow/packet->flow packet)]
    (is (= 6 (:ip-version result)))
    (is (= 17 (:protocol result)))
    (is (= 4660 (:src-port result)))
    (is (= 22136 (:dst-port result)))
    (is (= 2 (count (:src-ip result))))
    (is (= 2 (count (:dst-ip result))))))

(deftest non-first-fragment-has-no-ports
  (let [packet
        (test-util/hex->bytes
         "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
          60 00 00 00 00 08 2C 40
          20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
          20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
          06 00 00 08 12 34 56 78")
        result (flow/packet->flow packet)]
    (is (= 6 (:protocol result)))
    (is (nil? (:src-port result)))
    (is (nil? (:dst-port result)))))

(deftest projection-rejects-truncated-input
  (is (thrown-with-msg? clojure.lang.ExceptionInfo
                        #"truncated ethernet"
                        (flow/packet->flow (byte-array 4)))))

(deftest reduce-packets-flow-mode-is-flat
  (let [file (java.io.File/createTempFile "paclo-flow-test" ".pcap")
        frame (data/ethernet-ipv4-frame 64 :udp)]
    (try
      (core/write-pcap! [frame] (.getAbsolutePath file))
      (let [result (core/reduce-packets
                    {:path (.getAbsolutePath file)
                     :max 1
                     :max-time-ms 60000
                     :decode-mode :flow}
                    conj
                    [])
            packet (first result)]
        (is (= 4 (:ip-version packet)))
        (is (= 167772161 (:src-ip packet)))
        (is (= 12000 (:src-port packet)))
        (is (not (contains? packet :bytes)))
        (is (not (contains? packet :decoded))))
      (finally
        (.delete file)))))

(deftest reduce-packets-validates-decode-mode
  (is (thrown-with-msg? clojure.lang.ExceptionInfo
                        #"cannot be combined"
                        (core/reduce-packets
                         {:path "unused"
                          :decode? true
                          :decode-mode :flow}
                         conj
                         [])))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo
                        #"unsupported :decode-mode"
                        (core/reduce-packets
                         {:path "unused"
                          :decode-mode :tree}
                         conj
                         []))))
