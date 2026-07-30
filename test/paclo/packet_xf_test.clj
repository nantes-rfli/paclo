(ns paclo.packet-xf-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.core :as core]
   [paclo.decode-ext :as decode-ext]
   [paclo.dev.perf-data :as data]
   [paclo.flow :as flow]
   [paclo.parse :as parse]
   [paclo.pcap :as pcap]))

(deftest packet-xf-is-an-identity-without-a-decode-option
  (let [packet {:id 1}
        result (first (sequence (core/packet-xf {}) [packet]))]
    (is (identical? packet result))))

(deftest packet-xf-performs-full-decode-and-extensions
  (let [decoded (atom 0)
        extended (atom 0)
        packets [{:id 1 :bytes (byte-array 14)}
                 {:id 2 :bytes (byte-array 5)}]]
    (with-redefs [parse/packet->clj
                  (fn [_]
                    (swap! decoded inc)
                    {:l2 {:type :ethernet}})
                  decode-ext/apply!
                  (fn [packet]
                    (swap! extended inc)
                    (assoc packet :extended? true))]
      (let [[valid short] (into [] (core/packet-xf {:decode? true}) packets)]
        (is (= 1 @decoded))
        (is (= 1 @extended))
        (is (= {:l2 {:type :ethernet}} (:decoded valid)))
        (is (true? (:extended? valid)))
        (is (re-find #"frame too short: 5 bytes" (:decode-error short)))
        (is (not (contains? short :decoded)))))))

(deftest packet-xf-preserves-full-decode-error-contract
  (with-redefs [parse/packet->clj
                (fn [_]
                  (throw (RuntimeException. "invalid packet")))]
    (let [packet {:id 1 :bytes (byte-array 14)}
          result (first (sequence (core/packet-xf {:decode? true})
                                  [packet]))]
      (is (= 1 (:id result)))
      (is (= "invalid packet" (:decode-error result)))
      (is (not (contains? result :decoded))))))

(deftest packet-xf-projects-flows-and-preserves-flow-error-contract
  (testing "successful projection"
    (with-redefs [flow/project-packet
                  (fn [packet]
                    {:protocol 17 :source-id (:id packet)})]
      (is (= [{:protocol 17 :source-id 7}]
             (into []
                   (core/packet-xf {:decode-mode :flow})
                   [{:id 7 :bytes (byte-array 14)}])))))
  (testing "projection failure"
    (with-redefs [flow/project-packet
                  (fn [_]
                    (throw (RuntimeException. "bad flow")))]
      (let [result
            (first
             (sequence
              (core/packet-xf {:decode-mode :flow})
              [{:ts-sec 1
                :ts-usec 2
                :caplen 3
                :len 4
                :bytes (byte-array 3)}]))]
        (is (= {:ts-sec 1
                :ts-usec 2
                :caplen 3
                :len 4
                :decode-error "bad flow"}
               result))))))

(deftest packet-xf-validates-options-when-created
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"cannot be combined"
       (core/packet-xf {:decode? true :decode-mode :flow})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"unsupported :decode-mode"
       (core/packet-xf {:decode-mode :tree}))))

(deftest packet-xf-composes-with-standard-transducers
  (with-redefs [flow/project-packet
                (fn [packet]
                  {:protocol (:protocol packet)
                   :dst-port (:dst-port packet)})]
    (is (= [53]
           (transduce
            (comp
             (core/packet-xf {:decode-mode :flow})
             (filter #(= 17 (:protocol %)))
             (map :dst-port))
            conj
            []
            [{:protocol 17 :dst-port 53}
             {:protocol 6 :dst-port 443}])))))

(deftest packets-uses-the-public-packet-transformation-contract
  (with-redefs [pcap/capture->seq
                (fn [_]
                  [{:id 1 :bytes (byte-array 14)}])
                flow/project-packet
                (fn [packet]
                  {:source-id (:id packet) :protocol 17})]
    (is (= [{:source-id 1 :protocol 17}]
           (vec
            (core/packets
             {:path "dummy"
              :decode-mode :flow}))))))

(deftest packet-transformations-match-across-execution-models
  (let [file (java.io.File/createTempFile "paclo-packet-xf" ".pcap")
        path (.getAbsolutePath file)
        frame (data/ethernet-ipv4-frame 64 :udp)
        source-opts {:path path :max 2 :max-time-ms 60000}
        flow-opts (assoc source-opts :decode-mode :flow)]
    (try
      (core/write-pcap! [{:bytes frame :sec 100 :usec 1000}
                         {:bytes frame :sec 200 :usec 2000}]
                        path)
      (let [expected
            (into []
                  (core/packet-xf {:decode-mode :flow})
                  (core/packets source-opts))
            lazy-result (vec (core/packets flow-opts))
            reduce-result (core/reduce-packets flow-opts conj [])
            managed-result
            (with-open [^java.io.Closeable capture
                        (core/start-capture flow-opts)]
              (vec (core/capture-packets capture)))]
        (is (= expected lazy-result reduce-result managed-result)))
      (finally
        (when (.exists file)
          (.delete file))))))
