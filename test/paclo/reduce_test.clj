(ns paclo.reduce-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.core :as core]
   [paclo.dev.perf-data :as data]
   [paclo.pcap :as pcap]))

(defn- with-pcap-file [packet-count f]
  (let [file (java.io.File/createTempFile "paclo-reduce-test" ".pcap")
        frame (data/ethernet-ipv4-frame 64 :udp)]
    (try
      (core/write-pcap! (repeat packet-count frame)
                        (.getAbsolutePath file))
      (f (.getAbsolutePath file))
      (finally
        (when (.exists file)
          (.delete file))))))

(deftest reduce-packets-matches-seq-count-and-bytes
  (with-pcap-file
    20
    (fn [path]
      (let [opts {:path path :max 20 :max-time-ms 60000}
            expected (reduce
                      (fn [acc packet]
                        (-> acc
                            (update :packets inc)
                            (update :bytes + (:caplen packet))))
                      {:packets 0 :bytes 0}
                      (core/packets opts))
            actual (core/reduce-packets
                    opts
                    (fn [acc packet]
                      (-> acc
                          (update :packets inc)
                          (update :bytes + (:caplen packet))))
                    {:packets 0 :bytes 0})]
        (is (= expected actual))))))

(deftest reduce-packets-fuses-xform
  (with-pcap-file
    5
    (fn [path]
      (is (= [64 64 64 64 64]
             (core/reduce-packets
              {:path path
               :max 5
               :max-time-ms 60000
               :xform (map :caplen)}
              conj
              []))))))

(deftest reduce-packets-decode-matches-seq
  (with-pcap-file
    3
    (fn [path]
      (let [opts {:path path
                  :max 3
                  :max-time-ms 60000
                  :decode? true}
            normalize #(update-in % [:l3 :l4 :payload] vec)
            expected (mapv (comp normalize :decoded) (core/packets opts))
            actual (mapv
                    normalize
                    (core/reduce-packets
                     opts
                     (fn [acc packet] (conj acc (:decoded packet)))
                     []))]
        (is (= expected actual))))))

(deftest reduce-packets-honors-reduced
  (with-pcap-file
    20
    (fn [path]
      (is (= 7
             (core/reduce-packets
              {:path path :max 20 :max-time-ms 60000}
              (fn [count _]
                (let [next-count (inc count)]
                  (if (= next-count 7)
                    (reduced next-count)
                    next-count)))
              0))))))

(deftest reduce-packets-validates-filter
  (is (thrown-with-msg? clojure.lang.ExceptionInfo
                        #"invalid :filter"
                        (core/reduce-packets
                         {:path "unused.pcap" :filter 42}
                         (fn [acc _] acc)
                         nil))))

(deftest reduce-capture-closes-and-honors-stop
  (let [closed (atom 0)
        stopped (atom 0)
        ready (atom 0)
        setup-events (atom [])]
    (with-redefs [pcap/open-offline (fn [_] :handle)
                  pcap/set-bpf! (fn [& _]
                                  (swap! setup-events conj :filter)
                                  true)
                  pcap/close! (fn [_] (swap! closed inc))
                  pcap/loop-n-or-ms!
                  (fn [_ config handler]
                    (loop [[packet & more]
                           [{:caplen 1} {:caplen 2} {:caplen 3}]]
                      (when packet
                        (handler packet)
                        (if ((:stop? config) packet)
                          (swap! stopped inc)
                          (recur more)))))]
      (is (= 3
             (pcap/reduce-capture
              {:path "dummy"
               :filter "udp"
               :on-ready #(do
                            (swap! ready inc)
                            (swap! setup-events conj :ready))
               :stop? #(= 2 (:caplen %))}
              (fn [acc packet] (+ acc (:caplen packet)))
              0)))
      (is (= 1 @stopped))
      (is (= 1 @ready))
      (is (= [:filter :ready] @setup-events))
      (is (= 1 @closed)))))

(deftest reduce-capture-error-mode-pass-returns-last-accumulator
  (let [reported (atom nil)
        closed (atom 0)]
    (with-redefs [pcap/open-offline (fn [_] :handle)
                  pcap/close! (fn [_] (swap! closed inc))
                  pcap/loop-n-or-ms!
                  (fn [_ _ handler]
                    (handler {:caplen 2})
                    (throw (RuntimeException. "capture failed")))]
      (testing "pass mode reports and returns accumulated state"
        (is (= 2
               (pcap/reduce-capture
                {:path "dummy"
                 :error-mode :pass
                 :on-error #(reset! reported (.getMessage ^Throwable %))}
                (fn [acc packet] (+ acc (:caplen packet)))
                0)))
        (is (= "capture failed" @reported))
        (is (= 1 @closed))))))
