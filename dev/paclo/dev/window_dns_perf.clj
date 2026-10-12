(ns paclo.dev.window-dns-perf
  "Opt-in bounded analysis measurement; not native capture throughput.
   clojure -M:dev -m paclo.dev.window-dns-perf"
  (:require
   [paclo.dns :as dns]
   [paclo.window :as window])
  (:import
   [com.sun.management ThreadMXBean]
   [java.lang.management ManagementFactory]))

(def ^:private query {:time-us 0 :kind :query :id 42 :protocol :udp :ip-version 4
                      :src {:ip "192.0.2.1" :port 50000} :dst {:ip "192.0.2.53" :port 53}
                      :qname "example.com" :qtype 1 :qclass 1})
(defn- dns-run [n]
  (loop [i 0 state (dns/init {:timeout-us 100 :reuse-delay-us 50 :max-pending 1 :max-retired 1}) matches 0]
    (if (= i n)
      {:matches matches :pending (count (:pending state)) :retired (count (:retired state))}
      (let [t (* i 200) q (assoc query :time-us t)
            s (:state (dns/step state q))
            r (dns/step s (assoc q :kind :response :time-us (+ t 10) :src (:dst q) :dst (:src q)))
            advanced (dns/advance (:state r) (+ t 150))]
        (recur (inc i) (:state advanced) (+ matches (count (:events r))))))))
(defn- window-run [n]
  (loop [i 0 state (window/init {:width-us 1000 :max-windows 2 :max-groups 16}) output 0]
    (if (= i n)
      {:windows output :retained (count (:windows state))}
      (let [s (:state (window/step state {:time-us i :group (mod i 8) :captured-bytes 64}))
            r (window/advance s (inc i))]
        (recur (inc i) (:state r) (+ output (count (:events r))))))))
(defn- measure [label run]
  (let [^ThreadMXBean bean (ManagementFactory/getThreadMXBean)
        supported? (.isThreadAllocatedMemorySupported bean)]
    (when supported? (.setThreadAllocatedMemoryEnabled bean true))
    (dotimes [_ 3] (run 10000))
    (dotimes [iteration 5]
      (let [before (when supported? (.getCurrentThreadAllocatedBytes bean))
            start (System/nanoTime)
            result (run 50000)
            elapsed (- (System/nanoTime) start)
            bytes (when supported? (- (.getCurrentThreadAllocatedBytes bean) before))]
        (prn {:analysis label :run iteration :work-units 50000
              :unit (if (= label :dns) :query-response-advance :event-advance) :milliseconds (/ elapsed 1000000.0)
              :allocated-bytes bytes :result result})))))

(defn -main [& _]
  (try
    (prn {:scope :pure-analysis :jdk (System/getProperty "java.version")
          :clojure (clojure-version) :os (System/getProperty "os.name")
          :arch (System/getProperty "os.arch") :warmups 3 :warmup-work-units 10000 :runs 5 :drops 0})
    (measure :window window-run)
    (measure :dns dns-run)
    (finally (shutdown-agents))))
