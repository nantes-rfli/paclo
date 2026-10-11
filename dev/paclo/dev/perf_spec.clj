(ns paclo.dev.perf-spec
  "Pure benchmark case and profile definitions shared by workers and merger.")

(def offline-scenarios
  [:raw-seq :sync-loop :raw-reduce
   :full-decode :full-reduce
   :flow-aggregate :flow-reduce :flow-project
   :write-pipeline])

(def traffic-cases
  [{:id :udp-64 :frame-size 64 :traffic :udp}
   {:id :tcp-512 :frame-size 512 :traffic :tcp}
   {:id :mixed :frame-size 64
    :alternate-frame-size 512
    :traffic :mixed}])

(def profiles
  {:quick {:count 50000
           :cases traffic-cases}
   :reference {:count 1000000
               :cases traffic-cases}
   :stress {:count 10000000
            :cases traffic-cases}})

(defn expected-captured-bytes
  [{:keys [count frame-size alternate-frame-size traffic]}]
  (if (= traffic :mixed)
    (reduce +
            (take count
                  (cycle [(long frame-size)
                          (long (or alternate-frame-size frame-size))])))
    (* (long count) (long frame-size))))
