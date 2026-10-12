(ns paclo.window-test
  (:require
   [clojure.edn :as edn]
   [clojure.test :refer [deftest is]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [paclo.window :as window]))

(declare floor-boundaries bounded-replay-and-release)

(def opts {:width-us 10 :max-windows 5 :max-groups 10 :allowed-lateness-us 2})
(defn event [t group] {:time-us t :group group :captured-bytes 7})
(defn add [s e] (:state (window/step s e)))
(defn reason [f]
  (try (f) nil (catch clojure.lang.ExceptionInfo e (:reason (ex-data e)))))

(deftest half-open-boundaries-and-groups
  (let [initial (window/init opts)
        state (reduce add initial [(event -11 :a) (event -10 :a) (event -1 :b)
                                   (event 0 :a) (event 9 :a) (event 10 :a)])]
    (is (= [-20 -10 0 10] (vec (keys (:windows state)))))
    (is (= {:packets 2 :captured-bytes 14} (get-in state [:windows 0 :a])))
    (is (= #{:a :b} (set (keys (get-in state [:windows -10])))))
    (is (= 5 (:group-count state)))
    (is (= initial (window/init opts)))
    (is (= state (reduce add initial [(event 10 :a) (event 9 :a) (event 0 :a)
                                      (event -1 :b) (event -10 :a) (event -11 :a)])))))

(deftest watermark-lateness-and-finish
  (let [state (add (window/init opts) (event 0 :a))
        before (window/advance state 11)
        extra (window/step (:state before) (event 9 :b))
        closed (window/advance (:state extra) 12)]
    (is (empty? (:events before)))
    (is (= 1 (count (:windows (:state extra)))))
    (is (= [{:kind :window :start-us 0 :end-us 10 :complete? true
             :groups {:a {:packets 1 :captured-bytes 7} :b {:packets 1 :captured-bytes 7}}}]
           (:events closed)))
    (is (empty? (get-in closed [:state :windows])))
    (is (zero? (get-in closed [:state :group-count])))
    (doseq [t [-100 0 9]]
      (let [late (window/step (:state closed) (event t :a))]
        (is (= :late-event (get-in late [:events 0 :kind])))
        (is (= (:state closed) (:state late)))))
    (is (= [] (:events (window/advance (:state closed) 12))))
    (is (= :watermark-regression (reason #(window/advance (:state closed) 11))))
    (is (= state (add (window/init opts) (event 0 :a)))))
  (let [initial (window/init opts)
        sparse (reduce add initial [(event 0 :a) (event 100000000000000000000N :b)])
        finished (window/finish sparse)]
    (is (= 2 (count (:events finished))))
    (is (every? false? (map :complete? (:events finished))))
    (is (= [] (:events (window/finish (:state finished)))))
    (is (= :finished (reason #(window/step (:state finished) (event 0 :a)))))
    (is (= :finished (reason #(window/advance (:state finished) 0))))
    (is (= [] (:events (window/finish initial))))
    (is (= [] (:events (window/advance initial 100000000000000000000N))))))

(deftest invalid-input-and-capacity
  (doseq [k [:width-us :max-windows :max-groups]
          v [nil 0 -1 1.5]]
    (is (= :invalid-options (reason #(window/init (assoc opts k v))))))
  (doseq [v [nil -1 1.5]]
    (is (= :invalid-options (reason #(window/init (assoc opts :allowed-lateness-us v))))))
  (doseq [v [nil 1.5 "1"]]
    (is (= :invalid-time (reason #(window/step (window/init opts) (event v :a)))))
    (is (= :invalid-time (reason #(window/advance (window/init opts) v)))))
  (doseq [e [(dissoc (event 0 :a) :group) (assoc (event 0 :a) :group (byte-array 1))
             (assoc (event 0 :a) :group {:bad identity})
             (assoc (event 0 :a) :captured-bytes -1) (assoc (event 0 :a) :captured-bytes 1.5)]]
    (is (= :invalid-event (reason #(window/step (window/init opts) e)))))
  (let [initial (window/init (assoc opts :max-windows 1 :max-groups 1))
        state (add initial (event 0 :a))]
    (is (= :max-windows (reason #(add state (event 10 :a)))))
    (is (= :max-groups (reason #(add state (event 0 :b)))))
    (is (= 2 (get-in (add state (event 1 :a)) [:windows 0 :a :packets])))
    (is (= 1 (:group-count (add (:state (window/advance state 12)) (event 12 :b)))))))

(deftest arbitrary-precision-time-and-totals
  (let [state (window/init (assoc opts :width-us Long/MAX_VALUE))
        state (add state {:time-us Long/MAX_VALUE :group nil :captured-bytes Long/MAX_VALUE})
        state (add state {:time-us Long/MAX_VALUE :group nil :captured-bytes 1})
        result (window/advance state (+' (*' 2 Long/MAX_VALUE) 2))]
    (is (= (*' 2 Long/MAX_VALUE) (get-in result [:events 0 :end-us])))
    (is (= (inc' Long/MAX_VALUE) (get-in result [:events 0 :groups nil :captured-bytes])))
    (is (= result (edn/read-string (pr-str result)))))
  (let [s (add (window/init opts) (event Long/MIN_VALUE :a))]
    (is (< (first (keys (:windows s))) Long/MIN_VALUE))))

(defspec floor-boundaries 200
  (prop/for-all [t gen/large-integer width (gen/choose 1 1000000)]
                (let [s (add (window/init (assoc opts :width-us width)) (event t :a))
                      start (first (keys (:windows s)))]
                  (and (zero? (mod start width)) (<= start t) (< t (+' start width))))))

(defspec bounded-replay-and-release 200
  (prop/for-all [times (gen/vector (gen/choose -20 20) 0 50)]
                (let [events (mapv #(event % (mod % 2)) times)
                      initial (window/init opts)
                      snapshots (reductions add initial events)
                      a (last snapshots) b (transduce identity (completing add) initial events)
                      closed (window/advance a 32)]
                  (and (= a b) (= a (reduce add initial events))
                       (= a (edn/read-string (pr-str a))) (= initial (window/init opts))
                       (every? #(and (<= (count (:windows %)) 5) (<= (:group-count %) 10)) snapshots)
                       (empty? (get-in closed [:state :windows]))
                       (= (reduce + 0 (map #(reduce + 0 (map :packets (vals (:groups %)))) (:events closed)))
                          (count events))))))

(deftest edn-restored-state-retains-window-order-and-expiry
  (let [state (reduce add (window/init (assoc opts :max-windows 100 :max-groups 100))
                      (map #(event % :a) (range -100 200 10)))
        restored (edn/read-string (pr-str state))]
    (is (= (window/advance state 52) (window/advance restored 52)))
    (is (= (window/finish state) (window/finish restored)))
    (is (= (window/step state (event 51 :b)) (window/step restored (event 51 :b))))))

(deftest group-bound-is-total-and-zero-lateness-is-default
  (let [state (window/init {:width-us 10 :max-windows 2 :max-groups 1})
        state (add state (event 0 :a))]
    (is (= :max-groups (reason #(add state (event 10 :a)))))
    (is (empty? (:events (window/advance state 9))))
    (is (= 1 (count (:events (window/advance state 10)))))
    (is (= [:late-event] (mapv :kind (:events (window/step (:state (window/advance state 10))
                                                           (event 9 :a))))))))

(deftest group-metadata-cannot-retain-packets-or-mutable-values
  (let [hidden {:bytes (byte-array 20) :error (Throwable.) :packet (delay {:bad true})}
        group (with-meta [(with-meta 'dns hidden) (with-meta [:a] hidden)] hidden)
        result (window/finish (add (window/init opts) (event 0 group)))
        stored (first (keys (get-in result [:events 0 :groups])))]
    (is (= ['dns [:a]] stored))
    (is (every? nil? [(meta stored) (meta (first stored)) (meta (second stored))]))
    (is (= result (edn/read-string (pr-str result))))
    (is (= hidden (meta group)))))
