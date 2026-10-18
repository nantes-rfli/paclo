(ns paclo.dev.stream-retention
  "Bounded-heap stream stress probe; synthetic payloads, no live-capture claim."
  (:require
   [paclo.dev.perf-metrics :as metrics]
   [paclo.stream.impl :as stream])
  (:import
   [java.io Closeable]
   [java.lang.ref WeakReference]))

(defn- require! [condition data]
  (when-not condition
    (throw (ex-info "stream retention probe failed" data))))

(defn- payloads [n size refs]
  ;; Unchunked and generated on demand: total payload greatly exceeds the heap.
  (letfn [(step [i]
            (lazy-seq
             (when (< i n)
               (let [bytes (byte-array size)]
                 (when (zero? (mod i 1000))
                   (swap! refs conj (WeakReference. bytes)))
                 (cons {:index i :bytes bytes} (step (inc i)))))))]
    (step 0)))

(defn- consume [branch]
  (reduce (fn [expected {:keys [index bytes]}]
            (require! (= expected index) {:expected expected :actual index})
            (require! (pos? (alength ^bytes bytes)) {:index index})
            (inc expected))
          0 branch))

(defn- completed-run [n size refs]
  (let [fanout (stream/start (payloads n size refs)
                             {:left {:buffer-mode :blocking :buffer-cap 8}
                              :right {:buffer-mode :blocking :buffer-cap 8}
                              :idle {:buffer-mode :dropping :buffer-cap 4}})]
    (with-open [^Closeable f fanout
                ^Closeable left (stream/branch f :left)
                ^Closeable right (stream/branch f :right)
                ^Closeable idle (stream/branch f :idle)]
      (let [a (future (consume left))
            b (future (consume right))]
        (require! (= n (deref a 120000 ::timeout) (deref b 120000 ::timeout))
                  {:phase :delivery})
        (require! (true? (stream/await! f)) {:phase :dispatch})
        (require! (= 4 (reduce (fn [n _] (inc n)) 0 idle)) {:phase :idle})))
    ;; Return the handle too: completed runtime ownership must not retain input.
    fanout))

(defn- abandoned-run [size refs]
  (let [fanout (stream/start (payloads 1000 size refs)
                             {:blocked {:buffer-mode :blocking :buffer-cap 4}})
        deadline (+ (System/currentTimeMillis) 5000)]
    (with-open [^Closeable f fanout]
      (loop []
        (let [received (get-in (stream/stats f) [:source :received])]
          (when (< received 5)
            (require! (< (System/currentTimeMillis) deadline) {:phase :saturate})
            (Thread/sleep 1)
            (recur)))))
    (require! (true? (stream/await! fanout)) {:phase :abandon})
    fanout))

(defn- check-stats! [fanout]
  (doseq [[id {:keys [offered enqueued delivered dropped cancelled abandoned buffer]}]
          (:branches (stream/stats fanout))]
    (require! (= offered (+ enqueued dropped cancelled)) {:branch id :phase :offered})
    (require! (= enqueued (+ delivered abandoned)) {:branch id :phase :enqueued})
    (require! (zero? (:depth buffer)) {:branch id :phase :depth})
    (require! (<= (:max-depth buffer) (:capacity buffer)) {:branch id :phase :capacity})))

(defn run-probe! [n size]
  (let [refs (atom [])
        completed (completed-run n size refs)
        abandoned (mapv (fn [_] (abandoned-run size refs)) (range 50))
        handles (into [completed] abandoned)]
    (doseq [handle handles] (check-stats! handle))
    (let [deadline (+ (System/currentTimeMillis) 5000)
          retained
          (loop []
            (System/gc)
            (Thread/sleep 25)
            (let [remaining (count (filter #(.get ^WeakReference %) @refs))]
              (if (and (pos? remaining) (< (System/currentTimeMillis) deadline))
                (recur)
                remaining)))]
      (require! (zero? retained) {:phase :retention :retained retained})
      ;; Inspect after GC to keep all handles strongly reachable throughout.
      (doseq [handle handles] (check-stats! handle))
      {:packets n :bytes (* n size) :payload-bytes size
       :sampled-payloads (count @refs) :retained-payloads retained
       :abandon-cycles (count abandoned)
       :stream-stats (stream/stats completed)})))

(defn -main [& [count-arg size-arg output]]
  (try
    (let [n (Long/parseLong (or count-arg "100000"))
          size (Long/parseLong (or size-arg "65536"))
          result {:environment (metrics/environment)
                  :measurement (metrics/measure #(run-probe! n size))}]
      (if output
        (spit output (str (pr-str result) "\n"))
        (prn result)))
    (finally (shutdown-agents))))
