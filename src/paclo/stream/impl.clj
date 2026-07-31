(ns paclo.stream.impl
  "Internal bounded fan-out runtime.

  This namespace is an implementation detail and is not part of Paclo's
  public compatibility contract. Public stream functions will wrap these
  operations only after the v1.3 performance and lifecycle gates pass."
  (:require
   [clojure.core.async :as async])
  (:import
   [clojure.lang IReduceInit Seqable]
   [java.io Closeable]
   [java.util.concurrent.atomic AtomicInteger LongAdder]))

(def ^:private default-buffer-cap 1024)
(def ^:private default-close-timeout-ms 5000)

(deftype ^:private BlockedResult [status ^long blocked-ns])
(def ^:private nil-value (Object.))

(defprotocol ^:private BufferOps
  (-enqueue! [buffer mode boxed])
  (-take! [buffer])
  (-close! [buffer])
  (-abandon! [buffer])
  (-depth [buffer]))

(deftype ^:private AsyncBuffer [channel buffer closed?]
  BufferOps
  (-enqueue! [_ mode boxed]
    (if @closed?
      :cancelled
      (case mode
        :dropping
        (if (async/offer! channel boxed)
          :enqueued
          :dropped)

        :blocking
        (if (async/offer! channel boxed)
          :enqueued
          (let [started (System/nanoTime)
                accepted? (async/>!! channel boxed)]
            (BlockedResult.
             (if accepted? :enqueued :cancelled)
             (- (System/nanoTime) started)))))))

  (-take! [_]
    (async/<!! channel))

  (-close! [_]
    (when (compare-and-set! closed? false true)
      (async/close! channel))
    nil)

  (-abandon! [_]
    (loop [abandoned 0]
      (if (some? (async/poll! channel))
        (recur (unchecked-inc abandoned))
        abandoned)))

  (-depth [_]
    (count buffer)))

(defn- adder []
  (LongAdder.))

(defn- update-max! [^AtomicInteger maximum ^long value]
  (loop [observed (.get maximum)]
    (when (and (< observed value)
               (not (.compareAndSet maximum observed (int value))))
      (recur (.get maximum)))))

(defn- make-buffer [capacity]
  (let [buffer (async/buffer capacity)]
    (AsyncBuffer. (async/chan buffer)
                  buffer
                  (atom false))))

(defn- branch-state [id {:keys [buffer-cap buffer-mode]}]
  {:id id
   :mode buffer-mode
   :capacity buffer-cap
   :buffer (make-buffer buffer-cap)
   :state (atom :open)
   :stop-reason (atom nil)
   :error (atom nil)
   :handle-claimed? (atom false)
   :consumer-claimed? (atom false)
   :offered (adder)
   :enqueued (adder)
   :delivered (adder)
   :dropped (adder)
   :cancelled (adder)
   :abandoned (adder)
   :blocked-events (adder)
   :blocked-ns (adder)
   :max-depth (AtomicInteger.)})

(defn- error-map [^Throwable error]
  (when error
    {:class (.getName (class error))
     :message (or (.getMessage error) (str error))}))

(defn- branch-open? [branch-state*]
  (= :open @(:state branch-state*)))

(defn- invoke-cancel! [runtime]
  (when (and (:cancel! runtime)
             (compare-and-set! (:cancel-called? runtime) false true))
    (try
      ((:cancel! runtime))
      (catch Throwable error
        (reset! (:cancel-error runtime) error))))
  nil)

(defn- no-open-branches? [runtime]
  (zero? (.get ^AtomicInteger (:open-branches runtime))))

(defn- branch-terminal-state [reason]
  (case reason
    :reduced :reduced
    :consumer-error :failed
    :fanout-closed :fanout-closed
    :closed))

(defn- close-branch-state! [runtime branch-state* reason]
  (let [state (:state branch-state*)]
    (loop []
      (let [observed @state]
        (if (not= :open observed)
          nil
          (if (compare-and-set! state
                                observed
                                (branch-terminal-state reason))
            (do
              (reset! (:stop-reason branch-state*) reason)
              (-close! (:buffer branch-state*))
              (.add ^LongAdder
               (:abandoned branch-state*)
                    (long (-abandon! (:buffer branch-state*))))
              (let [open-count
                    (.decrementAndGet
                     ^AtomicInteger (:open-branches runtime))]
                (when (and (zero? open-count)
                           (= :running @(:state runtime))
                           (compare-and-set! (:stop-reason runtime)
                                             nil
                                             :no-branches))
                  (reset! (:state runtime) :stopping)
                  (invoke-cancel! runtime)))
              nil)
            (recur)))))))

(defn- record-delivery! [branch-state* boxed]
  (when (branch-open? branch-state*)
    (.increment ^LongAdder (:offered branch-state*))
    (let [result (-enqueue! (:buffer branch-state*)
                            (:mode branch-state*)
                            boxed)
          blocked? (instance? BlockedResult result)
          status (if blocked?
                   (.-status ^BlockedResult result)
                   result)]
      (when blocked?
        (.increment ^LongAdder (:blocked-events branch-state*))
        (.add ^LongAdder
         (:blocked-ns branch-state*)
              (.-blocked-ns ^BlockedResult result)))
      (case status
        :enqueued
        (do
          (.increment ^LongAdder (:enqueued branch-state*))
          (let [depth (long (-depth (:buffer branch-state*)))]
            (update-max! ^AtomicInteger
             (:max-depth branch-state*)
                         (if (pos? depth) depth 1))))

        :dropped
        (do
          (.increment ^LongAdder (:dropped branch-state*))
          (update-max! ^AtomicInteger
           (:max-depth branch-state*)
                       (:capacity branch-state*)))

        :cancelled
        (.increment ^LongAdder (:cancelled branch-state*))

        (throw (ex-info "unknown stream enqueue result"
                        {:result status
                         :branch (:id branch-state*)}))))))

(defn- finish-runtime! [runtime reason error]
  (when error
    (reset! (:error runtime) error))
  (compare-and-set! (:stop-reason runtime) nil reason)
  (reset! (:state runtime) (if @(:error runtime) :failed :closed))
  (compare-and-set! (:ended-at-ms runtime)
                    nil
                    (System/currentTimeMillis))
  (doseq [branch-state* (vals (:branches runtime))]
    (when (branch-open? branch-state*)
      (-close! (:buffer branch-state*))))
  nil)

(defn- deliver-to-branches! [runtime boxed]
  (let [branches ^objects (:branch-array runtime)
        branch-count (alength branches)]
    (loop [index 0]
      (when (< index branch-count)
        (record-delivery! (aget branches index) boxed)
        (recur (unchecked-inc index))))))

(defn- take-source! [runtime]
  (let [source @(:source runtime)]
    (reset! (:source runtime) nil)
    source))

(defn- dispatch! [runtime]
  (try
    (let [reason
          (loop [remaining (seq (take-source! runtime))]
            (cond
              (some? @(:stop-reason runtime))
              @(:stop-reason runtime)

              (no-open-branches? runtime)
              (do
                (compare-and-set! (:stop-reason runtime) nil :no-branches)
                (invoke-cancel! runtime)
                :no-branches)

              (nil? remaining)
              :source-exhausted

              :else
              (let [value (first remaining)
                    item (if (nil? value) nil-value value)]
                (.increment ^LongAdder (:source-received runtime))
                (deliver-to-branches! runtime item)
                (recur (next remaining)))))]
      (finish-runtime! runtime reason nil))
    (catch Throwable error
      (finish-runtime! runtime :error error))))

(declare close-runtime!)
(declare branch-seq)
(declare reduce-branch)

(deftype ^:private Fanout [runtime]
  Closeable
  (close [_]
    (close-runtime! runtime)))

(deftype ^:private Branch [runtime branch-state*]
  Seqable
  (seq [_]
    (branch-seq runtime branch-state*))

  IReduceInit
  (reduce [_ rf init]
    (reduce-branch runtime branch-state* rf init))

  Closeable
  (close [_]
    (close-branch-state! runtime branch-state* :closed)))

(defn- fanout-runtime [value]
  (when-not (instance? Fanout value)
    (throw (ex-info "not a Paclo stream fan-out"
                    {:fanout value})))
  (.-runtime ^Fanout value))

(defn- claim-consumer! [branch-state*]
  (when-not (compare-and-set! (:consumer-claimed? branch-state*) false true)
    (throw (ex-info "stream branch may only be consumed once"
                    {:branch (:id branch-state*)}))))

(defn- finish-branch-drain! [runtime branch-state*]
  (when (branch-open? branch-state*)
    (if-let [source-error @(:error runtime)]
      (do
        (reset! (:error branch-state*) source-error)
        (compare-and-set! (:state branch-state*) :open :failed)
        (reset! (:stop-reason branch-state*) :source-error)
        (throw (ex-info "stream source failed"
                        {:branch (:id branch-state*)}
                        source-error)))
      (do
        (compare-and-set! (:state branch-state*) :open :completed)
        (compare-and-set! (:stop-reason branch-state*)
                          nil
                          :source-exhausted))))
  nil)

(defn- branch-seq [runtime branch-state*]
  (claim-consumer! branch-state*)
  (letfn [(drain []
            (lazy-seq
             (if-let [item (-take! (:buffer branch-state*))]
               (do
                 (.increment ^LongAdder (:delivered branch-state*))
                 (cons (when-not (identical? nil-value item) item)
                       (drain)))
               (do
                 (finish-branch-drain! runtime branch-state*)
                 nil))))]
    (drain)))

(defn- fail-branch! [runtime branch-state* error]
  (when (branch-open? branch-state*)
    (reset! (:error branch-state*) error)
    (close-branch-state! runtime branch-state* :consumer-error))
  nil)

(defn- reduce-branch [runtime branch-state* rf init]
  (claim-consumer! branch-state*)
  (try
    (loop [acc init]
      (if-let [item (-take! (:buffer branch-state*))]
        (do
          (.increment ^LongAdder (:delivered branch-state*))
          (let [value (when-not (identical? nil-value item) item)
                next-acc (rf acc value)]
            (if (reduced? next-acc)
              (do
                (close-branch-state! runtime branch-state* :reduced)
                @next-acc)
              (recur next-acc))))
        (do
          (finish-branch-drain! runtime branch-state*)
          acc)))
    (catch Throwable error
      (fail-branch! runtime branch-state* error)
      (throw error))))

(defn- close-runtime! [runtime]
  (let [requested? (compare-and-set! (:stop-reason runtime) nil :closed)]
    (when requested?
      (reset! (:state runtime) :stopping))
    (doseq [branch-state* (vals (:branches runtime))]
      (close-branch-state! runtime branch-state* :fanout-closed))
    (when requested?
      (invoke-cancel! runtime))
    (when-let [dispatcher @(:dispatcher runtime)]
      (when (= ::timeout
               (deref dispatcher
                      (:close-timeout-ms runtime)
                      ::timeout))
        (let [error (ex-info "stream dispatcher did not stop"
                             {:timeout-ms (:close-timeout-ms runtime)})]
          (reset! (:error runtime) error)
          (reset! (:stop-reason runtime) :close-timeout)
          (reset! (:state runtime) :failed)
          (throw error)))))
  nil)

(defn- positive-int-capacity? [value]
  (and (integer? value)
       (<= 1 (long value) Integer/MAX_VALUE)))

(defn- positive-integer? [value]
  (and (integer? value)
       (pos? (long value))))

(defn- validate-branches [branches]
  (when-not (and (map? branches) (seq branches))
    (throw (ex-info "stream fan-out requires a non-empty branch map"
                    {:branches branches})))
  (reduce-kv
   (fn [result id config]
     (when-not (keyword? id)
       (throw (ex-info "stream branch id must be a keyword"
                       {:branch id})))
     (when-not (map? config)
       (throw (ex-info "stream branch config must be a map"
                       {:branch id
                        :config config})))
     (let [capacity (or (:buffer-cap config) default-buffer-cap)
           mode (:buffer-mode config)]
       (when-not (positive-int-capacity? capacity)
         (throw (ex-info ":buffer-cap must be an integer between 1 and 2147483647"
                         {:branch id
                          :buffer-cap capacity})))
       (when-not (contains? #{:blocking :dropping} mode)
         (throw (ex-info ":buffer-mode must be :blocking or :dropping"
                         {:branch id
                          :buffer-mode mode})))
       (assoc result id {:buffer-cap capacity
                         :buffer-mode mode})))
   {}
   branches))

(defn start
  "Start an internal core.async-backed fan-out runtime.

  `source` must be seqable. Every branch requires an explicit
  `:buffer-mode` and has a bounded `:buffer-cap`. `:cancel!` must unblock an
  infinite or externally waiting source when the runtime is closed."
  ([source branches]
   (start source branches {}))
  ([source branches {:keys [cancel! close-timeout-ms]
                     :or {close-timeout-ms default-close-timeout-ms}}]
   (when-not (seqable? source)
     (throw (ex-info "stream source must be seqable"
                     {:source source})))
   (when-not (or (nil? cancel!) (ifn? cancel!))
     (throw (ex-info ":cancel! must be invokable"
                     {:cancel! cancel!})))
   (when-not (positive-integer? close-timeout-ms)
     (throw (ex-info ":close-timeout-ms must be a positive integer"
                     {:close-timeout-ms close-timeout-ms})))
   (let [configs (validate-branches branches)
         branch-states
         (reduce-kv
          (fn [result id config]
            (assoc result id (branch-state id config)))
          {}
          configs)
         runtime
         {:source (atom source)
          :backend :core-async
          :branches branch-states
          :branch-array (object-array (vals branch-states))
          :open-branches (AtomicInteger. (count branch-states))
          :state (atom :running)
          :stop-reason (atom nil)
          :error (atom nil)
          :cancel-error (atom nil)
          :cancel! cancel!
          :cancel-called? (atom false)
          :source-received (adder)
          :started-at-ms (System/currentTimeMillis)
          :ended-at-ms (atom nil)
          :dispatcher (atom nil)
          :close-timeout-ms close-timeout-ms}
         handle (Fanout. runtime)
         dispatcher (future (dispatch! runtime))]
     (reset! (:dispatcher runtime) dispatcher)
     handle)))

(defn branch
  "Acquire one internal Seqable, IReduceInit, and Closeable branch handle."
  [fanout id]
  (let [runtime (fanout-runtime fanout)
        branch-state* (get (:branches runtime) id)]
    (when-not branch-state*
      (throw (ex-info "unknown stream branch"
                      {:branch id
                       :known-branches (set (keys (:branches runtime)))})))
    (when-not (compare-and-set! (:handle-claimed? branch-state*)
                                false
                                true)
      (throw (ex-info "stream branch handle may only be acquired once"
                      {:branch id})))
    (Branch. runtime branch-state*)))

(defn- branch-snapshot [branch-state*]
  {:state @(:state branch-state*)
   :offered (.sum ^LongAdder (:offered branch-state*))
   :enqueued (.sum ^LongAdder (:enqueued branch-state*))
   :delivered (.sum ^LongAdder (:delivered branch-state*))
   :dropped (.sum ^LongAdder (:dropped branch-state*))
   :cancelled (.sum ^LongAdder (:cancelled branch-state*))
   :abandoned (.sum ^LongAdder (:abandoned branch-state*))
   :buffer {:mode (:mode branch-state*)
            :capacity (:capacity branch-state*)
            :depth (-depth (:buffer branch-state*))
            :max-depth (.get ^AtomicInteger (:max-depth branch-state*))
            :blocked-events
            (.sum ^LongAdder (:blocked-events branch-state*))
            :blocked-ns (.sum ^LongAdder (:blocked-ns branch-state*))}
   :stop-reason @(:stop-reason branch-state*)
   :error (error-map @(:error branch-state*))})

(defn stats
  "Return a data-only snapshot of the internal fan-out runtime."
  [fanout]
  (let [runtime (fanout-runtime fanout)
        now (long (or @(:ended-at-ms runtime)
                      (System/currentTimeMillis)))
        started-at-ms (long (:started-at-ms runtime))]
    {:schema-version 1
     :backend (:backend runtime)
     :state @(:state runtime)
     :timing {:started-at-ms started-at-ms
              :elapsed-ms (Math/max (long 0) (- now started-at-ms))}
     :source {:received (.sum ^LongAdder (:source-received runtime))}
     :branches
     (reduce-kv
      (fn [result id branch-state*]
        (assoc result id (branch-snapshot branch-state*)))
      {}
      (:branches runtime))
     :stop-reason @(:stop-reason runtime)
     :error (error-map @(:error runtime))
     :cancel-error (error-map @(:cancel-error runtime))}))

(defn await!
  "Wait for the internal dispatcher. Return true when it has stopped."
  ([fanout]
   (await! fanout default-close-timeout-ms))
  ([fanout timeout-ms]
   (when-not (positive-integer? timeout-ms)
     (throw (ex-info "stream await timeout must be a positive integer"
                     {:timeout-ms timeout-ms})))
   (let [runtime (fanout-runtime fanout)]
     (if-let [dispatcher @(:dispatcher runtime)]
       (not= ::timeout (deref dispatcher timeout-ms ::timeout))
       true))))
