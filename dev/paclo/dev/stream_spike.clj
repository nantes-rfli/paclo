(ns paclo.dev.stream-spike
  "Internal v1.3 fan-out experiment.

  This namespace is intentionally outside the public API. It compares JDK
  queues and core.async channels behind the same Seqable/IReduceInit/Closeable
  branch contract."
  (:require
   [clojure.core.async :as async])
  (:import
   [clojure.lang IReduceInit Seqable]
   [java.io Closeable]
   [java.util.concurrent
    ArrayBlockingQueue
    BlockingQueue
    LinkedBlockingQueue
    TimeUnit]
   [java.util.concurrent.atomic AtomicInteger LongAdder]))

(def ^:private default-buffer-cap 1024)
(def ^:private default-close-timeout-ms 5000)
(def ^:private poll-ms 25)

(deftype ^:private Box [value])

(defprotocol ^:private BufferOps
  (-enqueue! [buffer mode boxed stop?])
  (-take! [buffer])
  (-close-buffer! [buffer])
  (-abandon! [buffer])
  (-depth [buffer]))

(deftype ^:private JdkBuffer
         [^BlockingQueue queue closed?]
  BufferOps
  (-enqueue! [_ mode boxed stop?]
    (if @closed?
      {:status :cancelled}
      (case mode
        :dropping
        (if (.offer queue boxed)
          {:status :enqueued}
          {:status :dropped})

        :blocking
        (if (.offer queue boxed)
          {:status :enqueued}
          (let [started (System/nanoTime)]
            (loop []
              (cond
                (or @closed? (stop?))
                {:status :cancelled
                 :blocked? true
                 :blocked-ns (- (System/nanoTime) started)}

                (.offer queue boxed poll-ms TimeUnit/MILLISECONDS)
                {:status :enqueued
                 :blocked? true
                 :blocked-ns (- (System/nanoTime) started)}

                :else
                (recur))))))))

  (-take! [_]
    (loop []
      (if-let [boxed (.poll queue 100 TimeUnit/MILLISECONDS)]
        boxed
        (when-not @closed?
          (recur)))))

  (-close-buffer! [_]
    (reset! closed? true)
    nil)

  (-abandon! [_]
    (let [abandoned (.size queue)]
      (.clear queue)
      abandoned))

  (-depth [_]
    (.size queue)))

(deftype ^:private AsyncBuffer
         [channel buffer closed?]
  BufferOps
  (-enqueue! [_ mode boxed _]
    (if @closed?
      {:status :cancelled}
      (case mode
        :dropping
        (if (async/offer! channel boxed)
          {:status :enqueued}
          {:status :dropped})

        :blocking
        (if (async/offer! channel boxed)
          {:status :enqueued}
          (let [started (System/nanoTime)
                accepted? (async/>!! channel boxed)]
            {:status (if accepted? :enqueued :cancelled)
             :blocked? true
             :blocked-ns (- (System/nanoTime) started)})))))

  (-take! [_]
    (async/<!! channel))

  (-close-buffer! [_]
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

(defn- make-buffer [backend capacity]
  (case backend
    :jdk-array
    (JdkBuffer. (ArrayBlockingQueue. (int capacity))
                (atom false))

    :jdk-linked
    (JdkBuffer. (LinkedBlockingQueue. (int capacity))
                (atom false))

    :core-async
    (let [buffer (async/buffer capacity)]
      (AsyncBuffer. (async/chan buffer)
                    buffer
                    (atom false)))

    (throw (ex-info "unsupported stream spike backend"
                    {:backend backend
                     :supported #{:jdk-array :jdk-linked :core-async}}))))

(defn- adder []
  (LongAdder.))

(defn- update-max! [^AtomicInteger maximum ^long value]
  (loop [observed (.get maximum)]
    (when (and (< observed value)
               (not (.compareAndSet maximum observed (int value))))
      (recur (.get maximum)))))

(defn- branch-state [backend id {:keys [buffer-cap buffer-mode]}]
  {:id id
   :mode buffer-mode
   :capacity buffer-cap
   :buffer (make-buffer backend buffer-cap)
   :state (atom :open)
   :stop-reason (atom nil)
   :error (atom nil)
   :handle-claimed? (atom false)
   :consumer-claimed? (atom false)
   :source-ended? (atom false)
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

(defn- branch-open? [branch]
  (= :open @(get branch :state)))

(defn- invoke-cancel! [runtime]
  (when (and (:cancel! runtime)
             (compare-and-set! (:cancel-called? runtime) false true))
    (try
      ((:cancel! runtime))
      (catch Throwable error
        (reset! (:cancel-error runtime) error))))
  nil)

(defn- no-open-branches? [runtime]
  (not-any? branch-open? (vals (:branches runtime))))

(defn- branch-terminal-state [reason]
  (case reason
    :reduced :reduced
    :consumer-error :failed
    :fanout-closed :fanout-closed
    :closed))

(defn- close-branch-state! [runtime branch reason]
  (let [state (:state branch)]
    (loop []
      (let [observed @state]
        (if (not= :open observed)
          nil
          (if (compare-and-set! state
                                observed
                                (branch-terminal-state reason))
            (do
              (reset! (:stop-reason branch) reason)
              (-close-buffer! (:buffer branch))
              (.add ^LongAdder
                    (:abandoned branch)
                    (long (-abandon! (:buffer branch))))
              (when (and (= :running @(:state runtime))
                         (no-open-branches? runtime)
                         (compare-and-set! (:stop-reason runtime)
                                           nil
                                           :no-branches))
                (reset! (:state runtime) :stopping)
                (invoke-cancel! runtime))
              nil)
            (recur)))))))

(defn- deliver! [runtime branch value]
  (when (branch-open? branch)
    (.increment ^LongAdder (:offered branch))
    (let [result (-enqueue! (:buffer branch)
                            (:mode branch)
                            (Box. value)
                            #(or (some? @(:stop-reason runtime))
                                 (not (branch-open? branch))))]
      (when (:blocked? result)
        (.increment ^LongAdder (:blocked-events branch))
        (.add ^LongAdder
              (:blocked-ns branch)
              (long (:blocked-ns result))))
      (case (:status result)
        :enqueued
        (do
          (.increment ^LongAdder (:enqueued branch))
          (let [depth (long (-depth (:buffer branch)))]
            (update-max! ^AtomicInteger
                         (:max-depth branch)
                         (if (pos? depth) depth 1))))

        :dropped
        (do
          (.increment ^LongAdder (:dropped branch))
          (update-max! ^AtomicInteger
                       (:max-depth branch)
                       (:capacity branch)))

        :cancelled
        (.increment ^LongAdder (:cancelled branch))

        (throw (ex-info "unknown stream spike enqueue result"
                        {:result result
                         :branch (:id branch)}))))))

(defn- finish-runtime! [runtime reason error]
  (when error
    (reset! (:error runtime) error))
  (compare-and-set! (:stop-reason runtime) nil reason)
  (reset! (:state runtime) (if error :failed :closed))
  (reset! (:ended-at-ms runtime) (System/currentTimeMillis))
  (doseq [branch (vals (:branches runtime))]
    (when (branch-open? branch)
      (reset! (:source-ended? branch) true)
      (-close-buffer! (:buffer branch))))
  nil)

(defn- dispatch! [runtime]
  (try
    (let [reason
          (loop [remaining (seq (:source runtime))]
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
              (let [value (first remaining)]
                (.increment ^LongAdder (:source-received runtime))
                (doseq [branch (vals (:branches runtime))]
                  (deliver! runtime branch value))
                (recur (next remaining)))))]
      (finish-runtime! runtime reason nil))
    (catch Throwable error
      (finish-runtime! runtime :error error))))

(declare close-runtime!)
(declare branch-seq)
(declare reduce-branch)

(deftype ^:private FanoutHandle [runtime]
  Closeable
  (close [_]
    (close-runtime! runtime)))

(deftype ^:private BranchHandle [runtime branch]
  Seqable
  (seq [_]
    (branch-seq runtime branch))

  IReduceInit
  (reduce [_ rf init]
    (reduce-branch runtime branch rf init))

  Closeable
  (close [_]
    (close-branch-state! runtime branch :closed)))

(defn- fanout-runtime [value]
  (when-not (instance? FanoutHandle value)
    (throw (ex-info "not a stream spike fan-out handle"
                    {:value value})))
  (.-runtime ^FanoutHandle value))

(defn- claim-consumer! [branch]
  (when-not (compare-and-set! (:consumer-claimed? branch) false true)
    (throw (ex-info "stream spike branch may only be consumed once"
                    {:branch (:id branch)}))))

(defn- finish-branch-drain! [runtime branch]
  (if-let [source-error @(:error runtime)]
    (do
      (reset! (:error branch) source-error)
      (compare-and-set! (:state branch) :open :failed)
      (reset! (:stop-reason branch) :source-error)
      (throw (ex-info "stream spike source failed"
                      {:branch (:id branch)}
                      source-error)))
    (do
      (compare-and-set! (:state branch) :open :completed)
      (compare-and-set! (:stop-reason branch) nil :source-exhausted)
      nil)))

(defn- branch-seq [runtime branch]
  (claim-consumer! branch)
  (letfn [(drain []
            (lazy-seq
             (if-let [^Box boxed (-take! (:buffer branch))]
               (do
                 (.increment ^LongAdder (:delivered branch))
                 (cons (.-value boxed) (drain)))
               (do
                 (finish-branch-drain! runtime branch)
                 nil))))]
    (drain)))

(defn- fail-branch! [runtime branch error]
  (when (branch-open? branch)
    (reset! (:error branch) error)
    (close-branch-state! runtime branch :consumer-error))
  nil)

(defn- reduce-branch [runtime branch rf init]
  (claim-consumer! branch)
  (try
    (loop [acc init]
      (if-let [^Box boxed (-take! (:buffer branch))]
        (do
          (.increment ^LongAdder (:delivered branch))
          (let [next-acc (rf acc (.-value boxed))]
            (if (reduced? next-acc)
              (do
                (close-branch-state! runtime branch :reduced)
                @next-acc)
              (recur next-acc))))
        (do
          (finish-branch-drain! runtime branch)
          acc)))
    (catch Throwable error
      (fail-branch! runtime branch error)
      (throw error))))

(defn- close-runtime! [runtime]
  (when (compare-and-set! (:stop-reason runtime) nil :closed)
    (reset! (:state runtime) :stopping))
  (doseq [branch (vals (:branches runtime))]
    (close-branch-state! runtime branch :fanout-closed))
  (invoke-cancel! runtime)
  (when-let [dispatcher @(:dispatcher runtime)]
    (when (= ::timeout
             (deref dispatcher
                    (:close-timeout-ms runtime)
                    ::timeout))
      (let [error (ex-info "stream spike dispatcher did not stop"
                           {:timeout-ms (:close-timeout-ms runtime)})]
        (reset! (:error runtime) error)
        (reset! (:state runtime) :failed)
        (throw error))))
  nil)

(defn- validate-branches [branches]
  (when-not (and (map? branches) (seq branches))
    (throw (ex-info "stream spike requires a non-empty branch map"
                    {:branches branches})))
  (reduce-kv
   (fn [result id config]
     (when-not (keyword? id)
       (throw (ex-info "stream spike branch id must be a keyword"
                       {:branch id})))
     (let [capacity (or (:buffer-cap config) default-buffer-cap)
           mode (:buffer-mode config)]
       (when-not (and (integer? capacity)
                      (<= 1 (long capacity) Integer/MAX_VALUE))
         (throw (ex-info "stream spike :buffer-cap must be a positive integer"
                         {:branch id
                          :buffer-cap capacity})))
       (when-not (contains? #{:blocking :dropping} mode)
         (throw (ex-info
                 "stream spike :buffer-mode must be :blocking or :dropping"
                 {:branch id
                  :buffer-mode mode})))
       (assoc result id {:buffer-cap capacity
                         :buffer-mode mode})))
   {}
   branches))

(defn fan-out
  "Start an internal fan-out experiment.

  `backend` is `:jdk-array`, `:jdk-linked`, or `:core-async`.
  This function is not public Paclo API."
  ([source branches]
   (fan-out source branches {}))
  ([source branches {:keys [backend cancel! close-timeout-ms]
                     :or {backend :jdk-array
                          close-timeout-ms default-close-timeout-ms}}]
   (when-not (seqable? source)
     (throw (ex-info "stream spike source must be seqable"
                     {:source source})))
   (when-not (or (nil? cancel!) (ifn? cancel!))
     (throw (ex-info "stream spike :cancel! must be invokable"
                     {:cancel! cancel!})))
   (when-not (and (integer? close-timeout-ms)
                  (pos? (long close-timeout-ms)))
     (throw (ex-info "stream spike :close-timeout-ms must be positive"
                     {:close-timeout-ms close-timeout-ms})))
   (let [configs (validate-branches branches)
         runtime
         {:source source
          :backend backend
          :branches
          (reduce-kv
           (fn [result id config]
             (assoc result id (branch-state backend id config)))
           {}
           configs)
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
         handle (FanoutHandle. runtime)
         dispatcher (future (dispatch! runtime))]
     (reset! (:dispatcher runtime) dispatcher)
     handle)))

(defn branch
  "Return one internal Seqable/IReduceInit/Closeable branch handle."
  [fanout id]
  (let [runtime (fanout-runtime fanout)
        branch-state* (get (:branches runtime) id)]
    (when-not branch-state*
      (throw (ex-info "unknown stream spike branch"
                      {:branch id
                       :known-branches (set (keys (:branches runtime)))})))
    (when-not (compare-and-set! (:handle-claimed? branch-state*)
                                false
                                true)
      (throw (ex-info "stream spike branch handle may only be acquired once"
                      {:branch id})))
    (BranchHandle. runtime branch-state*)))

(defn- branch-snapshot [branch]
  {:state @(:state branch)
   :offered (.sum ^LongAdder (:offered branch))
   :enqueued (.sum ^LongAdder (:enqueued branch))
   :delivered (.sum ^LongAdder (:delivered branch))
   :dropped (.sum ^LongAdder (:dropped branch))
   :cancelled (.sum ^LongAdder (:cancelled branch))
   :abandoned (.sum ^LongAdder (:abandoned branch))
   :buffer {:mode (:mode branch)
            :capacity (:capacity branch)
            :depth (-depth (:buffer branch))
            :max-depth (.get ^AtomicInteger (:max-depth branch))
            :blocked-events (.sum ^LongAdder (:blocked-events branch))
            :blocked-ns (.sum ^LongAdder (:blocked-ns branch))}
   :stop-reason @(:stop-reason branch)
   :error (error-map @(:error branch))})

(defn stats
  "Return a data-only snapshot for the internal fan-out experiment."
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
  "Wait for the internal dispatcher. Returns true on completion."
  ([fanout]
   (await! fanout default-close-timeout-ms))
  ([fanout timeout-ms]
   (let [runtime (fanout-runtime fanout)]
     (if-let [dispatcher @(:dispatcher runtime)]
       (not= ::timeout (deref dispatcher timeout-ms ::timeout))
       true))))
