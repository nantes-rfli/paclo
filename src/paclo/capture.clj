(ns paclo.capture
  "Internal managed capture implementation.

  This namespace owns the mutable boundary around a libpcap handle. Public
  callers use the data-first facade in `paclo.core`."
  (:require
   [clojure.java.io :as io]
   [clojure.string :as str]
   [paclo.pcap :as pcap])
  (:import
   [java.io Closeable]
   [java.util.concurrent LinkedBlockingQueue TimeUnit]
   [java.util.concurrent.atomic AtomicInteger LongAdder]))

(def ^:private default-max 100)
(def ^:private default-max-time-ms 10000)
(def ^:private default-idle-max-ms 3000)
(def ^:private default-queue-cap 1024)
(def ^:private poll-ms 25)
(def ^:private close-timeout-ms 5000)
(def ^:private terminal-states #{:closed :failed})

(defn- non-blank-string? [value]
  (and (string? value) (not (str/blank? value))))

(defn- valid-path? [path]
  (or (non-blank-string? path)
      (and (instance? java.io.File path)
           (non-blank-string? (.getPath ^java.io.File path)))))

(defn- positive-integer? [value]
  (and (integer? value) (pos? (long value))))

(defn- validate-opts
  [{:keys [device path queue-cap queue-mode max max-time-ms idle-max-ms
           error-mode stop?]
    :as opts}]
  (when (and device path)
    (throw (ex-info "start-capture takes either :device or :path, not both"
                    {:device device :path path})))
  (when-not (or (non-blank-string? device) (valid-path? path))
    (throw (ex-info "start-capture requires either :device or :path"
                    {:device device :path path})))
  (when-not (contains? #{:blocking :dropping} queue-mode)
    (throw (ex-info ":queue-mode must be :blocking or :dropping"
                    {:queue-mode queue-mode})))
  (when-not (and (integer? queue-cap)
                 (<= 1 (long queue-cap) Integer/MAX_VALUE))
    (throw (ex-info ":queue-cap must be an integer between 1 and 2147483647"
                    {:queue-cap queue-cap})))
  (when-not (positive-integer? max)
    (throw (ex-info ":max must be a positive integer" {:max max})))
  (when-not (positive-integer? max-time-ms)
    (throw (ex-info ":max-time-ms must be a positive integer"
                    {:max-time-ms max-time-ms})))
  (when-not (positive-integer? idle-max-ms)
    (throw (ex-info ":idle-max-ms must be a positive integer"
                    {:idle-max-ms idle-max-ms})))
  (when-not (contains? #{:throw :pass} error-mode)
    (throw (ex-info ":error-mode must be :throw or :pass"
                    {:error-mode error-mode})))
  (when-not (or (nil? stop?) (ifn? stop?))
    (throw (ex-info ":stop? must be invokable" {:stop? stop?})))
  opts)

(defn- source-map [{:keys [device path]}]
  (if device
    {:type :device :name device}
    {:type :path
     :path (.getAbsolutePath (io/file path))}))

(defn- error-map [^Throwable error]
  {:class (.getName (class error))
   :message (or (.getMessage error) (str error))})

(defn- update-max-depth! [^AtomicInteger maximum ^long depth]
  (loop [observed (.get maximum)]
    (when (and (< observed depth)
               (not (.compareAndSet maximum observed (int depth))))
      (recur (.get maximum)))))

(defprotocol ^:private SessionOps
  (-packet-seq [capture])
  (-request-stop! [capture reason])
  (-snapshot [capture])
  (-await-close! [capture]))

(deftype ^:private ManagedCapture
         [handle
          opts
          ^LinkedBlockingQueue queue
          state
          stop-reason
          failure
          pcap-final
          ended-at-ms
          producer
          stream-taken?
          handle-closed?
          ^LongAdder captured
          ^LongAdder enqueued
          ^LongAdder delivered
          ^LongAdder dropped
          ^LongAdder blocked-events
          ^LongAdder blocked-ns
          ^AtomicInteger max-depth
          ^long started-at-ms]

  SessionOps
  (-packet-seq [_]
    (when-not (compare-and-set! stream-taken? false true)
      (throw (ex-info "capture packet stream may only be acquired once"
                      {:reason :stream-already-acquired})))
    (letfn [(drain []
              (lazy-seq
               (if-let [packet (.poll queue (long 100) TimeUnit/MILLISECONDS)]
                 (do
                   (.increment delivered)
                   (cons packet (drain)))
                 (if (contains? terminal-states @state)
                   (if-let [error @failure]
                     (if (= :pass (:error-mode opts))
                       '()
                       (throw
                        (ex-info "managed capture background error"
                                 {:source :managed-capture}
                                 error)))
                     '())
                   (drain)))))]
      (drain)))

  (-request-stop! [_ reason]
    (when (compare-and-set! stop-reason nil reason)
      (swap! state #(if (= :running %) :stopping %)))
    (when-not @handle-closed?
      (try
        (pcap/breakloop! handle)
        (catch Throwable error
          (when-let [on-error (:on-error opts)]
            (try (on-error error) (catch Throwable _))))))
    nil)

  (-snapshot [_]
    (let [now (long (or @ended-at-ms (System/currentTimeMillis)))]
      {:schema-version 1
       :state @state
       :source (source-map opts)
       :timing {:started-at-ms started-at-ms
                :elapsed-ms (max 0 (- now started-at-ms))}
       :packets {:captured (.sum captured)
                 :enqueued (.sum enqueued)
                 :delivered (.sum delivered)}
       :queue {:mode (:queue-mode opts)
               :capacity (:queue-cap opts)
               :depth (.size queue)
               :max-depth (.get max-depth)
               :enqueued (.sum enqueued)
               :dropped (.sum dropped)
               :blocked-events (.sum blocked-events)
               :blocked-ns (.sum blocked-ns)}
       :pcap @pcap-final
       :stop-reason @stop-reason
       :error (some-> @failure error-map)}))

  (-await-close! [this]
    (-request-stop! this :closed)
    ;; An explicit close abandons any queued values and lets a blocked producer
    ;; observe the stop request without waiting for the consumer.
    (.clear queue)
    (when-let [running @producer]
      (when (= ::timeout (deref running close-timeout-ms ::timeout))
        (let [error (ex-info "managed capture did not stop before close timeout"
                             {:timeout-ms close-timeout-ms})]
          (reset! failure error)
          (reset! state :failed)
          (throw error))))
    nil)

  Closeable
  (close [this]
    (-await-close! this)))

(defn- open-handle [{:keys [device path] :as opts}]
  (if device
    (pcap/open-live opts)
    (pcap/open-offline path (select-keys opts [:filter]))))

(defn- queue-snapshot
  [^ManagedCapture capture]
  (:queue (-snapshot capture)))

(defn- close-handle-once!
  [^ManagedCapture capture]
  (when (compare-and-set! (.-handle-closed? capture) false true)
    (pcap/close! (.-handle capture))))

(defn- enqueue!
  [^ManagedCapture capture packet]
  (let [^LinkedBlockingQueue queue (.-queue capture)
        opts (.-opts capture)
        ^LongAdder enqueued (.-enqueued capture)
        ^LongAdder dropped (.-dropped capture)
        ^LongAdder blocked-events (.-blocked-events capture)
        ^LongAdder blocked-ns (.-blocked-ns capture)
        ^AtomicInteger max-depth (.-max-depth capture)]
    (case (:queue-mode opts)
      :dropping
      (if (.offer queue packet)
        (do
          (.increment enqueued)
          (update-max-depth! max-depth (max 1 (.size queue)))
          true)
        (do
          (.increment dropped)
          (update-max-depth! max-depth (:queue-cap opts))
          false))

      :blocking
      (if (.offer queue packet)
        (do
          (.increment enqueued)
          (update-max-depth! max-depth (max 1 (.size queue)))
          true)
        (let [started (System/nanoTime)]
          (.increment blocked-events)
          (update-max-depth! max-depth (:queue-cap opts))
          (loop []
            (cond
              (some? @(.-stop-reason capture))
              (do
                (.add blocked-ns (- (System/nanoTime) started))
                false)

              (.offer queue packet poll-ms TimeUnit/MILLISECONDS)
              (do
                (.add blocked-ns (- (System/nanoTime) started))
                (.increment enqueued)
                (update-max-depth! max-depth (max 1 (.size queue)))
                true)

              :else
              (recur))))))))

(defn- final-stop-reason
  [^ManagedCapture capture packet-count]
  (or @(.-stop-reason capture)
      (when (>= (long packet-count) (long (:max (.-opts capture))))
        :max-packets)
      (when (>= (- (System/currentTimeMillis)
                   (long (.-started-at-ms capture)))
                (long (:max-time-ms (.-opts capture))))
        :max-time)
      (if (:device (.-opts capture)) :idle-timeout :eof)))

(defn- finish!
  [^ManagedCapture capture]
  (let [opts (.-opts capture)
        live? (some? (:device opts))
        pcap-stats
        (when live?
          (try
            (pcap/capture-stats (.-handle capture))
            (catch Throwable error
              (when-let [on-error (:on-error opts)]
                (try (on-error error) (catch Throwable _)))
              nil)))]
    (when (and live? (:on-stats opts) pcap-stats)
      (try
        ((:on-stats opts) pcap-stats)
        (catch Throwable error
          (when-let [on-error (:on-error opts)]
            (try (on-error error) (catch Throwable _))))))
    (when-let [on-queue-stats (:on-queue-stats opts)]
      (try
        (on-queue-stats (queue-snapshot capture))
        (catch Throwable error
          (when-let [on-error (:on-error opts)]
            (try (on-error error) (catch Throwable _))))))
    (reset! (.-pcap-final capture) pcap-stats)
    (close-handle-once! capture)
    (compare-and-set! (.-ended-at-ms capture)
                      nil
                      (System/currentTimeMillis))))

(defn start
  "Start one managed capture and return an opaque Closeable handle."
  [opts]
  (let [opts* (-> (merge {:snaplen 65536
                          :promiscuous? true
                          :timeout-ms 10
                          :error-mode :throw
                          :queue-mode :blocking
                          :queue-cap default-queue-cap
                          :max default-max
                          :max-time-ms default-max-time-ms
                          :idle-max-ms default-idle-max-ms}
                         opts)
                  (update :queue-cap #(or % default-queue-cap))
                  (update :max #(or % default-max))
                  (update :max-time-ms #(or % default-max-time-ms))
                  (update :idle-max-ms #(or % default-idle-max-ms))
                  validate-opts)
        handle (open-handle opts*)
        queue (LinkedBlockingQueue. (int (:queue-cap opts*)))
        capture
        (ManagedCapture.
         handle opts* queue
         (atom :starting)
         (atom nil)
         (atom nil)
         (atom nil)
         (atom nil)
         (atom nil)
         (atom false)
         (atom false)
         (LongAdder.)
         (LongAdder.)
         (LongAdder.)
         (LongAdder.)
         (LongAdder.)
         (LongAdder.)
         (AtomicInteger.)
         (System/currentTimeMillis))]
    (try
      (when-let [on-ready (:on-ready opts*)]
        (on-ready))
      (reset! (.-state capture) :running)
      (let [running
            (future
              (try
                (pcap/loop-n-or-ms!
                 handle
                 {:n (:max opts*)
                  :ms (:max-time-ms opts*)
                  :idle-max-ms (:idle-max-ms opts*)
                  :timeout-ms (:timeout-ms opts*)
                  :stop?
                  (fn [packet]
                    (cond
                      (some? @(.-stop-reason capture)) true
                      (and (:stop? opts*) ((:stop? opts*) packet))
                      (do
                        (compare-and-set! (.-stop-reason capture)
                                          nil
                                          :predicate)
                        true)
                      :else false))}
                 (fn [packet]
                   (.increment ^LongAdder (.-captured capture))
                   (enqueue! capture packet)))
                (compare-and-set! (.-stop-reason capture)
                                  nil
                                  (final-stop-reason
                                   capture
                                   (.sum ^LongAdder (.-captured capture))))
                (catch Throwable error
                  (reset! (.-failure capture) error)
                  (reset! (.-stop-reason capture) :error)
                  (when-let [on-error (:on-error opts*)]
                    (try (on-error error) (catch Throwable _))))
                (finally
                  (try
                    (finish! capture)
                    (catch Throwable error
                      (when-not @(.-failure capture)
                        (reset! (.-failure capture) error)
                        (reset! (.-stop-reason capture) :error)))
                    (finally
                      (reset! (.-state capture)
                              (if @(.-failure capture)
                                :failed
                                :closed)))))))]
        (reset! (.-producer capture) running)
        capture)
      (catch Throwable error
        (try
          (close-handle-once! capture)
          (catch Throwable _))
        (throw error)))))

(defn packet-seq
  "Return the single-consumer packet sequence for a managed capture."
  [capture]
  (if (satisfies? SessionOps capture)
    (-packet-seq capture)
    (throw (ex-info "not a managed capture" {:capture capture}))))

(defn stop!
  "Request asynchronous, idempotent capture termination."
  [capture]
  (if (satisfies? SessionOps capture)
    (-request-stop! capture :consumer)
    (throw (ex-info "not a managed capture" {:capture capture}))))

(defn stats
  "Return a data-only snapshot for a managed capture."
  [capture]
  (if (satisfies? SessionOps capture)
    (-snapshot capture)
    (throw (ex-info "not a managed capture" {:capture capture}))))
