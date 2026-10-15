(ns paclo.pcapng
  "Bounded synchronous PCAPNG event sources with exact timestamp metadata.

  Own sources with with-open. Reduce each source once; there is no sequence,
  producer thread, implicit reopen, BPF filter or live capture."
  (:require
   [clojure.java.io :as io]
   [paclo.pcapng.cursor :as cursor]
   [paclo.pcapng.writer :as writer])
  (:import
   [clojure.lang IReduceInit]
   [java.io Closeable]
   [java.nio.channels ClosedChannelException FileChannel]
   [java.nio.file OpenOption Path StandardOpenOption]))

(defn- close-channel! [^FileChannel channel] (.close channel))

(defn- release! [channel pending active]
  (reset! pending nil)
  (reset! active nil)
  (close-channel! channel))

(defn- error-data [error]
  ;; Arbitrary consumer ex-data/message may contain secrets or retained arrays.
  (if (and (instance? clojure.lang.ExceptionInfo error)
           (= :pcapng-read (:phase (ex-data error))))
    (into {} (filter (fn [[_ value]] (or (and (keyword? value) (<= (count (str value)) 128))
                                         (and (integer? value)
                                              (<= -18446744073709551616N value 18446744073709551616N)))))
          (select-keys (ex-data error) [:phase :reason :file-offset :block-index :section-id
                                        :interface-id :block-type :field :expected :actual :limit]))
    {:reason :consumer-or-io-error :exception-class (.getName (class error))}))

(defn- snapshot-cursor [active]
  {:blocks-read (:block-index active) :bytes-read (:file-offset active)
   :active-interfaces (count (:interfaces active)) :active-metadata-bytes (:metadata-bytes active)})

(defn- claim-delivery! [status event]
  (locking status
    (when (= :reading (:state @status))
      (swap! status (fn [s]
                      (cond-> (update s :events inc')
                        (= :packet (:type event)) (update :packets inc')
                        (= :opaque-block (:type event)) (update :opaque-blocks inc'))))
      true)))

(defn- pull! [channel active opts status]
  (when-let [current @active]
    (when (= :reading (:state @status))
      (try
        (when-let [[next-state event] (cursor/next-block! channel current opts)]
          (locking status
            (when (= :reading (:state @status))
              (reset! active next-state)
              (swap! status merge (snapshot-cursor next-state))))
          event)
        (catch ClosedChannelException e
          (when-not (= :closed (:terminal @status)) (throw e)))))))

(defn- consume! [channel pending active opts status rf init]
  (locking status
    (when (:consumed? @status)
      (cursor/fail! {} :source-consumed {}))
    (when-not (= :open (:state @status))
      (cursor/fail! {} :source-closed {}))
    (swap! status assoc :consumed? true :state :reading))
  (let [primary (volatile! nil)]
    (try
      (loop [acc init event (let [event @pending] (reset! pending nil) event)]
        (if (and event (claim-delivery! status event))
          (let [next-acc (rf acc event)]
            (if (reduced? next-acc)
              (do
                (locking status
                  (when (= :reading (:state @status))
                    (swap! status assoc :state :closed :terminal :reduced)))
                @next-acc)
              (recur next-acc (pull! channel active opts status))))
          (do
            (locking status
              (when (= :reading (:state @status))
                (swap! status assoc :state :closed :terminal :eof)))
            acc)))
      (catch Throwable error
        (vreset! primary error)
        (locking status
          (swap! status assoc :state :failed :terminal :error :error (error-data error)))
        (throw error))
      (finally
        (try
          (release! channel pending active)
          (catch Throwable close-error
            (if-let [^Throwable error @primary]
              (when-not (identical? error close-error) (.addSuppressed error close-error))
              (do
                (locking status
                  (swap! status assoc :state :failed :terminal :error :error (error-data close-error)))
                (vreset! primary close-error)
                (throw close-error))))
          (finally
            (locking status
              (swap! status assoc :active-interfaces 0 :active-metadata-bytes 0))
            (when (and writer/*source-terminal!* (nil? @primary))
              (writer/*source-terminal!* (:terminal @status)))))))))

(deftype ^:private Source [channel pending active opts status]
  Closeable
  (close [_]
    (let [close? (locking status
                   (when (#{:open :reading} (:state @status))
                     (swap! status assoc :state :closed :terminal :closed)
                     true))]
      (when close?
        ;; Do not wait for a claimed consumer call. Channel close interrupts I/O.
        (reset! pending nil)
        (reset! active nil)
        (try
          (close-channel! channel)
          (catch Throwable error
            (locking status
              (swap! status assoc :state :failed :terminal :error :error (error-data error)))
            (throw error))
          (finally
            (locking status
              (swap! status assoc :active-interfaces 0 :active-metadata-bytes 0)))))))
  IReduceInit
  (reduce [_ rf init] (consume! channel pending active opts status rf init)))

(defn open-source
  "Open a single-use Closeable IReduceInit source from {:path file-or-path}.

  Reads only the first bounded Section Header Block before returning. Reduction
  emits ordered :section, :interface, :packet and :opaque-block event maps and
  closes on EOF, reduced, consumer exception or parse/I/O failure. External close
  cancels further delivery; an already claimed consumer call may finish.

  Optional positive ceilings: :max-block-bytes (16 MiB), :max-packet-bytes
  (8 MiB), :max-options-bytes (1 MiB), :max-options-per-block (4096),
  :max-interfaces-per-section (4096), :max-section-metadata-bytes (8 MiB),
  :max-opaque-block-bytes (1 MiB). No unlimited/nil setting. Unknown options fail
  before opening. See docs/pcapng.md for event, timestamp and failure contracts."
  [opts]
  (let [opts (cursor/validate-options opts)
        path (if (instance? Path (:path opts)) (:path opts) (.toPath (io/file (:path opts))))
        channel (FileChannel/open path (into-array OpenOption [StandardOpenOption/READ]))]
    (try
      (let [[active first-event] (cursor/next-block! channel (cursor/initial-state) opts)
            status (atom (merge {:state :open :terminal nil :consumed? false :error nil
                                 :events 0 :packets 0 :opaque-blocks 0}
                                (snapshot-cursor active)))]
        (Source. channel (atom first-event) (atom active) opts status))
      (catch Throwable error
        (try (close-channel! channel)
             (catch Throwable close-error
               (when-not (identical? error close-error) (.addSuppressed error close-error))))
        (throw error)))))

(defn source-info
  "Return a bounded data-only source snapshot, without packet/descriptor arrays.

  :state is :open/:reading/:closed/:failed; terminal is nil or
  :eof/:reduced/:closed/:error. Counts include delivered :events/:packets/
  :opaque-blocks and validated :blocks-read/:bytes-read. Active interface and
  metadata accounting become zero after cleanup. :error contains bounded data.
  A valid prefix or terminal :reduced does not validate the unread suffix."
  [source]
  (when-not (instance? Source source)
    (cursor/fail! {} :invalid-source {}))
  @(.-status ^Source source))

(defn write-pcapng!
  "Synchronously write ordered PCAPNG events to a new path, once.

  (write-pcapng! events path) defaults to :mode :preserve. Options accept
  :mode :preserve/:lossy/:author, :drop #{:comments :unknown-options
  :noncopyable-options :opaque-blocks} (lossy only), :context-changed? boolean,
  and the same positive resource ceilings as open-source.

  Exact ticks and descriptor options must agree with derived fields. Author
  mode alone permits exact integral conversion from a complete microsecond pair
  when :timestamp is absent. Explicit nil is timestamp absence (SPB only).
  Declare edits/subsets with :context-changed? true; opaque content then needs
  explicit drops. No inference of source fidelity or detection of hidden edits.

  Publishes a closed sibling temporary file with an exclusive atomic rename on
  Linux/macOS; existing paths and unsupported providers fail without fallback.
  Returns bounded status/fidelity/loss counts. Failure preserves the exception
  and adds output location/cleanup details as suppressed exceptions. Paclo
  sources own their close during reduction; other reducibles own upstream I/O.
  See docs/pcapng.md for the full policy and ownership contract."
  ([events path] (write-pcapng! events path {}))
  ([events path opts]
   (writer/write! events path opts
                  (when (instance? Source events) #(source-info events)))))
