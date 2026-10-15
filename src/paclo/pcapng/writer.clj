(ns paclo.pcapng.writer
  "Internal bounded encoder and exclusive atomic path publication."
  (:require
   [clojure.java.io :as io]
   [paclo.pcapng.cursor :as cursor])
  (:import
   [java.io OutputStream]
   [java.nio ByteBuffer ByteOrder]
   [java.nio.file
    FileSystems
    Files
    LinkOption
    Path
    StandardOpenOption]
   [java.nio.file.attribute FileAttribute]
   [java.util Arrays]
   [jnr.ffi LibraryLoader]))

;; Both primitives atomically fail if the destination exists, including a symlink.
;; No existence-check/ordinary-rename fallback is safe under concurrent creation.
(definterface ExclusiveRename
  (^int renameat2 [^int olddir ^String oldpath ^int newdir ^String newpath ^int flags])
  (^int renamex_np [^String oldpath ^String newpath ^int flags]))

(def ^:dynamic *source-terminal!*
  "Internal terminal observer, bound only during synchronous output reduction."
  nil)

(def ^:private libc (delay (.load (LibraryLoader/create ExclusiveRename) "c")))

(defn- fail! [state reason data]
  (throw (ex-info (str "PCAPNG " (name reason))
                  (merge (select-keys state [:file-offset :block-index :section-id])
                         {:phase :pcapng-write :reason reason :output-status :not-published} data))))

(defn- publish! [^Path temp ^Path destination]
  (when-not (and (= (FileSystems/getDefault) (.getFileSystem destination))
                 (= (.getFileSystem destination) (.getFileSystem temp)))
    (fail! {} :atomic-publication-unsupported {}))
  (let [^ExclusiveRename lib @libc
        rc (case (System/getProperty "os.name")
             "Linux" (.renameat2 lib -100 (str temp) -100 (str destination) 1)
             "Mac OS X" (.renamex_np lib (str temp) (str destination) 4)
             (fail! {} :atomic-publication-unsupported {}))]
    (when-not (zero? rc)
      (fail! {} :atomic-publication-failed {:errno (.getLastError (jnr.ffi.Runtime/getRuntime lib))}))))

(defn- padded [n] (*' 4 (quot (+' n 3) 4)))
(defn- order ^ByteOrder [v]
  (case v
    :little-endian ByteOrder/LITTLE_ENDIAN
    :big-endian ByteOrder/BIG_ENDIAN
    (fail! {} :invalid-byte-order {})))
(defn- uint! [state field value max-value]
  (when-not (and (integer? value) (<= 0 value max-value))
    (fail! state :invalid-field {:field field})))
(defn- limit! [opts state field n]
  (when (> n (get opts field))
    (fail! state :limit-exceeded {:field field :actual n :limit (get opts field)})))
(defn- octets! [state value]
  (when-not (bytes? value) (fail! state :missing-metadata {:field :octets})))
(defn- required! [state value fields]
  (when-not (and (map? value) (every? #(contains? value %) fields))
    (fail! state :missing-metadata {})))

(defn- option-size [state opts options]
  (when-not (vector? options) (fail! state :missing-metadata {:field :options}))
  (limit! opts state :max-options-per-block (count options))
  (reduce (fn [n {:keys [code value]}]
            (uint! state :option-code code 65535)
            (when (zero? code) (fail! state :invalid-option-length {:field :end-of-options}))
            (octets! state value)
            (uint! state :option-length (alength ^bytes value) 65535)
            (let [n (+' n 4 (padded (alength ^bytes value)))]
              (limit! opts state :max-options-bytes n)
              n))
          0 options))

(defn- put-options! [^ByteBuffer b options]
  (doseq [{:keys [code value]} options]
    (.putShort b (unchecked-short code))
    (.putShort b (unchecked-short (alength ^bytes value)))
    (.put b ^bytes value)
    (.position b (int (+ (.position b) (- (padded (alength ^bytes value)) (alength ^bytes value)))))))

(defn- ticks! [state opts packet interface]
  (let [ng (:pcapng packet)
        exact? (contains? ng :timestamp)
        pair? (and (contains? packet :ts-sec) (contains? packet :ts-usec))
        partial? (not= (contains? packet :ts-sec) (contains? packet :ts-usec))
        resolution (:timestamp-resolution interface)
        offset (:timestamp-offset-sec interface)
        ticks (if exact?
                (get-in ng [:timestamp :ticks])
                (when (and (= :author (:mode opts)) pair?)
                  (let [sec (:ts-sec packet) usec (:ts-usec packet)]
                    (when-not (and (integer? sec) (integer? usec) (<= 0 usec 999999))
                      (fail! state :invalid-timestamp {}))
                    (/ (*' (+' (*' (-' sec offset) 1000000) usec)
                           (reduce *' 1N (repeat (:exponent resolution) (:base resolution))))
                       1000000))))]
    (when partial? (fail! state :invalid-timestamp {}))
    (uint! state :timestamp-ticks ticks 18446744073709551615N)
    (when (and pair? (not= (select-keys packet [:ts-sec :ts-usec])
                           (cursor/projection ticks resolution offset)))
      (fail! state :timestamp-conflict {}))
    ticks))

(defn- encode [state opts event]
  (let [kind (:type event)
        section? (= kind :section)
        descriptor (:section event)
        sid (if section? (:id descriptor) (:section-id state))
        byte-order (if section? (:byte-order descriptor) (:byte-order state))]
    (when-not (= sid (:section-id event)) (fail! state :invalid-section-id {}))
    (when (and (not section?) (neg? (:section-id state))) (fail! state :missing-section {}))
    (let [interface (:interface event)
          packet (:packet event)
          ng (:pcapng packet)
          opaque (:block event)
          options (case kind :section (:options descriptor) :interface (:options interface)
                        :packet (:options ng) :opaque-block []
                        (fail! state :missing-metadata {}))
          option-bytes (option-size state opts options)
          simple? (= :simple-packet (:block-type ng))
          [type fixed payload] (case kind
                                 :section [0x0a0d0d0a 16 nil]
                                 :interface [1 8 nil]
                                 :packet [(if simple? 3 6) (if simple? 4 20) (:bytes packet)]
                                 :opaque-block [(:block-type opaque) 0 (:body opaque)])
          payload-size (if payload (do (octets! state payload) (alength ^bytes payload)) 0)
          total (+' 12 fixed (padded payload-size) option-bytes)]
      (when (#{:packet :opaque-block} kind)
        (octets! state payload)
        (limit! opts state (if (= kind :packet) :max-packet-bytes :max-opaque-block-bytes) payload-size))
      (limit! opts state :max-block-bytes total)
      (when (= kind :interface)
        (limit! opts state :max-interfaces-per-section (inc (count (:interfaces state)))))
      (when (#{:section :interface} kind)
        (limit! opts state :max-section-metadata-bytes
                (+' (if section? 0 (:metadata-bytes state)) 256 option-bytes (*' 32 (count options)))))
      (let [b (.order (ByteBuffer/allocate (int total)) (order byte-order))]
        (.putInt b (unchecked-int type))
        (.putInt b (int total))
        (case kind
          :section
          (do
            (required! state descriptor [:id :byte-order :version :section-length :options])
            (when-not (= sid (inc' (:section-id state))) (fail! state :invalid-section-id {}))
            (when-not (= [1 0] (:version descriptor)) (fail! state :unsupported-section-version {}))
            (when-let [n (:section-length descriptor)] (uint! state :section-length n Long/MAX_VALUE))
            (.putInt b 0x1a2b3c4d) (.putShort b (short 1)) (.putShort b (short 0)) (.putLong b -1))
          :interface
          (do
            (required! state interface [:id :section-id :file-linktype :linktype :snaplen
                                        :timestamp-resolution :timestamp-offset-sec :options])
            (when-not (and (= (:id interface) (count (:interfaces state))) (= sid (:section-id interface)))
              (fail! state :invalid-interface-id {}))
            (uint! state :file-linktype (:file-linktype interface) 65535)
            (uint! state :snaplen (:snaplen interface) 4294967295)
            (.putShort b (unchecked-short (:file-linktype interface))) (.putShort b (short 0))
            (.putInt b (unchecked-int (:snaplen interface))))
          :packet
          (let [_ (required! state packet [:bytes :caplen :len :linktype :pcapng])
                id (:interface-id ng)
                _ (uint! state :interface-id id 4294967295)
                iface (or (get (:interfaces state) id) (fail! state :undefined-interface {:interface-id id}))]
            (required! state ng [:section-id :interface-id :block-type :options])
            (when-not (and (= sid (:section-id ng)) (= (:linktype iface) (:linktype packet)))
              (fail! state :descriptor-conflict {}))
            (when-not (#{:simple-packet :enhanced-packet} (:block-type ng))
              (fail! state :unsupported-packet-block {}))
            (uint! state :wire-length (:len packet) 4294967295)
            (when-not (= payload-size (:caplen packet)) (fail! state :invalid-packet-length {}))
            (if simple?
              (do
                (when-not (and (zero? id) (contains? ng :timestamp) (nil? (:timestamp ng))
                               (empty? options) (not (contains? packet :ts-sec)) (not (contains? packet :ts-usec)))
                  (fail! state :invalid-timestamp-absence {}))
                (.putInt b (unchecked-int (:len packet))))
              (let [ticks (ticks! state opts packet iface)]
                (.putInt b (unchecked-int id))
                (.putInt b (unchecked-int (quot ticks 4294967296N)))
                (.putInt b (unchecked-int (rem ticks 4294967296N)))
                (.putInt b (int payload-size)) (.putInt b (unchecked-int (:len packet))))))
          :opaque-block
          (do
            (required! state opaque [:block-type :body :byte-order :copy-policy])
            (uint! state :block-type type 4294967295)
            (when (#{0x0a0d0d0a 1 2 3 6 10} type) (fail! state :unsupported-opaque-block {}))
            (when-not (and (= byte-order (:byte-order opaque)) (zero? (mod payload-size 4)))
              (fail! state :opaque-context-changed {}))))
        (when payload
          (.put b ^bytes payload)
          (.position b (int (+ (.position b) (- (padded payload-size) payload-size)))))
        (put-options! b options)
        (.putInt b (int total))
        ;; Apply the same format/option rules as the reader, before any output write.
        ;; This also checks SPB inferred caplen, singleton options and descriptor caches.
        (let [body (ByteBuffer/wrap (Arrays/copyOfRange (.array b) 8 (- (int total) 4)))
              _ (.order body (order byte-order))
              [next-state decoded] (try (cursor/accept-body state body opts type byte-order total)
                                        (catch clojure.lang.ExceptionInfo e
                                          (throw (ex-info (.getMessage e)
                                                          (assoc (ex-data e) :phase :pcapng-write
                                                                 :output-status :not-published) e))))]
          (when (= kind :interface)
            (when-not (= (select-keys interface [:id :section-id :file-linktype :linktype :snaplen :timestamp-resolution :timestamp-offset-sec])
                         (dissoc (:interface decoded) :options))
              (fail! state :descriptor-conflict {})))
          (when (and (= kind :opaque-block)
                     (not= (:copy-policy opaque)
                           (cond (= type 0x40000bad) :never
                                 (#{4 5 0x00000bad} type) :copyable
                                 :else :unknown)))
            (fail! state :descriptor-conflict {}))
          [next-state (.array b)])))))

(defn- known-option? [kind code]
  (or (= code 1) (#{2988 2989 19372 19373} code)
      (case kind :section (<= 2 code 4) :interface (<= 2 code 18) :packet (<= 2 code 8) false)))

(defn- loss-event [state opts event losses]
  (let [kind (:type event) drops (:drop opts) changed? (:context-changed? opts)
        path (case kind :section [:section :options] :interface [:interface :options]
                   :packet [:packet :pcapng :options] nil)
        count-loss! (fn [reason] (vswap! losses update reason (fnil inc' 0)))
        drop-option (fn [{:keys [code]}]
                      (cond
                        (and (= code 1) (contains? drops :comments)) :comments
                        (and (#{19372 19373} code) (contains? drops :noncopyable-options)) :noncopyable-options
                        (and (not (known-option? kind code)) (contains? drops :unknown-options)) :unknown-options
                        (and (#{2988 2989} code) (contains? drops :custom-options)) :custom-options))]
    (if (= kind :opaque-block)
      (let [type (get-in event [:block :block-type])]
        (cond
          (contains? drops :opaque-blocks) (do (count-loss! :opaque-blocks) nil)
          (= type 0x40000bad) (fail! state :noncopyable-data {})
          changed? (fail! state :opaque-context-changed {})
          :else event))
      (update-in event path
                 (fn [options]
                   (into [] (keep (fn [{:keys [code] :as option}]
                                    (if-let [reason (drop-option option)]
                                      (do (count-loss! reason) nil)
                                      (do
                                        (when (#{19372 19373} code) (fail! state :noncopyable-data {}))
                                        (when (and changed? (or (not (known-option? kind code))
                                                                (#{2988 2989} code)))
                                          (fail! state :opaque-context-changed {}))
                                        option)))) options))))))

(defn- validate-options [opts]
  (when-not (map? opts) (fail! {} :invalid-writer-options {}))
  (when (contains? opts :path) (fail! {} :invalid-writer-options {:field :unknown-option}))
  (let [mode (get opts :mode :preserve) drops (get opts :drop #{})
        extra (apply dissoc opts [:mode :drop :context-changed?])]
    (when-not (and (#{:preserve :lossy :author} mode) (set? drops)
                   (every? #{:comments :unknown-options :noncopyable-options :custom-options :opaque-blocks} drops)
                   (or (= mode :lossy) (empty? drops))
                   (or (not (contains? opts :context-changed?)) (boolean? (:context-changed? opts)))
                   (not (and (= mode :preserve) (:context-changed? opts))))
      (fail! {} :invalid-writer-options {}))
    (try
      (merge (dissoc (cursor/validate-options (assoc extra :path :unused)) :path)
             {:mode mode :drop drops :context-changed? (get opts :context-changed? false)})
      (catch clojure.lang.ExceptionInfo e (fail! {} :invalid-writer-options (select-keys (ex-data e) [:field :limit]))))))

(defn- open-output! [^Path path]
  (Files/newOutputStream path (into-array StandardOpenOption [StandardOpenOption/WRITE])))
(defn- write-block! [^OutputStream out ^bytes bytes] (.write out bytes))
(defn- flush-output! [^OutputStream out] (.flush out))
(defn- close-output! [^OutputStream out] (.close out))
(defn- cleanup! [^Path path] (Files/deleteIfExists path))

(defn write!
  [events path opts terminal-info]
  (let [opts (validate-options opts)
        ^Path destination (.toAbsolutePath ^Path (if (instance? Path path) path (.toPath (io/file path))))
        _ (when (Files/exists destination (into-array LinkOption [LinkOption/NOFOLLOW_LINKS]))
            (fail! {} :destination-exists {}))
        temp (Files/createTempFile (.getParent destination) ".paclo-pcapng-" ".tmp" (make-array FileAttribute 0))
        primary (volatile! nil) state (volatile! (cursor/initial-state)) losses (volatile! {})]
    (try
      (let [out (open-output! temp)]
        (try
          (binding [*source-terminal!* (fn [terminal]
                                         (when (and (not= :eof terminal)
                                                    (not (and (= :reduced terminal) (#{:lossy :author} (:mode opts))
                                                              (:context-changed? opts))))
                                           (fail! @state :incomplete-source {})))]
            (reduce (fn [_ event]
                      (let [encoded (encode @state opts event)
                            retained (loss-event @state opts event losses)]
                        (when retained
                          (let [[next-state bytes] (if (= retained event) encoded (encode @state opts retained))]
                            (write-block! out bytes)
                            (vreset! state next-state))))
                      nil) nil events))
          (when (neg? (:section-id @state)) (fail! @state :missing-section {}))
          (when (and terminal-info (not= :eof (:terminal (terminal-info))))
            (fail! @state :incomplete-source {}))
          (flush-output! out)
          (catch Throwable error (vreset! primary error) (throw error))
          (finally
            (try (close-output! out)
                 (catch Throwable close-error
                   (if-let [^Throwable error @primary]
                     (when-not (identical? error close-error) (.addSuppressed error close-error))
                     (throw close-error)))))))
      (publish! temp destination)
      {:status :complete :fidelity (case (:mode opts) :preserve :known-semantics :lossy :explicit-loss :author :authored)
       :loss-counts (cond-> @losses (:context-changed? opts) (assoc :context-changed 1))
       :blocks-written (:block-index @state) :bytes-written (:file-offset @state)}
      (catch Throwable error
        (vreset! primary error)
        (.addSuppressed error (ex-info "PCAPNG output was not published"
                                       (merge (select-keys @state [:block-index :file-offset :section-id])
                                              {:phase :pcapng-write :output-status :not-published :temp-path (str temp)})))
        (throw error))
      (finally
        (when-let [^Throwable error @primary]
          (try (cleanup! temp)
               (catch Throwable cleanup-error
                 (.addSuppressed error (ex-info "PCAPNG temporary file cleanup failed"
                                                {:temp-path (str temp) :phase :pcapng-cleanup} cleanup-error)))))))))
