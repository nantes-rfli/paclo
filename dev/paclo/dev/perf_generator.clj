(ns paclo.dev.perf-generator
  "Exact-count UDP generator for separate-host live-capture measurements."
  (:import
   [java.net DatagramPacket DatagramSocket InetAddress]
   [java.util.concurrent CountDownLatch TimeUnit]
   [java.util.concurrent.locks LockSupport]))

(defn- usage []
  (println "Usage:")
  (println "  clojure -M:perf-generator --host HOST --packets N --rate PPS")
  (println "       [--port 39053] [--frame-size 64] [--senders 1]")
  (println "       [--start-delay-ms 0]"))

(defn- parse-long!
  [value label]
  (try
    (Long/parseLong value)
    (catch Throwable cause
      (throw (ex-info (str label " must be an integer")
                      {:label label :value value}
                      cause)))))

(defn- parse-args
  [args]
  (loop [opts {:port 39053
               :frame-size 64
               :senders 1
               :start-delay-ms 0}
         remaining args]
    (if (empty? remaining)
      opts
      (let [[flag value & more] remaining]
        (case flag
          "--help" (assoc opts :help? true)
          "-h" (assoc opts :help? true)
          "--host" (recur (assoc opts :host value) more)
          "--packets" (recur (assoc opts :packets
                                    (parse-long! value "packets")) more)
          "--rate" (recur (assoc opts :rate
                                 (parse-long! value "rate")) more)
          "--port" (recur (assoc opts :port
                                 (parse-long! value "port")) more)
          "--frame-size" (recur (assoc opts :frame-size
                                       (parse-long! value "frame-size")) more)
          "--senders" (recur (assoc opts :senders
                                    (parse-long! value "senders")) more)
          "--start-delay-ms"
          (recur (assoc opts :start-delay-ms
                        (parse-long! value "start-delay-ms")) more)
          (throw (ex-info "unknown or incomplete argument"
                          {:remaining remaining})))))))

(defn- validate-opts!
  [{:keys [host packets rate port frame-size senders start-delay-ms]}]
  (when-not (and (string? host) (not (.isBlank ^String host)))
    (throw (ex-info "host is required" {:host host})))
  (doseq [[label value] [[:packets packets]
                         [:rate rate]
                         [:frame-size frame-size]
                         [:senders senders]]]
    (when-not (and value (pos? (long value)))
      (throw (ex-info (str (name label) " must be positive")
                      {label value}))))
  (when-not (<= 1 (long port) 65535)
    (throw (ex-info "port must be between 1 and 65535" {:port port})))
  (when (> (long senders) (long packets))
    (throw (ex-info "senders cannot exceed packets"
                    {:senders senders :packets packets})))
  (when (neg? (long start-delay-ms))
    (throw (ex-info "start-delay-ms cannot be negative"
                    {:start-delay-ms start-delay-ms}))))

(defn- split-counts
  [packets senders]
  (let [packets (long packets)
        senders (long senders)
        base (quot packets senders)
        remainder (mod packets senders)]
    (mapv #(+ base (if (< (long %) (long remainder)) 1 0))
          (range senders))))

(defn- send-count!
  [^DatagramSocket socket ^InetAddress address port payload-bytes packet-count
   sender-rate]
  (let [payload (byte-array (long payload-bytes))
        packet (DatagramPacket. payload (alength payload) address (int port))
        interval (/ 1.0e9 (double sender-rate))]
    (with-open [socket socket]
      (let [started (System/nanoTime)]
        (loop [sent 0]
          (if (= (long sent) (long packet-count))
            sent
            (do
              (.send socket packet)
              (let [sent' (unchecked-inc (long sent))
                    target (+ started (long (* sent' interval)))
                    remaining (- target (System/nanoTime))]
                (if (> remaining 50000)
                  (LockSupport/parkNanos remaining)
                  (while (< (System/nanoTime) target)
                    (Thread/onSpinWait)))
                (recur sent')))))))))

(defn- open-sockets
  [senders]
  (loop [remaining (long senders)
         sockets []]
    (if (zero? remaining)
      sockets
      (let [socket
            (try
              (DatagramSocket.)
              (catch Throwable cause
                (doseq [^DatagramSocket open-socket sockets]
                  (.close open-socket))
                (throw cause)))]
        (recur (dec remaining) (conj sockets socket))))))

(defn run-generator!
  [{:keys [host packets rate port frame-size senders start-delay-ms] :as opts}]
  (validate-opts! opts)
  (let [address (InetAddress/getByName host)
        counts (split-counts packets senders)
        sockets (open-sockets senders)
        ready (CountDownLatch. (int senders))
        start (CountDownLatch. 1)
        tasks (mapv
               (fn [packet-count ^DatagramSocket socket]
                 (let [sender-rate (* (double rate)
                                      (/ (double packet-count)
                                         (double packets)))]
                   (future
                     (.countDown ready)
                     (.await start)
                     (send-count! socket address port
                                  (max 1 (- (long frame-size) 28))
                                  packet-count sender-rate))))
               counts
               sockets)]
    (when-not (.await ready 10 TimeUnit/SECONDS)
      (doseq [^DatagramSocket socket sockets]
        (.close socket))
      (doseq [task tasks]
        (future-cancel task))
      (.countDown start)
      (throw (ex-info "UDP senders did not become ready"
                      {:senders senders})))
    (when (pos? (long start-delay-ms))
      (Thread/sleep (long start-delay-ms)))
    (let [started (System/nanoTime)]
      (.countDown start)
      (let [sent (reduce + 0 (map deref tasks))
            elapsed-ns (- (System/nanoTime) started)]
        {:host (.getHostAddress address)
         :port port
         :requested-packets packets
         :sent sent
         :target-pps rate
         :realized-pps (/ (double sent)
                          (/ (double elapsed-ns) 1.0e9))
         :elapsed-ns elapsed-ns
         :frame-size frame-size
         :senders senders
         :start-delay-ms start-delay-ms}))))

(defn -main
  [& args]
  (try
    (let [opts (parse-args args)]
      (if (:help? opts)
        (usage)
        (prn (run-generator! opts))))
    (finally
      (shutdown-agents))))
