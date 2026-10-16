(ns paclo.dev.dns-jar-consumer
  "Load this file with -i from a JAR-only -Srepro consumer directory, then call -main with the checkout path."
  (:require
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [paclo.core :as core]
   [paclo.dns :as dns]
   [paclo.pcapng :as pcapng]
   [paclo.proto.dns-ext :as dns-ext]
   [paclo.stream :as stream]
   [paclo.window :as window])
  (:import
   [java.io Closeable]
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]))

(def options {:timeout-us 10000000 :reuse-delay-us 10000000 :max-pending 100 :max-retired 100})

(defn- event-step [{:keys [analysis events]} event]
  (let [r (dns/step analysis event)]
    {:analysis (:state r) :events (into events (:events r))}))

(defn- packet-step [s p] (event-step s (dns/packet->event p)))
(defn- initial [] {:analysis (dns/init options) :events []})

(defn -main [checkout]
  (try
    (doseq [resource ["paclo/core.clj" "paclo/dns.clj" "paclo/window.clj" "paclo/pcapng.clj"
                      "paclo/stream.clj" "paclo/proto/dns_ext.clj" "paclo/jnr/PcapLibrary.class"]]
      (let [url (io/resource resource)]
        (assert (and url (= "jar" (.getProtocol url))) (str "not loaded from JAR: " resource))))
    (let [path (str checkout "/test/resources/dns-sample.pcap")
          opts {:path path :decode? true :extensions [dns-ext/annotate-dns]
                :max Long/MAX_VALUE :error-mode :throw}
          packets (core/reduce-packets opts conj [])
          events (mapv dns/packet->event packets)
          expected (reduce event-step (initial) events)
          seed (event-step (initial) (first events))
          resumed (update seed :analysis #(edn/read-string (pr-str %)))
          finish #(dns/finish (:analysis %))]
      (assert (= [10241 15817] (vec (sort (map :rtt-us (:events expected))))))
      (assert (= expected (core/reduce-packets opts packet-step (initial))))
      (assert (= expected (reduce event-step resumed (rest events))))
      (assert (= (finish expected) (finish (reduce event-step seed (rest events)))))
      (let [legacy (update seed :analysis dissoc :paclo.dns/next-expiry-us)
            rebuilt (dns/advance (:analysis legacy) (:time-us (first events)))]
        (assert (= (:analysis seed) (assoc (:state rebuilt) :watermark-us nil))))
      (with-open [^Closeable capture (core/start-capture opts)
                  ^Closeable fanout (stream/fan-out (core/capture-packets capture)
                                                    {:left {:buffer-mode :blocking :buffer-cap 1}
                                                     :right {:buffer-mode :blocking :buffer-cap 1}}
                                                    {:cancel! #(core/stop-capture! capture)})
                  ^Closeable left (stream/branch fanout :left)
                  ^Closeable right (stream/branch fanout :right)]
        (let [a (future (reduce packet-step (initial) left))
              b (future (reduce packet-step (initial) right))]
          (assert (= expected (deref a 10000 :timeout) (deref b 10000 :timeout)))))
      (let [query (assoc (first events) :time-us (dec Long/MAX_VALUE))
            s (:state (dns/step (dns/init options) query))
            s (:state (dns/step s (assoc query :time-us (- Long/MAX_VALUE 2))))
            response (assoc (second events) :time-us Long/MAX_VALUE)
            r (dns/step s response)]
        (assert (= 2 (get-in r [:events 0 :rtt-us])))
        (assert (= 1 (get-in r [:events 0 :retransmissions])))
        (assert (> (get-in r [:events 0 :deadline-us]) Long/MAX_VALUE))
        (assert (= [:id-reuse] (mapv :kind (:events (dns/step (:state r) query)))))
        (assert (empty? (get-in (dns/advance (:state r) (+' Long/MAX_VALUE 20000000)) [:state :retired]))))
      (let [raw (core/reduce-packets (dissoc opts :decode? :extensions) conj [])
            directory (Files/createTempDirectory "paclo-dns-consumer-" (make-array FileAttribute 0))
            output (.resolve directory "dns.pcapng")
            descriptors [{:type :section :section-id 0
                          :section {:id 0 :byte-order :little-endian :version [1 0] :section-length nil :options []}}
                         {:type :interface :section-id 0
                          :interface {:section-id 0 :id 0 :file-linktype 1 :linktype 1 :snaplen 65536
                                      :timestamp-resolution {:base 10 :exponent 6} :timestamp-offset-sec 0 :options []}}]
            envelopes (map #(hash-map :type :packet :section-id 0
                                      :packet (assoc % :pcapng {:section-id 0 :interface-id 0
                                                                :block-type :enhanced-packet :options []})) raw)]
        (try
          (pcapng/write-pcapng! (concat descriptors envelopes) output {:mode :author})
          (with-open [source (pcapng/open-source {:path output})]
            (let [decoded (transduce (comp (filter :packet) (map :packet)
                                           (core/packet-xf {:decode? true :extensions [dns-ext/annotate-dns]}))
                                     conj [] source)
                  analyzed (reduce packet-step (initial) decoded)
                  windows (reduce (fn [s p] (:state (window/step s {:time-us (dns/packet-time-us p)
                                                                    :group :dns :captured-bytes (:caplen p)})))
                                  (window/init {:width-us 1000000 :max-windows 100 :max-groups 100}) decoded)
                  finalized (window/finish windows)]
              (assert (= expected analyzed))
              (assert (= 4 (reduce + (map #(get-in % [:groups :dns :packets]) (:events finalized)))))
              (assert (empty? (get-in finalized [:state :windows])))))
          (finally (Files/deleteIfExists output) (Files/delete directory)))))
    (println :jar-consumer-ok :dns :exact :snapshots :independent-fanout :pcapng :window)
    (finally (shutdown-agents))))
