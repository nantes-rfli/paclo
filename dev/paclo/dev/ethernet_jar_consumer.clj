(ns paclo.dev.ethernet-jar-consumer
  "Run with -i from outside the checkout on a JAR-only -Srepro classpath."
  (:require
   [clojure.java.io :as io]
   [clojure.walk :as walk]
   [paclo.core :as core]
   [paclo.proto.dns-ext :as dns]
   [paclo.proto.tls-ext :as tls]))

(defn- data-value [x]
  (walk/postwalk #(if (bytes? %) (vec %) %) x))

(defn -main [checkout]
  (try
    (doseq [path ["paclo/core.clj" "paclo/parse.clj" "paclo/linktype.clj" "paclo/flow/project.clj"
                  "paclo/pcap.clj" "paclo/capture.clj" "paclo/proto/dns_ext.clj"
                  "paclo/proto/tls_ext.clj" "paclo/jnr/PcapLibrary.class"]]
      (assert (= "jar" (some-> (io/resource path) .getProtocol)) (str "not loaded from JAR: " path)))
    (doseq [[path dlt] [["dns-sample.pcap" 1] ["cooked/sll.pcap" 113] ["cooked/sll2.pcap" 276]
                        ["raw-ip/raw.pcap" 12] ["null-loop/null-header-le-file-le.pcap" 0]
                        ["null-loop/loop-header-be-file-le.pcap" 108]]]
      (let [path (str checkout "/test/resources/" path)
            raw (core/reduce-packets {:path path :max 8} conj [])
            snapshots (data-value raw)]
        (doseq [options [{:decode? true :extensions []}
                         {:decode? true :extensions [dns/annotate-dns tls/annotate-tls-sni]}
                         {:decode-mode :flow}]]
          (let [result (into [] (core/packet-xf options) raw)
                native (core/reduce-packets (assoc options :path path :max 8) conj [])]
            (assert (= (count raw) (count result) (count native)))
            (assert (= (data-value result) (data-value native)))
            (assert (every? #(and (= dlt (:linktype %)) (not (:decode-error %))) result))
            (if (:decode? options)
              (assert (every? true? (map #(identical? (:bytes %1) (:bytes %2)) raw result)))
              (assert (not-any? #(or (contains? % :bytes) (contains? % :decoded)) result)))))
        (assert (= snapshots (data-value raw)))))
    (println :ethernet-jar-consumer-ok :all-six-dlts :full :flow :extensions :identity)
    (finally (shutdown-agents))))
