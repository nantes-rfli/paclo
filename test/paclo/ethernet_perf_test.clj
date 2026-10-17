(ns paclo.ethernet-perf-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [paclo.core :as core]
   [paclo.dev.ethernet-perf :as perf]))

(declare ethernet-addresses-and-vlans-remain-exact)

(defn- transform [mode packet]
  (first (into [] (core/packet-xf (if (= mode :full)
                                    {:decode? true :extensions []} {:decode-mode :flow})) [packet])))

(defspec ethernet-addresses-and-vlans-remain-exact 250
  (prop/for-all [addresses (gen/vector gen/byte 12)
                 version (gen/elements [4 6]) traffic (gen/elements [:udp :tcp])
                 size (gen/elements [96 1514]) tags (gen/choose 0 5)]
                (let [^bytes bytes (perf/frame version traffic size tags)
                      _ (doseq [[index value] (map-indexed vector addresses)] (aset-byte bytes index value))
                      snapshot (vec bytes)
                      packet (perf/packet bytes 1 version)
                      full (transform :full packet) projected (transform :flow packet)
                      header (:decoded full)
                      mac #(str/join ":" (map (fn [b] (format "%02x" (bit-and b 255))) %))]
                  (and (= snapshot (vec bytes)) (identical? bytes (:bytes full))
                       (not-any? #(contains? projected %) [:bytes :decoded])
                       (nil? (:decode-error full)) (nil? (:diagnostics full))
                       (nil? (:decode-error projected)) (nil? (:diagnostics projected))
                       (= (mac (take 6 addresses)) (:dst header))
                       (= (mac (drop 6 addresses)) (:src header))
                       (= (if (= version 4) 0x0800 0x86dd) (:eth header))
                       (= (mapv (fn [i] {:tpid (if (zero? i) 0x88a8 0x8100)
                                         :pcp 5 :dei true :vid i}) (range tags))
                          (vec (:vlan-tags header)))
                       (= (pos? tags) (contains? header :vlan-tags))
                       (= version (get-in header [:l3 :version]) (:ip-version projected))
                       (= 12000 (get-in header [:l3 :l4 :src-port]) (:src-port projected))
                       (= (if (= traffic :tcp) 443 5300)
                          (get-in header [:l3 :l4 :dst-port]) (:dst-port projected))))))

(deftest matrix-generator-covers-every-supported-framing
  (is (= 128 (count (perf/scenarios :matrix))))
  (is (= 96 (count (perf/scenarios :native))))
  (doseq [{:keys [version traffic size vlans dlt mode]} (perf/scenarios :matrix)]
    (let [p (perf/packet (perf/frame version traffic size vlans) dlt version)
          r (transform mode p)]
      (is (nil? (:decode-error r)))
      (is (nil? (:diagnostics r)))
      (is (= version (if (= mode :full) (get-in r [:decoded :l3 :version]) (:ip-version r)))))))

(deftest benchmark-rejects-unknown-suite
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unknown benchmark suite" (perf/scenarios :invalid))))
