(ns examples.cli-contract-test
  (:require
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.java.shell :as shell]
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [examples.dns-qps :as dns-qps]
   [examples.dns-topn :as dns-topn]
   [examples.flow-topn :as flow-topn]
   [examples.pcap-filter :as pcap-filter]
   [examples.pcap-stats :as pcap-stats])
  (:import
   [java.io File]))

(def ^:private sample-abs
  (let [url (io/resource "dns-sample.pcap")]
    (when (nil? url)
      (throw (ex-info "dns-sample.pcap not found on classpath" {})))
    (.getAbsolutePath (io/file url))))

(def ^:private snapshots
  (let [url (io/resource "cli_snapshots.edn")]
    (when (nil? url)
      (throw (ex-info "cli_snapshots.edn not found on classpath" {})))
    (edn/read-string (slurp (io/file url)))))

(defn- run-main
  "Run example -main and capture stdout/stderr."
  [f & args]
  (let [err-w (java.io.StringWriter.)
        out (with-out-str
              (binding [*err* err-w]
                (apply f args)))]
    {:out out
     :err (.toString err-w)}))

(defn- parse-first-edn [s]
  (edn/read-string s))

(defn- parse-last-edn-line [s]
  (some->> (str/split-lines s)
           (filter #(str/starts-with? % "{"))
           last
           edn/read-string))

(defn- normalize-top [rows]
  (->> rows
       (sort-by (fn [{:keys [count key]}]
                  [(- (long count)) (str key)]))
       vec))

(defn- normalize-pcap-stats [m]
  {:packets (:packets m)
   :bytes (:bytes m)
   :caplen (:caplen m)
   :proto (:proto m)
   :top {:src (normalize-top (get-in m [:top :src]))
         :dst (normalize-top (get-in m [:top :dst]))}})

(defn- normalize-flow-topn [rows]
  (->> rows
       (sort-by (fn [row]
                  [(get-in row [:flow :proto])
                   (get-in row [:flow :src])
                   (get-in row [:flow :dst])]))
       vec))

(defn- normalize-pcap-filter [m]
  {:in (some-> (:in m) io/file .getName)
   :filter (:filter m)
   :min-caplen (:min-caplen m)
   :in-packets (:in-packets m)
   :out-packets (:out-packets m)
   :in-bytes (:in-bytes m)
   :out-bytes (:out-bytes m)
   :drop-pct (:drop-pct m)})

(defn- run-cli
  "Run CLI as subprocess to validate real exit codes."
  [& args]
  (apply shell/sh "clojure" args))

(deftest cli-output-snapshot-test
  (testing "pcap-stats normalized snapshot"
    (let [{:keys [out]} (run-main pcap-stats/-main sample-abs)
          got (normalize-pcap-stats (parse-first-edn out))]
      (is (= (:pcap-stats snapshots) got))))

  (testing "flow-topn normalized snapshot"
    (let [{:keys [out]} (run-main flow-topn/-main sample-abs)
          got (normalize-flow-topn (parse-first-edn out))]
      (is (= (normalize-flow-topn (:flow-topn snapshots)) got))))

  (testing "dns-topn snapshot"
    (let [{:keys [out]} (run-main dns-topn/-main sample-abs)
          got (parse-first-edn out)]
      (is (= (:dns-topn snapshots) got))))

  (testing "dns-qps snapshot"
    (let [{:keys [out]} (run-main dns-qps/-main sample-abs)
          got (parse-first-edn out)]
      (is (= (:dns-qps snapshots) got))))

  (testing "pcap-filter normalized snapshot"
    (let [tmp (-> (File/createTempFile "paclo-cli-contract" ".pcap")
                  .getAbsolutePath)
          {:keys [out]} (run-main pcap-filter/-main sample-abs tmp)
          meta-map (parse-last-edn-line out)
          got (normalize-pcap-filter meta-map)]
      (is (= (:pcap-filter snapshots) got)))))

(deftest cli-exit-code-contract-test
  (testing "missing required arg exits with code 1 (usage)"
    (let [{:keys [exit err]} (run-cli "-M:dev" "-m" "examples.pcap-stats")]
      (is (= 1 exit))
      (is (str/includes? err "Usage:"))))

  (testing "missing input file exits with code 2"
    (let [{:keys [exit err]} (run-cli "-M:dev" "-m" "examples.pcap-stats" "/tmp/paclo-no-such-file.pcap")]
      (is (= 2 exit))
      (is (str/includes? err "input PCAP not found"))))

  (testing "unknown flag exits with code 4"
    (let [{:keys [exit err]} (run-cli "-M:dev" "-m" "examples.pcap-stats" sample-abs "_" "_" "edn" "--unknown-flag")]
      (is (= 4 exit))
      (is (str/includes? err "unknown flag")))))
