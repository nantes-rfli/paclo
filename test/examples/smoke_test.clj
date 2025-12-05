(ns examples.smoke-test
  (:require
   [clojure.data.json :as json]
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [examples.dns-rtt :as dns-rtt]
   [examples.flow-topn :as flow-topn]
   [examples.pcap-filter :as pcap-filter]
   [examples.pcap-stats :as pcap-stats])
  (:import
   [java.io File]))

(def sample
  (let [url (io/resource "dns-sample.pcap")]
    (when (nil? url)
      (throw (ex-info "dns-sample.pcap not found on classpath" {})))
    (.getAbsolutePath (io/file url))))

(def sample-synth
  (let [url (io/resource "dns-synth-small.pcap")]
    (when (nil? url)
      (throw (ex-info "dns-synth-small.pcap not found on classpath" {})))
    (.getAbsolutePath (io/file url))))

(defn run-main
  "例の -main を実行して stdout/err を取り出す。"
  [f & args]
  (let [err-w (java.io.StringWriter.)
        out (with-out-str
              (binding [*err* err-w]
                (apply f args)))]
    {:out out
     :err (.toString err-w)}))

(defn parse-first-edn [s]
  (edn/read-string s))

(defn parse-last-edn-line [s]
  (some->> (str/split-lines s)
           (filter #(str/starts-with? % "{"))
           last
           edn/read-string))

(defn parse-first-json [s]
  (let [line (->> (str/split-lines s)
                  (filter #(re-find #"^[\[{]" (str/trim %)))
                  first)]
    (json/read-str line :key-fn keyword)))

(deftest pcap-stats-smoke
  (testing "pcap-stats returns a sane map"
    (let [{:keys [out]} (run-main pcap-stats/-main sample)
          m (parse-first-edn out)]
      (is (map? m))
      (is (= 4 (:packets m)))        ;; サンプルpcapの既知値
      (is (= 4 (get-in m [:proto :l4 :udp]))))))

(deftest pcap-stats-jsonl-smoke
  (testing "pcap-stats returns JSONL when requested"
    (let [{:keys [out]} (run-main pcap-stats/-main sample nil nil "jsonl")
          m (parse-first-json out)]
      (is (map? m))
      (is (= 4 (:packets m))))))

(deftest pcap-stats-async-smoke
  (testing "pcap-stats async still counts packets"
    (let [{:keys [out err]} (run-main pcap-stats/-main sample "_" "_" "edn" "--async" "--async-buffer" "16" "--async-mode" "dropping")
          m (parse-first-edn out)]
      (is (map? m))
      (is (= 4 (:packets m)))
      (is (str/includes? err "async=true")))))

(deftest flow-topn-smoke
  (testing "flow-topn returns a non-empty vector"
    (let [{:keys [out]} (run-main flow-topn/-main sample)
          v (parse-first-edn out)]
      (is (vector? v))
      (is (= 4 (count v))))))     ;; サンプルpcapの既知値（4フロー）

(deftest flow-topn-jsonl-smoke
  (testing "flow-topn emits JSONL per row"
    (let [{:keys [out]} (run-main flow-topn/-main sample "udp or tcp" "10" "unidir" "packets" "jsonl")
          lines (str/split-lines out)
          m (-> lines first (json/read-str :key-fn keyword))]
      (is (<= 1 (count lines)))   ;; 小PCAPだと 2〜4 行想定
      (is (map? m))
      (is (contains? m :flow)))))

(deftest flow-topn-async-smoke
  (testing "flow-topn async keeps same results on small PCAP"
    (let [{:keys [out err]} (run-main flow-topn/-main sample "udp or tcp" "10" "unidir" "packets" "edn" "--async" "--async-buffer" "1024")
          v (parse-first-edn out)]
      (is (vector? v))
      (is (= 4 (count v)))  ;; sample known size
      (is (str/includes? err "async=true")))))

(deftest flow-topn-async-timeout-smoke
  (testing "flow-topn async timeout may truncate results"
    (let [{:keys [out err]} (run-main flow-topn/-main sample "udp or tcp" "10" "unidir" "packets" "edn" "--async" "--async-timeout-ms" "0" "--async-buffer" "4")
          v (parse-first-edn out)]
      (is (vector? v))
      (is (<= (count v) 4))
      (is (str/includes? err "cancelled=")))))

(deftest dns-rtt-smoke
  (testing "dns-rtt stats mode returns a sane map"
    ;; pairs は片側欠損で 0 になりうるため、stats で健全性を確認する
    ;; 引数順: <in> [bpf] [topN] [mode] [metric] [format]
    (let [{:keys [out]} (run-main dns-rtt/-main sample "_" "_" "stats")
          m (parse-first-edn out)]
      (is (map? m))
      ;; サンプルでは 1 以上が期待（将来PCAPが変わっても 0 以外であればOKにするのも可）
      (is (<= 1 (:pairs m))))))

(deftest dns-rtt-jsonl-smoke
  (testing "dns-rtt stats mode emits JSONL"
    (let [{:keys [out]} (run-main dns-rtt/-main sample "_" "_" "stats" "_" "jsonl")
          m (parse-first-json out)]
      (is (map? m))
      (is (<= 1 (:pairs m))))))

(deftest dns-rtt-async-smoke
  (testing "dns-rtt async still produces rows and metadata"
    (let [{:keys [out err]} (run-main dns-rtt/-main sample "_" "_" "pairs" "_" "edn" "_" "--async" "--async-buffer" "16" "--async-mode" "dropping")
          rows (parse-first-edn out)]
      (is (vector? rows))
      (is (<= 1 (count rows)))
      (is (str/includes? err "async=true")))))

(deftest dns-rtt-async-timeout-smoke
  (testing "dns-rtt async timeout cancels early"
    (let [{:keys [out err]} (run-main dns-rtt/-main sample "_" "_" "stats" "_" "edn" "_" "--async" "--async-buffer" "8" "--async-timeout-ms" "0")
          m (parse-first-edn out)]
      (is (map? m))
      (is (str/includes? err "cancelled=true")))))

(deftest dns-rtt-synth-query-only-smoke
  (testing "dns-rtt handles query-only synthetic PCAP without errors"
    (let [{:keys [out]} (run-main dns-rtt/-main sample-synth "_" "_" "stats")
          m (parse-first-edn out)]
      (is (map? m))
      (is (= 0 (:pairs m)))
      (is (= 0 (:with-rtt m))))))

(deftest pcap-filter-smoke
  (testing "pcap-filter writes a file and prints EDN meta"
    (let [tmp (-> (File/createTempFile "paclo-smoke" ".pcap") .getAbsolutePath)
          {:keys [out]} (run-main pcap-filter/-main sample tmp)
          meta (parse-last-edn-line out)]
      (is (.exists (File. tmp)))
      (is (map? meta))
      (is (= tmp (:out meta)))
      (is (= (:in-packets meta) (:out-packets meta))))))  ;; フィルタなし=等数

(deftest pcap-filter-jsonl-smoke
  (testing "pcap-filter writes JSONL meta when requested"
    (let [tmp (-> (File/createTempFile "paclo-smoke-jsonl" ".pcap") .getAbsolutePath)
          {:keys [out]} (run-main pcap-filter/-main sample tmp nil nil "jsonl")
          meta (parse-first-json out)]
      (is (.exists (File. tmp)))
      (is (map? meta))
      (is (= tmp (:out meta)))
      (is (= (:in-packets meta) (:out-packets meta))))))

(deftest pcap-filter-async-buffer-smoke
  (testing "pcap-filter async mode matches sync output on small PCAP"
    (let [tmp (-> (File/createTempFile "paclo-smoke-async" ".pcap") .getAbsolutePath)
          {:keys [out]} (run-main pcap-filter/-main sample tmp "_" "_" "edn" "--async" "--async-buffer" "1024" "--async-mode" "buffer")
          meta (parse-last-edn-line out)]
      (is (.exists (File. tmp)))
      (is (:async? meta))
      (is (false? (:async-cancelled? meta)))
      (is (= (:in-packets meta) (:out-packets meta))))))

(deftest pcap-filter-async-timeout-smoke
  (testing "pcap-filter async timeout cancels early"
    (let [tmp (-> (File/createTempFile "paclo-smoke-async-timeout" ".pcap") .getAbsolutePath)
          {:keys [out]} (run-main pcap-filter/-main sample tmp "_" "_" "edn" "--async" "--async-timeout-ms" "0" "--async-buffer" "4")
          meta (parse-last-edn-line out)]
      (is (.exists (File. tmp)))
      (is (:async? meta))
      (is (:async-cancelled? meta))
      (is (< (:out-packets meta) (:in-packets meta))))))
