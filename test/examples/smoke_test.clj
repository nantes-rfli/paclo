(ns examples.smoke-test
  (:require
   [clojure.data.json :as json]
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [examples.dns-qps :as dns-qps]
   [examples.dns-rtt :as dns-rtt]
   [examples.dns-topn :as dns-topn]
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

(def sample-tls
  (let [url (io/resource "tls-sni-sample.pcap")]
    (when (nil? url)
      (throw (ex-info "tls-sni-sample.pcap not found on classpath" {})))
    (.getAbsolutePath (io/file url))))

(def sample-tls-alpn
  (let [url (io/resource "tls-sni-alpn-sample.pcap")]
    (when (nil? url)
      (throw (ex-info "tls-sni-alpn-sample.pcap not found on classpath" {})))
    (.getAbsolutePath (io/file url))))

(def sample-tls-h3
  (let [url (io/resource "tls-sni-h3-sample.pcap")]
    (when (nil? url)
      (throw (ex-info "tls-sni-h3-sample.pcap not found on classpath" {})))
    (.getAbsolutePath (io/file url))))

(def sample-tls-h3mix
  (let [url (io/resource "tls-sni-alpn-h3mix-sample.pcap")]
    (when (nil? url)
      (throw (ex-info "tls-sni-alpn-h3mix-sample.pcap not found on classpath" {})))
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
  (testing "pcap-filter async timeout cancels early")
  (let [tmp (-> (File/createTempFile "paclo-smoke-async-timeout" ".pcap") .getAbsolutePath)
        {:keys [out]} (run-main pcap-filter/-main sample tmp "_" "_" "edn" "--async" "--async-timeout-ms" "0" "--async-buffer" "4")
        meta (parse-last-edn-line out)]
    (is (.exists (File. tmp)))
    (is (:async? meta))
    (is (:async-cancelled? meta))
    (is (< (:out-packets meta) (:in-packets meta)))))

;; ---------- dns-topn / dns-qps (v0.4 追加) ----------

(deftest dns-topn-default-smoke
  (testing "dns-topn returns vector of rankings"
    (let [{:keys [out err]} (run-main dns-topn/-main sample)
          rows (parse-first-edn out)
          meta (parse-last-edn-line err)]
      (is (vector? rows))
      (is (pos? (count rows)))
      (is (map? (first rows)))
      (is (false? (:async? meta)) (str "meta: " meta)))))

(deftest dns-topn-csv-smoke
  (testing "dns-topn emits csv when requested"
    (let [{:keys [out]} (run-main dns-topn/-main sample "_" "_" "qname" "csv")
          lines (str/split-lines out)]
      (is (>= (count lines) 2))
      (is (= "key,count,bytes,pct" (first lines))))))

(deftest dns-topn-sni-smoke
  (testing "dns-topn extracts SNI"
    (let [{:keys [out]} (run-main dns-topn/-main sample-tls "_" "_" "sni" "edn")
          rows (parse-first-edn out)]
      (is (vector? rows))
      (is (= "example.com" (:key (first rows)))))))

(deftest dns-topn-alpn-smoke
  (testing "dns-topn extracts ALPN"
    (let [{:keys [out]} (run-main dns-topn/-main sample-tls-alpn "_" "_" "alpn" "edn")
          rows (parse-first-edn out)]
      (is (vector? rows))
      (is (= "h2" (:key (first rows)))))))

(deftest dns-topn-alpn-join-smoke
  (testing "dns-topn alpn join aggregates all protocols"
    (let [{:keys [out]} (run-main dns-topn/-main sample-tls-alpn "_" "_" "alpn" "edn" "_" "--alpn-join")
          rows (parse-first-edn out)]
      (is (= "h2,http/1.1" (:key (first rows)))))))

(deftest dns-topn-alpn-h3-smoke
  (testing "dns-topn alpn handles h3"
    (let [{:keys [out]} (run-main dns-topn/-main sample-tls-h3 "_" "_" "alpn" "edn")
          rows (parse-first-edn out)]
      (is (= "h3" (:key (first rows)))))))

(deftest dns-topn-alpn-h3mix-join-smoke
  (testing "dns-topn alpn join aggregates h3/h2/http1.1"
    (let [{:keys [out]} (run-main dns-topn/-main sample-tls-h3mix "_" "_" "alpn" "edn" "_" "--alpn-join")
          rows (parse-first-edn out)]
      (is (= "h3,h2,http/1.1" (:key (first rows)))))))

(deftest dns-qps-smoke
  (testing "dns-qps buckets timestamps"
    (let [{:keys [out err]} (run-main dns-qps/-main sample)
          rows (parse-first-edn out)
          meta (parse-last-edn-line err)]
      (is (vector? rows))
      (is (<= 1 (count rows)))
      (is (every? #(contains? % :t) rows))
      (is (= (:bucket-ms meta) 1000))
      (is (false? (:async? meta))))))

(deftest dns-qps-max-buckets-smoke
  (testing "dns-qps honors max-buckets"
    (let [{:keys [out err]} (run-main dns-qps/-main sample "_" "_" "_" "_" "--max-buckets" "1")
          rows (parse-first-edn out)
          meta (parse-last-edn-line err)]
      (is (<= (count rows) 1))
      (is (= 1 (:max-buckets meta))))))

(deftest dns-qps-emit-empty-flag-smoke
  (testing "dns-qps accepts emit-empty-buckets flag"
    (let [{:keys [err]} (run-main dns-qps/-main sample "_" "2000" "_" "_" "--emit-empty-buckets")
          meta (parse-last-edn-line err)]
      (is (= true (:emit-empty-buckets meta))))))

(deftest dns-qps-empty-per-key-smoke
  (testing "dns-qps emit-empty-per-key fills gaps"
    (let [{:keys [err]} (run-main dns-qps/-main sample "_" "2000" "qname" "_" "--emit-empty-per-key" "--max-buckets" "100")
          meta (parse-last-edn-line err)]
      (is (= true (:emit-empty-per-key meta))))))

(deftest dns-topn-punycode-warn-smoke
  (testing "dns-topn logs punycode failure when requested"
    (let [normalize #'examples.dns-topn/normalize-qname
          bad (str "xn--" (apply str (repeat 200 "a")))
          err-w (java.io.StringWriter.)]
      (binding [*err* err-w]
        (let [res (normalize bad true true)
              err-str (.toString err-w)]
          (is (= bad res))
          (is (re-find #"punycode-decode failed" err-str)))))))
