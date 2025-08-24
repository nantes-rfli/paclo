(ns examples.smoke-test
  (:require
   [clojure.edn :as edn]
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [examples.dns-rtt :as dns-rtt]
   [examples.flow-topn :as flow-topn]
   [examples.pcap-filter :as pcap-filter]
   [examples.pcap-stats :as pcap-stats])
  (:import
   [java.io File]))

(def sample "dns-sample.pcap")

(defn run-main
  "例の -main を実行して stdout/err を取り出す。"
  [f & args]
  (let [err-w (java.io.StringWriter.)]
    (let [out (with-out-str
                (binding [*err* err-w]
                  (apply f args)))]
      {:out out
       :err (.toString err-w)})))

(defn parse-first-edn [s]
  (edn/read-string s))

(defn parse-last-edn-line [s]
  (some->> (str/split-lines s)
           (filter #(str/starts-with? % "{"))
           last
           edn/read-string))

(deftest pcap-stats-smoke
  (testing "pcap-stats returns a sane map"
    (let [{:keys [out]} (run-main pcap-stats/-main sample)
          m (parse-first-edn out)]
      (is (map? m))
      (is (= 4 (:packets m)))        ;; サンプルpcapの既知値
      (is (= 4 (get-in m [:proto :l4 :udp]))))))

(deftest flow-topn-smoke
  (testing "flow-topn returns a non-empty vector"
    (let [{:keys [out]} (run-main flow-topn/-main sample)]
      (let [v (parse-first-edn out)]
        (is (vector? v))
        (is (= 4 (count v)))))))     ;; サンプルpcapの既知値（4フロー）

(deftest dns-rtt-smoke
  (testing "dns-rtt pairs mode prints vector"
    (let [{:keys [out]} (run-main dns-rtt/-main sample)]
      (let [v (parse-first-edn out)]
        (is (vector? v))
        (is (<= 1 (count v)))))))    ;; サンプルでは2件のはず

(deftest pcap-filter-smoke
  (testing "pcap-filter writes a file and prints EDN meta"
    (let [tmp (-> (File/createTempFile "paclo-smoke" ".pcap") .getAbsolutePath)
          {:keys [out]} (run-main pcap-filter/-main sample tmp)
          meta (parse-last-edn-line out)]
      (is (.exists (File. tmp)))
      (is (map? meta))
      (is (= tmp (:out meta)))
      (is (= (:in-packets meta) (:out-packets meta))))))  ;; フィルタなし=等数
