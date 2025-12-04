(ns paclo.decode-ext-prop-test
  (:require
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [paclo.decode-ext :as dx]))

(declare prop-apply-respects-map-only prop-register-overwrites-to-tail)

;; Helpers
(defn reset-hooks! []
  (doseq [k (dx/installed)] (dx/unregister! k)))

(def gen-hook
  "Generate hook descriptors {:k kw :kind :map|:nonmap|:boom :val any}"
  (let [kw-gen (gen/fmap (fn [i] (keyword "h" (str i))) (gen/choose 0 8))
        kind-gen (gen/elements [:map :nonmap :boom])]
    (gen/let [k kw-gen
              kind kind-gen
              v gen/any-printable]
      {:k k :kind kind :val v})))

(defn apply-desc [m desc]
  (case (:kind desc)
    :map    (assoc m (:k desc) (:val desc))
    :nonmap m
    :boom   m))

;; Property: apply! respects order, ignores non-map returns and exceptions
(defn dedupe-tail-order
  "Given hook descriptors, emulate register! overwrite semantics:
   remove previous same key, append new one."
  [hooks]
  (reduce (fn [acc h]
            (conj (vec (remove #(= (:k %) (:k h)) acc)) h))
          [] hooks))

(defspec prop-apply-respects-map-only 100
  (prop/for-all [hooks (gen/vector gen-hook 1 12)]
                (reset-hooks!)
                (try
      ;; register hooks in order
                  (doseq [{:keys [k kind val]} hooks]
                    (dx/register! k
                                  (case kind
                                    :map    (fn [m] (assoc m k val))
                                    :nonmap (fn [_] :non-map)
                                    :boom   (fn [_] (throw (ex-info "boom" {}))))))
                  (let [m0 {:decoded {:l3 {:l4 {:type :udp}}}}
                        eff-hooks (dedupe-tail-order hooks)
                        expected  (reduce apply-desc m0 eff-hooks)
                        actual    (dx/apply! m0)]
                    (= expected actual))
                  (finally
                    (reset-hooks!)))))

;; Property: register! overwrites same key and moves it to the tail (execution order)
(defspec prop-register-overwrites-to-tail 100
  (prop/for-all [keys (gen/vector (gen/fmap #(keyword "k" (str %)) (gen/choose 0 6)) 1 10)]
                (reset-hooks!)
                (try
                  (doseq [k keys]
                    (dx/register! k identity))
                  (let [expected
                        (reduce (fn [order k]
                                  (conj (vec (remove #(= % k) order)) k))
                                [] keys)
                        installed (vec (dx/installed))]
                    (= expected installed))
                  (finally
                    (reset-hooks!)))))
