;; Offline regression for Dependency-Check #8466/#8467. Exercise the schema
;; shipped in the resolved engine, using its actual H2 driver, without NVD I/O.
(ns verify-schema
  (:require [clojure.java.io :as io])
  (:import [java.sql DriverManager]
           [org.h2.tools RunScript]))

(with-open [connection (DriverManager/getConnection "jdbc:h2:mem:long-reference")
            schema (io/reader (io/resource "data/initialize.sql"))]
  (RunScript/execute connection schema)
  (doseq [length [1115 1585 8000]]
    (let [prefix "https://bugzilla.mozilla.org/buglist.cgi?bug_id="
          url (str prefix (apply str (repeat (- length (count prefix)) \1)))]
      (with-open [insert (.prepareStatement connection
                                           "INSERT INTO reference (url) VALUES (?)")]
        (.setString insert 1 url)
        (assert (= 1 (.executeUpdate insert))))
      (with-open [query (.prepareStatement connection
                                          "SELECT url FROM reference WHERE url = ?")]
        (.setString query 1 url)
        (with-open [result (.executeQuery query)]
          (assert (.next result))
          (assert (= url (.getString result 1)))
          (assert (not (.next result)))))))
  (println "Dependency-Check H2 schema preserves 1115-, 1585- and 8000-character URLs"))
