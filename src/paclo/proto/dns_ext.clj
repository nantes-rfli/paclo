(ns paclo.proto.dns-ext
  (:require
   [paclo.decode-ext :as dx]))

(defn ^:private annotate-dns
  "If decoded packet has DNS, attach a tiny :summary."
  [m]
  (if (= :dns (get-in m [:decoded :l3 :l4 :app :type]))
    (assoc-in m [:decoded :l3 :l4 :app :summary] "DNS message")
    m))

(defn register!
  "Install DNS annotation hook."
  []
  (dx/register! ::dns-summary annotate-dns))
