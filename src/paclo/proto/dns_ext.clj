(ns paclo.proto.dns-ext
  (:require
   [clojure.string :as str]
   [paclo.decode-ext :as dx]))

;; ------------------------------
;; internal: bytes helpers
;; ------------------------------

(defn- u8 [^bytes ba i]
  (when (and ba (<= 0 i) (< i (alength ba)))
    (bit-and 0xFF (aget ba i))))

(defn- u16 [^bytes ba i]
  (when-let [hi (u8 ba i)]
    (when-let [lo (u8 ba (unchecked-inc-int i))]
      (bit-or (bit-shift-left hi 8) lo))))

;; ------------------------------
;; internal: DNS name decoder (with compression)
;; ------------------------------

(defn- decode-name
  "Return [name next-off] or nil on failure.
   Follows compression pointers (0xC0xx). Limits jumps to avoid loops."
  [^bytes ba start-off]
  (try
    (let [len (alength ba)]
      (loop [off start-off
             parts (transient [])
             jumps 0
             jumped? false]
        (when (>= jumps 20)
          (throw (ex-info "too many jumps" {:off off})))
        (when (or (nil? off) (>= off len))
          (throw (ex-info "offset OOB" {:off off :len len})))
        (let [b (u8 ba off)]
          (cond
            ;; terminal zero
            (= b 0x00)
            [(->> (persistent! parts)
                  (remove str/blank?)
                  (str/join "."))
             (if jumped? start-off (inc off))]

            ;; compression pointer 11xxxxxx
            (= 0xC0 (bit-and b 0xC0))
            (let [ptr (bit-or (bit-shift-left (bit-and b 0x3F) 8)
                              (u8 ba (inc off)))]
              ;; follow pointer; the 'next-off' does not advance if we've jumped
              (let [[nm _] (decode-name ba ptr)]
                [(or nm "") (if jumped? (inc (inc off)) (inc (inc off)))]))

            ;; ordinary label
            :else
            (let [lablen b
                  s (inc off)
                  e (+ s lablen)]
              (when (> e len)
                (throw (ex-info "label OOB" {:s s :e e :len len})))
              (let [label (String. ba s lablen "UTF-8")]
                (recur e (conj! parts label) jumps jumped?)))))))
    (catch Throwable _ nil)))

;; ------------------------------
;; internal: QTYPE mapping
;; ------------------------------

(def ^:private qtype->kw
  {1 :A, 2 :NS, 5 :CNAME, 6 :SOA, 12 :PTR, 15 :MX, 16 :TXT
   28 :AAAA, 33 :SRV, 65 :HTTPS, 64 :SVCB})

(defn- annotate-qname-qtype
  "Best-effort: parse first Question from DNS payload and attach
   [:decoded :l3 :l4 :app :qname] and :qtype-name (keyword).
   Only runs when qdcount>=1 and payload looks sane."
  [m]
  (try
    (let [app (get-in m [:decoded :l3 :l4 :app])
          qd  (:qdcount app)
          ba  (get-in m [:decoded :l3 :l4 :payload])]
      (if (and (pos? (long (or qd 0))) ba (>= (alength ^bytes ba) 12))
        (let [[qname off1] (decode-name ^bytes ba 12)
              qt (some-> (u16 ^bytes ba off1))
              qc (some-> (u16 ^bytes ba (+ off1 2)))
              qtype-kw (get qtype->kw qt (keyword (str "TYPE" qt)))]
          (cond-> m
            qname (assoc-in [:decoded :l3 :l4 :app :qname] qname)
            qt    (assoc-in [:decoded :l3 :l4 :app :qtype] qt)
            qt    (assoc-in [:decoded :l3 :l4 :app :qtype-name] qtype-kw)
            qc    (assoc-in [:decoded :l3 :l4 :app :qclass] qc)))
        m))
    (catch Throwable _ m)))

(defn ^:private annotate-dns
  "If decoded packet has DNS, attach a tiny :summary and (best-effort) qname/qtype."
  [m]
  (if (= :dns (get-in m [:decoded :l3 :l4 :app :type]))
    (-> m
        (assoc-in [:decoded :l3 :l4 :app :summary] "DNS message")
        (annotate-qname-qtype))
    m))

(defn register!
  "Install DNS annotation hook."
  []
  (dx/register! ::dns-summary annotate-dns))
