(ns paclo.proto.tls-ext
  (:require
   [clojure.string :as str]
   [paclo.decode-ext :as dx]))

;; --- tiny byte helpers -------------------------------------------------------

(defn- u8  ^long [^bytes ba ^long i]
  (when (and ba (<= 0 i) (< i (alength ba)))
    (bit-and 0xFF (aget ba i))))

(defn- u16 ^long [^bytes ba ^long i]
  (when-let [hi (u8 ba i)]
    (when-let [lo (u8 ba (inc i))]
      (bit-or (bit-shift-left hi 8) lo))))

(defn- u24 ^long [^bytes ba ^long i]
  (when-let [a (u8 ba i)]
    (when-let [b (u8 ba (inc i))]
      (when-let [c (u8 ba (+ i 2))]
        (bit-or (bit-shift-left a 16)
                (bit-shift-left b 8)
                c)))))

(defn- substr ^String [^bytes ba ^long off ^long len]
  (when (and ba (<= 0 off) (<= 0 len) (<= (+ off len) (alength ba)))
    (String. ba off len java.nio.charset.StandardCharsets/UTF_8)))

;; --- TLS ClientHello → SNI / ALPN --------------------------------------------

(defn- parse-server-name [^bytes ba ^long lb ^long le]
  (loop [q lb]
    (when (<= (unchecked-add q 3) le)
      (let [nt (u8 ba q)
            nl (u16 ba (unchecked-inc q))
            nb (unchecked-add q 3)
            ne (unchecked-add nb (long (or nl 0)))]
        (when (<= ne le)
          (if (zero? nt) ;; host_name
            (let [s (substr ba nb (long (or nl 0)))]
              (when (and s (not (str/blank? s))) s))
            (recur ne)))))))

(defn- parse-alpn [^bytes ba ^long lb ^long le]
  (loop [q lb acc []]
    (if (< q le)
      (let [pl (u8 ba q)
            nb (unchecked-inc q)
            ne (unchecked-add nb (long (or pl 0)))]
        (cond
          (nil? pl) acc
          (<= ne le)
          (if-let [proto (substr ba nb (long (or pl 0)))]
            (recur ne (conj acc proto))
            acc)
          :else acc))
      acc)))

(defn- parse-extensions [^bytes ba ^long ext-beg ^long ext-end]
  (loop [p ext-beg info {}]
    (if (<= (unchecked-add p 4) ext-end)
      (let [et (or (u16 ba p) 0)
            el (u16 ba (unchecked-add p 2))
            db (unchecked-add p 4)
            de (unchecked-add db (long (or el 0)))]
        (if (<= de ext-end)
          (let [info'
                (case et
                  0  (let [list-len (u16 ba db)
                           lb (unchecked-add db 2)
                           le (unchecked-add lb (long (or list-len 0)))
                           sni (when (<= le de) (parse-server-name ba lb le))]
                       (cond-> info sni (assoc :sni sni)))
                  16 (let [alpn-len (u16 ba db)
                           lb (unchecked-add db 2)
                           le (unchecked-add lb (long (or alpn-len 0)))
                           protos (when (<= le de) (parse-alpn ba lb le))]
                       (cond-> info (seq protos) (assoc :alpn protos)))
                  info)]
            (recur de info'))
          info))
      info)))

(defn- extract-tls-info
  "TLS ClientHello から SNI/ALPN を best-effort 抽出。
   返り値例: {:sni \"example.com\" :alpn [\"h2\" \"http/1.1\"]}（キーは存在するものだけ）"
  [^bytes ba]
  (try
    (or
     (let [len (alength ba)]
       (when (<= 5 len)
         (let [ct   (u8 ba 0)
               vmaj (u8 ba 1)
               rlen (u16 ba 3)]
           (when (and (= 22 ct) (= 3 vmaj) (some? rlen) (<= (unchecked-add 5 (long rlen)) len))
             (let [ho    5
                   htype (u8 ba ho)
                   hlen  (u24 ba (inc ho))
                   hb    (unchecked-add ho 4)
                   he    (unchecked-add hb (long (or hlen 0)))]
               (when (and (= 1 htype) (some? hlen) (<= he (unchecked-add 5 (long rlen))) (<= (unchecked-add hb 35) len))
                 (let [p0       hb
                       p1       (unchecked-add p0 34) ;; 2 + 32
                       sid-len  (u8 ba p1)
                       p2       (unchecked-add (unchecked-inc p1) (long (or sid-len 0)))
                       cs-len   (u16 ba p2)
                       p3       (unchecked-add (unchecked-add p2 2) (long (or cs-len 0)))
                       cm-len   (u8 ba p3)
                       p4       (unchecked-add (unchecked-inc p3) (long (or cm-len 0)))]
                   (when (<= (unchecked-add p4 2) he)
                     (let [ext-len (u16 ba p4)
                           ext-beg (unchecked-add p4 2)
                           ext-end (unchecked-add ext-beg (long (or ext-len 0)))]
                       (when (<= ext-end he)
                         (parse-extensions ba ext-beg ext-end)))))))))))
     {})
    (catch Throwable _ {})))

(defn extract-sni
  "TLS ClientHello の SNI を best-effort で抽出。該当なし/解析失敗は nil。"
  ^String
  [^bytes ba]
  (:sni (extract-tls-info ba)))

;; --- decode-ext hook ---------------------------------------------------------

(defn- annotate-tls-sni [m]
  (if (= :tcp (get-in m [:decoded :l3 :l4 :type]))
    (let [ba   (get-in m [:decoded :l3 :l4 :payload])
          info (when ba (extract-tls-info ^bytes ba))
          sni  (:sni info)
          alpn (:alpn info)]
      (if (seq info)
        (-> m
            (assoc-in [:decoded :l3 :l4 :app :type] :tls)
            (cond-> sni (assoc-in [:decoded :l3 :l4 :app :sni] sni))
            (cond-> alpn (assoc-in [:decoded :l3 :l4 :app :alpn] alpn))
            (update-in [:decoded :l3 :l4 :app]
                       #(cond-> %
                          sni  (assoc :summary (str "TLS ClientHello SNI=" sni))
                          (and (not sni) (seq alpn)) (assoc :summary (str "TLS ClientHello ALPN=" (str/join "," alpn))))))
        m))
    m))

(defn register!
  "Install TLS SNI annotation hook."
  []
  (dx/register! ::tls-sni annotate-tls-sni))
