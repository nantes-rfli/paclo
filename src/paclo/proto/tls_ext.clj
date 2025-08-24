(ns paclo.proto.tls-ext
  (:require
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

;; --- TLS ClientHello → SNI ---------------------------------------------------

(defn extract-sni
  "TLS ClientHello の SNI を best-effort で抽出。該当なし/解析失敗は nil。
   単一 TLS レコード内・単一セグメント前提（ストリーム再構成はしない）。"
  ^String
  [^bytes ba]
  (try
    (let [len (alength ba)]
      (when (<= 5 len)
        (let [ct   (u8 ba 0)              ;; ContentType
              vmaj (u8 ba 1)              ;; Major
              _vmin (u8 ba 2)
              rlen (u16 ba 3)]
          (when (and (= 22 ct) (= 3 vmaj) (some? rlen) (<= (+ 5 rlen) len))
            (let [ho    5                 ;; handshake offset
                  htype (u8 ba ho)
                  hlen  (u24 ba (inc ho))
                  hb    (+ ho 4)
                  he    (+ hb (or hlen 0))]
              (when (and (= 1 htype) (some? hlen) (<= he (+ 5 rlen)) (<= (+ hb 2 32 1) len))
                ;; ClientHello body
                (let [p0       hb
                      _cli-ver (u16 ba p0)
                      p1       (+ p0 2 32)                         ;; random
                      sid-len  (u8 ba p1)
                      p2       (+ p1 1 (or sid-len 0))
                      cs-len   (u16 ba p2)
                      p3       (+ p2 2 (or cs-len 0))
                      cm-len   (u8 ba p3)
                      p4       (+ p3 1 (or cm-len 0))]
                  (when (<= (+ p4 2) he)
                    (let [ext-len (u16 ba p4)
                          ext-beg (+ p4 2)
                          ext-end (+ ext-beg (or ext-len 0))]
                      (when (<= ext-end he)
                        ;; scan extensions
                        (loop [p ext-beg]
                          (when (<= (+ p 4) ext-end)
                            (let [et (u16 ba p)
                                  el (u16 ba (+ p 2))
                                  db (+ p 4)
                                  de (+ db (or el 0))]
                              (when (<= de ext-end)
                                (if (zero? et) ;; server_name(0)
                                  (let [list-len (u16 ba db)
                                        lb       (+ db 2)
                                        le       (+ lb (or list-len 0))]
                                    (when (<= le de)
                                      (loop [q lb]
                                        (when (<= (+ q 3) le)
                                          (let [nt (u8 ba q)
                                                nl (u16 ba (inc q))
                                                nb (+ q 3)
                                                ne (+ nb (or nl 0))]
                                            (when (<= ne le)
                                              (if (zero? nt)       ;; host_name(0)
                                                (let [s (substr ba nb (or nl 0))]
                                                  (when (and s (not (clojure.string/blank? s)))
                                                    (throw (ex-info "FOUND" {:sni s}))))
                                                (recur ne))))))))
                                  (recur de))))))))))))))))
    nil
    (catch clojure.lang.ExceptionInfo ex
      (or (:sni (ex-data ex)) nil))
    (catch Throwable _ nil)))

;; --- decode-ext hook ---------------------------------------------------------

(defn- annotate-tls-sni [m]
  (if (= :tcp (get-in m [:decoded :l3 :l4 :type]))
    (let [ba  (get-in m [:decoded :l3 :l4 :payload])
          sni (when ba (extract-sni ^bytes ba))]
      (if sni
        (-> m
            (assoc-in [:decoded :l3 :l4 :app :type] :tls)
            (assoc-in [:decoded :l3 :l4 :app :sni] sni)
            (update-in [:decoded :l3 :l4 :app]
                       #(cond-> %
                          true (assoc :summary (str "TLS ClientHello SNI=" sni)))))
        m))
    m))

(defn register!
  "Install TLS SNI annotation hook."
  []
  (dx/register! ::tls-sni annotate-tls-sni))
