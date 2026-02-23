(ns paclo.test-util
  (:require
   [clojure.string :as str]))

(defn hex->bytes ^bytes [^String s]
  (let [no-line-comments (str/replace s #"(?m);.*$" "")     ;;    ;       
        no-block-comments (str/replace no-line-comments #"(?s)/\*.*?\*/" "") ;; /* ... */      
        cleaned (-> no-block-comments
                    str/lower-case
                    (str/replace #"[^0-9a-f]" ""))]         ;; 16        
    (when (odd? (count cleaned))
      (throw (ex-info "Odd number of hex digits" {:len (count cleaned)})))
    (byte-array
     (map (fn [[a b]]
            (unchecked-byte (Integer/parseInt (str a b) 16)))
          (partition 2 cleaned)))))
