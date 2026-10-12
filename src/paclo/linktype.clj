(ns paclo.linktype
  "Internal Ethernet decode dispatch shared by full and flow transformations.")

(defn unsupported?
  "Absence retains legacy Ethernet input; explicit values must be integer DLT 1."
  [packet]
  (and (contains? packet :linktype)
       (not (and (integer? (:linktype packet)) (= 1 (:linktype packet))))))

(defn require-ethernet!
  [packet]
  (when (unsupported? packet)
    (throw (ex-info "unsupported linktype"
                    {:reason :unsupported-linktype :linktype (:linktype packet)}))))
