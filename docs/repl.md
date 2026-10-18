# Offline analysis at the REPL

From the repository root, start `bash dev/script/codex.sh repl` after the
[development setup](../CONTRIBUTING.md#environment). This compiles the Java
bindings and includes the existing dev and DNS extension paths. No capture
privileges, live traffic or additional dependencies are needed.

Evaluate each block below as ordinary REPL forms. Each block is self-contained
and returns inspectable data; use `*1` or `clojure.pprint/pprint` to explore it.
The checked-in `test/resources/dns-sample.pcap` contains four Ethernet IPv4 UDP
packets: two DNS query/response pairs from `10.0.0.1`, to `1.1.1.1` and `8.8.8.8`.
All four blocks and their expected results run in the documentation CI gate.

## Inspect a small packet prefix

Materialize the result inside `with-open`, so pausing at the REPL leaves data
you can inspect after the capture closes. `take` limits the returned vector;
it does not identify how far the background reader has read ahead.

<!-- paclo-doc-test: repl-inspect -->

```clojure
(require '[paclo.core :as core])

(with-open [capture (core/start-capture
                     {:path "test/resources/dns-sample.pcap"
                      :decode? true :extensions [] :queue-cap 1})]
  (into []
        (comp (take 2)
              (map (fn [packet]
                     {:caplen (:caplen packet)
                      :src (get-in packet [:decoded :l3 :src])
                      :dst (get-in packet [:decoded :l3 :dst])
                      :protocol (get-in packet [:decoded :l3 :l4 :type])})))
        (core/capture-packets capture)))
;; => [{:caplen 82, :src "10.0.0.1", :dst "1.1.1.1", :protocol :udp}
;;     {:caplen 178, :src "1.1.1.1", :dst "10.0.0.1", :protocol :udp}]
```

To inspect complete nested maps, replace the final `map` with `identity`.
Treat packet `:bytes` arrays as read-only. Do not return a lazy stream from
`with-open`, or assume `(take 2 (core/packets ...))` closes a native source;
see [lazy capture lifetime](usage.md#lazy-capture-lifetime).

## Filter by address, port and protocol, then aggregate flows

Flow projection uses numeric fields: IPv4 `1.1.1.1` is unsigned integer
`16843009`, UDP is `17`, and TCP is `6`. Full decoding above uses address
strings and protocol keywords. Choose one representation for each analysis;
full decode and `:decode-mode :flow` are mutually exclusive.

<!-- paclo-doc-test: repl-flow -->

```clojure
(require '[paclo.core :as core] '[paclo.flow :as flow])

(let [server 16843009 ; 1.1.1.1, either direction
      selected? (fn [{:keys [protocol src-ip dst-ip src-port dst-port]}]
                  (and (= 17 protocol)
                       (or (= server src-ip) (= server dst-ip))
                       (or (= 53 src-port) (= 53 dst-port))))
      rf (flow/aggregate-rf {:direction :bidir :max-flows 100})
      report (core/reduce-packets-report
               {:path "test/resources/dns-sample.pcap"
                :max Long/MAX_VALUE :max-time-ms 60000
                :decode-mode :flow :xform (filter selected?)}
               rf (rf))]
  {:stop-reason (get-in report [:stats :stop-reason])
   :captured (get-in report [:stats :packets :captured])
   :summary (get-in report [:result :summary])
   :top (flow/top-n (:result report) {:n 5 :metric :captured-bytes})})
;; => {:stop-reason :eof, :captured 4,
;;     :summary {:seen 2, :aggregated 2, :skipped 0},
;;     :top [{:flow {:ip-version 4, :protocol 17,
;;                  :src-ip 16843009, :src-port 53,
;;                  :dst-ip 167772161, :dst-port 58555},
;;            :packets 2, :captured-bytes 260, :wire-bytes 260}]}
```

`:xform` runs after projection, before the reducer; `:seen` counts filtered
inputs, while capture statistics count source packets. `:bidir` combines both
directions using canonical endpoint order. Bytes mean captured length or wire
length as named. The reducer retains at most 100 flow keys and fails on overflow.
Change the predicate, bound and ranking for your input.

For native filtering, supply `:filter "host 1.1.1.1 and udp port 53"` instead
of `:xform`; the write example below exercises that equivalent selection.
These synchronous examples remove the default 100-packet limit and set an
explicit 60-second wall-clock budget instead of the default 10 seconds. Increase
that budget for larger inputs; check `:stop-reason` before treating a report as
complete. A transducer such as `take`, or a reducer returning `reduced`, stops
synchronous reads and closes their source immediately.

## Decode DNS and inspect transaction results

Select the annotation explicitly for each read. No global registration is
needed. This small fixture fits in memory; `packet->event` drops raw bytes,
and the pure analysis state bounds pending queries and retired keys separately.

<!-- paclo-doc-test: repl-dns -->

```clojure
(require '[paclo.core :as core] '[paclo.dns :as dns]
         '[paclo.proto.dns-ext :as dns-ext])

(let [events (core/reduce-packets
               {:path "test/resources/dns-sample.pcap"
                :max Long/MAX_VALUE :max-time-ms 60000
                :decode? true :extensions [dns-ext/annotate-dns]
                :xform (keep dns/packet->event)}
               conj [])
      initial (dns/init {:timeout-us 5000000 :max-pending 100 :max-retired 100})
      result (reduce (fn [{:keys [state transactions]} event]
                       (let [next (dns/step state event)]
                         {:state (:state next)
                          :transactions (into transactions (:events next))}))
                     {:state initial :transactions []} events)
      final (dns/finish (:state result))
      transactions (into (:transactions result) (:events final))]
  {:questions (mapv :qname (filter #(= :query (:kind %)) events))
   :transactions (mapv (fn [tx]
                         {:kind (:kind tx) :qname (get-in tx [:query :qname])
                          :rtt-us (:rtt-us tx) :rcode (get-in tx [:response :rcode])})
                       transactions)
   :pending (count (get-in final [:state :pending]))})
;; => {:questions ["example.com" "google.com"],
;;     :transactions [{:kind :match, :qname "example.com", :rtt-us 15817, :rcode 0}
;;                    {:kind :match, :qname "google.com", :rtt-us 10241, :rcode 0}],
;;     :pending 0}
```

RTT and timeout units are integer microseconds; rcode `0` means no error.
Inspect every transaction's `:kind`, including `:unfinished` from `finish`;
zero pending at finish does not imply every query received a response.
For this short replay no watermark is advanced, so unmatched queries finish as
`:unfinished` rather than `:timeout`. Longer inputs need caller-chosen monotonic
watermarks with `dns/advance` to expire queries and release retired keys, and
incremental consumption instead of collecting every event. See the
[DNS contract](cljdoc-api-contract.md#paclodns) and the existing
[bounded DNS reports](usage.md#bounded-dns-cli-reports-p07-b) for those policies.
Projection currently accepts standard unfragmented UDP/53 with at most one
question; `keep` omits ineligible packets. Missing questions produce diagnostics
instead of guessed matches.

## Write selected packets and read them back

Keep the original packet bytes and metadata for writing. Flow projection omits
`:bytes`, so reopen the source for a raw selection. This example uses a temporary
file, compares contents and metadata after reloading, and removes the file even
if an operation throws. Replace the temporary path/cleanup when saving an output.

<!-- paclo-doc-test: repl-roundtrip -->

```clojure
(require '[paclo.core :as core])

(let [selected (core/reduce-packets
                 {:path "test/resources/dns-sample.pcap"
                  :filter "host 1.1.1.1 and udp port 53"
                  :max Long/MAX_VALUE :max-time-ms 60000}
                 conj [])
      output (java.io.File/createTempFile "paclo-repl-" ".pcap")
      snapshot (fn [packet]
                 (assoc (select-keys packet [:ts-sec :ts-usec :caplen :len :linktype])
                        :bytes (vec (:bytes packet))))]
  (try
    (core/write-pcap! selected (.getPath output) {:linktype 1})
    (let [reloaded (core/reduce-packets
                     {:path (.getPath output)
                      :max Long/MAX_VALUE :max-time-ms 60000}
                     conj [])]
      {:packets (count reloaded)
       :captured-bytes (reduce + (map :caplen reloaded))
       :preserved? (= (mapv snapshot selected) (mapv snapshot reloaded))})
    (finally (java.nio.file.Files/deleteIfExists (.toPath output)))))
;; => {:packets 2, :captured-bytes 260, :preserved? true}
```

The fixture is Ethernet (`:linktype 1`); other single-DLT captures require their
matching native linktype and an adequate snaplen. The Classic PCAP writer can
overwrite its destination and can leave partial output on failure. It preserves
packet order, bytes, timestamps and lengths, including truncated records; it
does not preserve PCAPNG sections, interfaces or options. See the
[writer contract](cljdoc-api-contract.md#write-pcap) and
[PCAPNG guide](pcapng.md) for format-specific ownership and fidelity.
