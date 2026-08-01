(ns paclo.stream
  "Composable bounded fan-out for finite or externally cancellable streams.

  Fan-out handles and branches are opaque Closeable resources. Own them with
  `with-open`, consume each branch once, and use `stats` for distribution
  metrics. The public contract does not expose the internal queue backend."
  (:require
   [paclo.stream.impl :as impl]))

(defn- validate-public-branches!
  [branches]
  (when-not (and (map? branches) (<= 2 (count branches)))
    (throw (ex-info "stream fan-out requires at least two branches"
                    {:branches branches}))))

(defn fan-out
  "Start bounded distribution of every source value to named branches.

  `source` must be seqable. `branches` must be a map of at least two keyword
  IDs to configs. Every config requires `:buffer-mode` (`:blocking` or
  `:dropping`) and may set positive `:buffer-cap` (default 1024).

  Options:
  - `:cancel!` releases an externally waiting source during shutdown.
  - `:close-timeout-ms` bounds the dispatcher wait during close.

  Returns an opaque `java.io.Closeable` fan-out handle."
  ([source branches]
   (fan-out source branches {}))
  ([source branches opts]
   (validate-public-branches! branches)
   (impl/start source branches opts)))

(defn branch
  "Acquire a named single-consumer branch from `fanout`.

  A branch is opaque, Seqable, reducible, and `java.io.Closeable`. Each branch
  ID may be acquired once. Closing a branch does not close sibling branches."
  [fanout branch-id]
  (impl/branch fanout branch-id))

(defn stats
  "Return the data-only, schema-versioned distribution snapshot for `fanout`.

  The snapshot contains source, branch, buffer, drop, backpressure, lifecycle,
  and data-only error fields. Capture and application metrics remain separate."
  [fanout]
  (impl/stats fanout))
