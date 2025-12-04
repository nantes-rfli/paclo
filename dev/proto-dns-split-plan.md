現在の方針（2025-12-04時点）
- リポ分割は行わず、`:dns-ext` alias で DNS 拡張をオプション読み込みする。
- JAR には DNS 拡張も同梱する（ライブラリ利用時は alias 不要）。
- 将来、拡張が増えて肥大化した場合に外出しを再検討する。

将来分割したくなった場合の簡易メモ
- 新artifact: `io.github.paclo/paclo-proto-dns`
- 移設対象: `extensions/dns/src/paclo/proto/dns_ext.clj`, `test/paclo/dns_ext_test.clj`, DNS用 test resources
- paclo 側は optional dep として参照し、examples/dns-* はその alias/deps を前提にする
- CI: clj -T:build test + cljdoc
- 公開: Clojars 0.1.x
