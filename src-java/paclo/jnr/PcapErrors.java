package paclo.jnr;

import jnr.ffi.Pointer;

/** libpcap エラーメッセージの取得を一元化するヘルパー。 */
public final class PcapErrors {
  private static final String NO_DETAIL = "(no detail)";

  private PcapErrors() { }

  /**
   * pcap_geterr の結果を返す。例外安全で、失敗時は (no detail) を返す。
   *
   * @param pcap pcap_t ポインタ
   * @return エラーメッセージまたは "(no detail)"
   */
  public static String lastError(Pointer pcap) {
    if (pcap == null) {
      return NO_DETAIL;
    }
    try {
      String msg = PcapLibrary.INSTANCE.pcap_geterr(pcap);
      return (msg == null || msg.isEmpty()) ? NO_DETAIL : msg;
    } catch (Throwable ignore) {
      return NO_DETAIL;
    }
  }

  /**
   * errbuf（pcap_open_offline などの第二引数）から文字列を取り出す。
   *
   * @param errbuf エラーバッファ
   * @return エラーメッセージまたは "(no detail)"
   */
  public static String fromErrbuf(Pointer errbuf) {
    if (errbuf == null) {
      return NO_DETAIL;
    }
    try {
      String msg = errbuf.getString(0);
      return (msg == null || msg.isEmpty()) ? NO_DETAIL : msg.trim();
    } catch (Throwable ignore) {
      return NO_DETAIL;
    }
  }
}
