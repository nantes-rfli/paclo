package paclo.jnr;

import jnr.ffi.Pointer;

/** Helpers for retrieving libpcap error messages safely. */
public final class PcapErrors {
  private static final String NO_DETAIL = "(no detail)";

  private PcapErrors() { }

  /**
   * Return pcap_geterr text. Never throws; returns {@code (no detail)} on failure.
   *
   * @param pcap pcap_t pointer
   * @return error message or {@code "(no detail)"}
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
   * Return error text from an errbuf (e.g. second argument of pcap_open_offline).
   *
   * @param errbuf error buffer pointer
   * @return error message or {@code "(no detail)"}
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
