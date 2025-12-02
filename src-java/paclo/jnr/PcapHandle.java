package paclo.jnr;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

/**
 * libpcap の pcap_t を安全に扱うための小さなラッパー。
 * AutoCloseable により try-with-resources で確実に close できる。
 */
public final class PcapHandle implements AutoCloseable {
  private static final int ERRBUF_SIZE = 256;

  private final Pointer pcap;
  private final Runtime rt;
  private boolean closed;

  private PcapHandle(Pointer pcap, Runtime rt) {
    this.pcap = pcap;
    this.rt = rt;
  }

  /** offline pcap を開く。失敗時は IllegalStateException を投げる。 */
  public static PcapHandle openOffline(String path) {
    Runtime rt = Runtime.getRuntime(PcapLibrary.INSTANCE);
    Pointer err = Memory.allocate(rt, ERRBUF_SIZE);
    Pointer pcap = PcapLibrary.INSTANCE.pcap_open_offline(path, err);
    if (pcap == null) {
      String msg = PcapErrors.fromErrbuf(err);
      throw new IllegalStateException("pcap_open_offline failed: " + msg);
    }
    return new PcapHandle(pcap, rt);
  }

  /** libpcap の pcap_t ポインタをそのまま返す。 */
  public Pointer pointer() {
    return pcap;
  }

  @Override
  public void close() {
    if (closed) return;
    closed = true;
    try {
      PcapLibrary.INSTANCE.pcap_close(pcap);
    } catch (Throwable ignore) {
      // best-effort
    }
  }
}
