package paclo.jnr;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

/**
 * Small AutoCloseable wrapper for a libpcap {@code pcap_t} pointer.
 * Use with try-with-resources to ensure {@code pcap_close} is called.
 */
public final class PcapHandle implements AutoCloseable {
  private static final int ERRBUF_SIZE = 256;

  private final Pointer pcap;
  private boolean closed;

  private PcapHandle(Pointer pcap) {
    this.pcap = pcap;
  }

  /**
   * Open an offline pcap file.
   *
   * @param path PCAP file path
   * @return PcapHandle (AutoCloseable)
   * @throws IllegalStateException when open fails
   */
  public static PcapHandle openOffline(String path) {
    Runtime rt = Runtime.getRuntime(PcapLibrary.INSTANCE);
    Pointer err = Memory.allocate(rt, ERRBUF_SIZE);
    Pointer pcap = PcapLibrary.INSTANCE.pcap_open_offline(path, err);
    if (pcap == null) {
      String msg = PcapErrors.fromErrbuf(err);
      throw new IllegalStateException("pcap_open_offline failed: " + msg);
    }
    return new PcapHandle(pcap);
  }

  /**
   * Underlying libpcap pointer.
   *
   * @return pointer to pcap_t
   */
  public Pointer pointer() {
    return pcap;
  }

  @Override
  public void close() {
    if (closed) {
      return;
    }
    closed = true;
    try {
      PcapLibrary.INSTANCE.pcap_close(pcap);
    } catch (Throwable ignore) {
      // best-effort
    }
  }
}
