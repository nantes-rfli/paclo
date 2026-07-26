package paclo.jnr;

import jnr.ffi.Pointer;

/**
 * Offset-based helpers for the portable fields in {@code struct pcap_stat}.
 *
 * <p>libpcap guarantees that the first three fields are unsigned 32-bit
 * counters. Some platforms append private fields, so callers allocate a
 * conservatively sized native buffer and only read the portable prefix.</p>
 */
public final class PcapStat {
  /** Size of the portable prefix in bytes. */
  public static final int PORTABLE_BYTES = 12;

  /** Conservative buffer size for platform-specific trailing fields. */
  public static final int BUFFER_BYTES = 64;

  private PcapStat() { }

  /**
   * Packets received by the capture mechanism.
   *
   * @param stats pcap_stat pointer
   * @return unsigned receive count
   */
  public static long received(Pointer stats) {
    return stats.getInt(0) & 0xffffffffL;
  }

  /**
   * Packets dropped by the capture mechanism.
   *
   * @param stats pcap_stat pointer
   * @return unsigned drop count
   */
  public static long dropped(Pointer stats) {
    return stats.getInt(4) & 0xffffffffL;
  }

  /**
   * Packets dropped by the network interface, when supported.
   *
   * @param stats pcap_stat pointer
   * @return unsigned interface drop count
   */
  public static long interfaceDropped(Pointer stats) {
    return stats.getInt(8) & 0xffffffffL;
  }
}
