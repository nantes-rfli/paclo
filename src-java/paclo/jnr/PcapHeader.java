package paclo.jnr;

import jnr.ffi.Pointer;

/**
 * Offset-based helpers for reading fields from {@code struct pcap_pkthdr}.
 * This mapping assumes the common 64-bit layout used by libpcap.
 */
public final class PcapHeader {
  private static final boolean DARWIN =
      System.getProperty("os.name", "").startsWith("Mac");

  private PcapHeader() { }

  /**
   * timeval.tv_sec (8 bytes)
   *
   * @param hdr pcap_pkthdr pointer
   * @return seconds part of timestamp
   */
  public static long tv_sec(Pointer hdr) {
    return hdr.getLong(0);
  }

  /**
   * timeval.tv_usec (8 bytes on Linux, 4 bytes on Darwin)
   *
   * @param hdr pcap_pkthdr pointer
   * @return microseconds part of timestamp
   */
  public static long tv_usec(Pointer hdr) {
    /*
     * Darwin defines suseconds_t as int32 and pads struct timeval to 16 bytes.
     * Reading a long there includes uninitialized padding in the upper bits.
     */
    return DARWIN ? hdr.getInt(8) : hdr.getLong(8);
  }

  /**
   * caplen (4 bytes, unsigned)
   *
   * @param hdr pcap_pkthdr pointer
   * @return captured length (uint32)
   */
  public static long caplen(Pointer hdr) {
    return hdr.getInt(16) & 0xffffffffL;
  }

  /**
   * len (4 bytes, unsigned)
   *
   * @param hdr pcap_pkthdr pointer
   * @return original packet length (uint32)
   */
  public static long len(Pointer hdr) {
    return hdr.getInt(20) & 0xffffffffL;
  }
}
