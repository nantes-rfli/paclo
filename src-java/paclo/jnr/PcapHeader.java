package paclo.jnr;

import jnr.ffi.Pointer;

/**
 * pcap_pkthdr を直接オフセットで読むための軽量ヘルパー。
 * macOS/64bit でのオフセットを前提とし、長さは unsigned として扱う。
 */
public final class PcapHeader {
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
   * timeval.tv_usec (8 bytes)
   *
   * @param hdr pcap_pkthdr pointer
   * @return microseconds part of timestamp
   */
  public static long tv_usec(Pointer hdr) {
    return hdr.getLong(8);
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
