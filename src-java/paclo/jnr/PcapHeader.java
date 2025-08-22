package paclo.jnr;

import jnr.ffi.Pointer;

/** pcap_pkthdr をオフセットで読むだけの超軽量ヘルパー（macOS/64bit前提） */
public final class PcapHeader {
  private PcapHeader() {}

  /** timeval.tv_sec (8 bytes) */
  public static long tv_sec(Pointer hdr)  { return hdr.getLong(0); }

  /** timeval.tv_usec (8 bytes) */
  public static long tv_usec(Pointer hdr) { return hdr.getLong(8); }

  /** caplen (4 bytes, unsigned) */
  public static long caplen(Pointer hdr)  { return hdr.getInt(16) & 0xffffffffL; }

  /** len (4 bytes, unsigned) */
  public static long len(Pointer hdr)     { return hdr.getInt(20) & 0xffffffffL; }
}
