package paclo.jnr;

import jnr.ffi.Pointer;

/**
 * C stdio error inspection for libpcap dumpers on supported Linux/macOS runtimes.
 * The stream returned by pcap_dump_file belongs to libpcap; never close it here.
 */
public interface PcapStdioLibrary {
  /**
   * Inspect the stream's sticky error indicator, including earlier failed writes.
   * @param stream FILE pointer owned by the libpcap dumper
   * @return nonzero when an I/O error occurred, zero otherwise
   */
  int ferror(Pointer stream);
}
