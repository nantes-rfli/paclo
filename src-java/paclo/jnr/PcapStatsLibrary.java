package paclo.jnr;

import jnr.ffi.LibraryLoader;
import jnr.ffi.Pointer;

/**
 * Small libpcap binding kept separate from {@link PcapLibrary} so existing
 * test doubles for the main API do not need to implement optional statistics.
 */
public interface PcapStatsLibrary {
  /** Shared singleton loader. */
  PcapStatsLibrary INSTANCE =
      LibraryLoader.create(PcapStatsLibrary.class).load("pcap");

  /**
   * Read live-capture statistics.
   *
   * @param pcap live pcap handle
   * @param stats writable native buffer for struct pcap_stat
   * @return zero on success, negative on failure
   */
  int pcap_stats(Pointer pcap, Pointer stats);
}
