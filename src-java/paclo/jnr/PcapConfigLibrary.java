package paclo.jnr;

import jnr.ffi.LibraryLoader;
import jnr.ffi.Pointer;

/**
 * Optional libpcap create/activate API used for explicit live tuning.
 */
public interface PcapConfigLibrary {
  /** Shared singleton loader. */
  PcapConfigLibrary INSTANCE =
      LibraryLoader.create(PcapConfigLibrary.class).load("pcap");

  /**
   * Create an inactive capture handle.
   *
   * @param device capture device
   * @param errbuf error buffer
   * @return inactive handle or null
   */
  Pointer pcap_create(String device, Pointer errbuf);

  /** Set snapshot length before activation. */
  int pcap_set_snaplen(Pointer pcap, int snaplen);

  /** Set promiscuous mode before activation. */
  int pcap_set_promisc(Pointer pcap, int promiscuous);

  /** Set read timeout before activation. */
  int pcap_set_timeout(Pointer pcap, int timeoutMillis);

  /** Set capture-buffer bytes before activation. */
  int pcap_set_buffer_size(Pointer pcap, int bufferBytes);

  /** Set immediate mode before activation. */
  int pcap_set_immediate_mode(Pointer pcap, int immediate);

  /** Activate a configured capture handle. */
  int pcap_activate(Pointer pcap);
}
