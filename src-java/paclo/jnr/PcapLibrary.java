package paclo.jnr;

import jnr.ffi.LibraryLoader;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import jnr.ffi.Runtime;
import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import jnr.ffi.byref.IntByReference;
import paclo.jnr.BpfProgram;
import paclo.jnr.PcapErrors;

/**
 * jnr-ffi interface for the libpcap APIs used by Paclo.
 * Includes small static helpers used from both Java and Clojure.
 */
public interface PcapLibrary {

  /** Shared singleton loader. */
  PcapLibrary INSTANCE = LibraryLoader.create(PcapLibrary.class).load("pcap");

  // open/close
  /**
   * Open offline pcap file.
   * @param fname file path
   * @param errbuf error buffer (PCAP_ERRBUF_SIZE)
   * @return pcap_t pointer or null on failure
   */
  Pointer pcap_open_offline(String fname, Pointer errbuf);

  /**
   * Open live capture.
   * @param device interface name
   * @param snaplen snapshot length
   * @param promisc promiscuous flag (1/0)
   * @param to_ms timeout milliseconds
   * @param errbuf error buffer
   * @return pcap_t pointer or null
   */
  Pointer pcap_open_live(String device, int snaplen, int promisc, int to_ms, Pointer errbuf);

  /**
   * Close pcap handle.
   * @param pcap pcap_t pointer
   */
  void    pcap_close(Pointer pcap);

  /**
   * Create a dead capture handle (for writing PCAPs).
   * @param linktype DLT_* link type
   * @param snaplen snapshot length
   * @return pcap_t pointer
   */
  Pointer pcap_open_dead(int linktype, int snaplen);

  // poll (no callback)
  /**
   * Non-callback packet fetch.
   * @param pcap pcap_t
   * @param headerRef out header pointer
   * @param dataRef out data pointer
   * @return 1=packet, 0=timeout, -1=error, -2=EOF
   */
  int     pcap_next_ex(Pointer pcap, PointerByReference headerRef, PointerByReference dataRef);

  // control
  /**
   * break loop
   * @param pcap handle to break out of loop
   */
  void    pcap_breakloop(Pointer pcap);

  // BPF
  /**
   * Compile BPF expression.
   * @param pcap handle
   * @param bpfProgram out struct pointer
   * @param expr filter expression
   * @param optimize 1/0
   * @param netmask netmask
   * @return 0 on success
   */
  int     pcap_compile(Pointer pcap, Pointer bpfProgram, String expr, int optimize, int netmask);

  /**
   * Set compiled filter.
   * @param pcap pcap_t pointer
   * @param bpfProgram compiled filter program
   * @return 0 on success
   */
  int     pcap_setfilter(Pointer pcap, Pointer bpfProgram);

  /**
   * Free compiled filter.
   * @param bpfProgram compiled filter program
   */
  void    pcap_freecode(Pointer bpfProgram);

  // misc
  /**
   * libpcap version string.
   * @return version string
   */
  String  pcap_lib_version();

  // dumper (pcap_dump_*)
  /**
   * Open dumper.
   * @param pcap pcap_t
   * @param fname output file path
   * @return dumper handle
   */
  Pointer pcap_dump_open(Pointer pcap, String fname);
  /**
   * Write packet via dumper.
   * @param dumper dumper handle
   * @param hdr packet header
   * @param data packet data
   */
  void    pcap_dump(Pointer dumper, Pointer hdr, Pointer data);
  /** Flush dumper.
   * @param dumper dumper handle
   */
  void    pcap_dump_flush(Pointer dumper);
  /** Close dumper.
   * @param dumper dumper handle
   */
  void    pcap_dump_close(Pointer dumper);

  /**
   * Get last error string from pcap handle.
   * @param pcap pcap_t pointer
   * @return last error string
   */
  String pcap_geterr(Pointer pcap);

  // struct helpers (minimal mapping)
  /** Minimal pcap_if struct mapping. */
  public static final class PcapIf extends jnr.ffi.Struct {
    /** next interface */
    @SuppressFBWarnings("URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD")
    public final jnr.ffi.Struct.Pointer  next = new jnr.ffi.Struct.Pointer();
    /** device name */
    @SuppressFBWarnings("URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD")
    public final jnr.ffi.Struct.Pointer  name = new jnr.ffi.Struct.Pointer();
    /** description */
    @SuppressFBWarnings("URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD")
    public final jnr.ffi.Struct.Pointer  desc = new jnr.ffi.Struct.Pointer();
    /** Construct struct with runtime.
     * @param r runtime
     */
    public PcapIf(jnr.ffi.Runtime r) { super(r); }
  }

  /**
   * find all devices.
   * @param alldevs out list
   * @param errbuf error buffer
   * @return 0 on success
   */
  int     pcap_findalldevs(jnr.ffi.byref.PointerByReference alldevs, jnr.ffi.Pointer errbuf);
  /** free device list.
   * @param alldevs device list pointer
   */
  void    pcap_freealldevs(jnr.ffi.Pointer alldevs);

  /**
   * lookup net and mask.
   * @param device interface name
   * @param netp out network
   * @param maskp out netmask
   * @param errbuf error buffer
   * @return 0 on success
   */
  int     pcap_lookupnet(String device, IntByReference netp, IntByReference maskp, Pointer errbuf);

  // ===== BPF convenience helpers =====
  /**
   * Compile filter and throw on error.
   * @param pcap handle
   * @param expr filter expression
   * @param optimize enable optimizer
   * @param netmask netmask
   * @return compiled BpfProgram
   */
  static BpfProgram compileFilter(Pointer pcap, String expr, boolean optimize, int netmask) {
    Runtime rt = Runtime.getRuntime(INSTANCE);
    BpfProgram prog = new BpfProgram(rt);
    int rc = INSTANCE.pcap_compile(pcap, prog.addr(), expr, optimize ? 1 : 0, netmask);
    if (rc != 0) {
      String msg = PcapErrors.lastError(pcap);
      throw new IllegalStateException("pcap_compile failed rc=" + rc + " expr=" + expr + " err=" + msg);
    }
    return prog;
  }

  /**
   * Set filter or throw IllegalStateException.
   * @param pcap handle
   * @param prog compiled program
   */
  static void setFilterOrThrow(Pointer pcap, BpfProgram prog) {
    int rc = INSTANCE.pcap_setfilter(pcap, prog.addr());
    if (rc != 0) {
      String msg = PcapErrors.lastError(pcap);
      throw new IllegalStateException("pcap_setfilter failed rc=" + rc + " err=" + msg);
    }
  }

  /**
   * Free filter program safely.
   * @param prog compiled program
   */
  static void freeFilter(BpfProgram prog) {
    INSTANCE.pcap_freecode(prog.addr());
  }
}
