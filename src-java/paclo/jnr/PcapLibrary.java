package paclo.jnr;

import jnr.ffi.LibraryLoader;
import jnr.ffi.Runtime;
import jnr.ffi.Pointer;
import jnr.ffi.Struct;
import jnr.ffi.byref.PointerByReference;
import jnr.ffi.byref.IntByReference;
import paclo.jnr.BpfProgram;
import paclo.jnr.PcapErrors;

/**
 * jnr-ffi 経由で libpcap の主要 API を公開するインターフェース。
 * Clojure 側からも直接呼べるよう、静的メソッドで安全ヘルパーを提供する。
 */
public interface PcapLibrary {

  /** libpcap ローダ（Clojure側からも直接使えるようにしておく） */
  PcapLibrary INSTANCE = LibraryLoader.create(PcapLibrary.class).load("pcap");

  // open/close
  Pointer pcap_open_offline(String fname, Pointer errbuf);
  Pointer pcap_open_live(String device, int snaplen, int promisc, int to_ms, Pointer errbuf);
  void    pcap_close(Pointer pcap);

  /** dead pcap_t を作る（生成PCAP用） */
  Pointer pcap_open_dead(int linktype, int snaplen);

  // poll (no callback)
  int     pcap_next_ex(Pointer pcap, PointerByReference headerRef, PointerByReference dataRef);

  // control
  void    pcap_breakloop(Pointer pcap);

  // BPF
  int     pcap_compile(Pointer pcap, Pointer bpfProgram, String expr, int optimize, int netmask);
  int     pcap_setfilter(Pointer pcap, Pointer bpfProgram);
  void    pcap_freecode(Pointer bpfProgram);

  // misc
  String  pcap_lib_version();

  // 追加: dumper（pcap_dump_*）
  Pointer pcap_dump_open(Pointer pcap, String fname);
  void    pcap_dump(Pointer dumper, Pointer hdr, Pointer data);
  void    pcap_dump_flush(Pointer dumper);
  void    pcap_dump_close(Pointer dumper);

  String pcap_geterr(Pointer pcap);

  // 構造体ヘルパー（最小限）
  public static final class PcapIf extends jnr.ffi.Struct {
    public final jnr.ffi.Struct.Pointer  next = new jnr.ffi.Struct.Pointer();
    public final jnr.ffi.Struct.Pointer  name = new jnr.ffi.Struct.Pointer();
    public final jnr.ffi.Struct.Pointer  desc = new jnr.ffi.Struct.Pointer();
    public PcapIf(jnr.ffi.Runtime r) { super(r); }
  }

  int     pcap_findalldevs(jnr.ffi.byref.PointerByReference alldevs, jnr.ffi.Pointer errbuf);
  void    pcap_freealldevs(jnr.ffi.Pointer alldevs);

  int     pcap_lookupnet(String device, IntByReference netp, IntByReference maskp, Pointer errbuf);

  // ===== BPF ヘルパー（利便性向上・例外で失敗がわかるように） =====
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

  static void setFilterOrThrow(Pointer pcap, BpfProgram prog) {
    int rc = INSTANCE.pcap_setfilter(pcap, prog.addr());
    if (rc != 0) {
      String msg = PcapErrors.lastError(pcap);
      throw new IllegalStateException("pcap_setfilter failed rc=" + rc + " err=" + msg);
    }
  }

  static void freeFilter(BpfProgram prog) {
    INSTANCE.pcap_freecode(prog.addr());
  }
}
