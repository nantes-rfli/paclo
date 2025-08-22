package paclo.jnr;

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import jnr.ffi.byref.IntByReference;

public interface PcapLibrary {
  // open/close
  Pointer pcap_open_offline(String fname, Pointer errbuf);
  Pointer pcap_open_live(String device, int snaplen, int promisc, int to_ms, Pointer errbuf);
  void    pcap_close(Pointer pcap);

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
}
