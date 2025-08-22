package paclo.jnr;

import jnr.ffi.Struct;

public class BpfProgram extends Struct {
  public final Unsigned32      bf_len  = new Unsigned32();
  public final Struct.Pointer  bf_insn = new Struct.Pointer();

  public BpfProgram(jnr.ffi.Runtime r) { super(r); }

  /** Address to pass to libpcap functions (jnr.ffi.Pointer). */
  public jnr.ffi.Pointer addr() {
    return Struct.getMemory(this);
  }
}
