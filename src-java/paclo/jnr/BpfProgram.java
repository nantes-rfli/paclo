package paclo.jnr;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import jnr.ffi.Struct;

/**
 * libpcap の struct bpf_program を jnr-ffi で表現したもの。
 * AutoCloseable を実装し、フィルタ解放忘れを防ぐ。
 */
@SuppressFBWarnings("URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD")
public class BpfProgram extends Struct implements AutoCloseable {
  public final Unsigned32      bf_len  = new Unsigned32();
  public final Struct.Pointer  bf_insn = new Struct.Pointer();

  private boolean closed;

  public BpfProgram(jnr.ffi.Runtime r) { super(r); }

  /** Address to pass to libpcap functions (jnr.ffi.Pointer). */
  public jnr.ffi.Pointer addr() {
    return Struct.getMemory(this);
  }

  @Override
  public void close() {
    if (closed) return;
    closed = true;
    try {
      PcapLibrary.freeFilter(this);
    } catch (Throwable ignore) {
      // best-effort: libpcap may already have freed; avoid throwing on close
    }
  }
}
