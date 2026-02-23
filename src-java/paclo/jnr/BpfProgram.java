package paclo.jnr;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import jnr.ffi.Struct;

/**
 * jnr-ffi mapping of libpcap's {@code struct bpf_program}.
 * Implements {@link AutoCloseable} to make release explicit in Java code.
 */
@SuppressFBWarnings("URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD")
public class BpfProgram extends Struct implements AutoCloseable {
  /** instruction length (bf_len) */
  public final Unsigned32      bf_len  = new Unsigned32();
  /** pointer to instructions (bf_insn) */
  public final Struct.Pointer  bf_insn = new Struct.Pointer();

  private boolean closed;

  /**
   * Construct a BpfProgram struct bound to the given runtime.
   *
   * @param r jnr runtime
   */
  public BpfProgram(jnr.ffi.Runtime r) { super(r); }

  /**
   * Address to pass to libpcap functions (jnr.ffi.Pointer).
   *
   * @return pointer to the underlying struct memory
   */
  public jnr.ffi.Pointer addr() {
    return Struct.getMemory(this);
  }

  @Override
  public void close() {
    if (closed) {
      return;
    }
    closed = true;
    try {
      PcapLibrary.freeFilter(this);
    } catch (Throwable ignore) {
      // best-effort: libpcap may already have freed; avoid throwing on close
    }
  }
}
