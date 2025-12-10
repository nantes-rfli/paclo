package paclo.jnr;

import static org.junit.jupiter.api.Assertions.assertEquals;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;
import org.junit.jupiter.api.Test;

class PcapHeaderTest {
  @Test
  void readsFieldsAtExpectedOffsets() {
    Runtime rt = Runtime.getSystemRuntime();
    Pointer hdr = Memory.allocate(rt, 24);

    hdr.putLong(0, 1234L);
    hdr.putLong(8, 5678L);
    hdr.putInt(16, 0x01020304);
    hdr.putInt(20, 0x05060708);

    assertEquals(1234L, PcapHeader.tv_sec(hdr));
    assertEquals(5678L, PcapHeader.tv_usec(hdr));
    assertEquals(0x01020304L, PcapHeader.caplen(hdr));
    assertEquals(0x05060708L, PcapHeader.len(hdr));
  }
}
