package paclo.jnr;

import static org.junit.jupiter.api.Assertions.assertEquals;

import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for portable pcap_stat offsets.
 */
public class PcapStatTest {

  @Test
  public void readsPortableUnsignedCounters() {
    Pointer stats = Memory.allocateDirect(
        Runtime.getSystemRuntime(), PcapStat.BUFFER_BYTES);
    stats.putInt(0, -1);
    stats.putInt(4, 2);
    stats.putInt(8, 3);

    assertEquals(0xffffffffL, PcapStat.received(stats));
    assertEquals(2L, PcapStat.dropped(stats));
    assertEquals(3L, PcapStat.interfaceDropped(stats));
  }
}
