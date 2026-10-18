package paclo.jnr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import jnr.ffi.byref.PointerByReference;
import org.junit.jupiter.api.Test;

/** Real native ABI checks, shared by supported and experimental JDK runs. */
class PcapNativeCompatibilityTest {
  private static final String FIXTURE = "test/resources/dns-sample.pcap";

  @Test
  void nativeHeadersAgreeWithPhysicalRecordsThroughEof() throws IOException {
    ByteBuffer disk = ByteBuffer.wrap(Files.readAllBytes(Path.of(FIXTURE)))
        .order(ByteOrder.LITTLE_ENDIAN);
    assertEquals(0xa1b2c3d4, disk.getInt());
    disk.position(24);
    try (PcapHandle handle = PcapHandle.openOffline(FIXTURE)) {
      PointerByReference header = new PointerByReference();
      PointerByReference data = new PointerByReference();
      int count = 0;
      while (disk.hasRemaining()) {
        long seconds = Integer.toUnsignedLong(disk.getInt());
        long micros = Integer.toUnsignedLong(disk.getInt());
        int caplen = disk.getInt();
        long length = Integer.toUnsignedLong(disk.getInt());
        assertEquals(1, PcapLibrary.INSTANCE.pcap_next_ex(handle.pointer(), header, data));
        assertEquals(seconds, PcapHeader.tv_sec(header.getValue()));
        assertEquals(micros, PcapHeader.tv_usec(header.getValue()));
        assertEquals(caplen, PcapHeader.caplen(header.getValue()));
        assertEquals(length, PcapHeader.len(header.getValue()));
        byte[] actual = new byte[caplen];
        data.getValue().get(0, actual, 0, caplen);
        byte[] expected = new byte[caplen];
        disk.get(expected);
        org.junit.jupiter.api.Assertions.assertArrayEquals(expected, actual);
        count++;
      }
      assertEquals(4, count);
      assertEquals(-2, PcapLibrary.INSTANCE.pcap_next_ex(handle.pointer(), header, data));
    }
  }

  @Test
  void nativeBpfStructCompilesFiltersAndClosesTwice() {
    try (PcapHandle handle = PcapHandle.openOffline(FIXTURE)) {
      BpfProgram program = PcapLibrary.compileFilter(handle.pointer(), "tcp", true, 0);
      try {
        assertTrue(program.bf_len.get() > 0);
        assertNotNull(program.bf_insn.get());
        PcapLibrary.setFilterOrThrow(handle.pointer(), program);
      } finally {
        program.close();
        program.close();
      }
      assertEquals(-2, PcapLibrary.INSTANCE.pcap_next_ex(
          handle.pointer(), new PointerByReference(), new PointerByReference()));
      IllegalStateException error = assertThrows(IllegalStateException.class,
          () -> PcapLibrary.compileFilter(handle.pointer(), "udp and (", true, 0));
      assertTrue(error.getMessage().contains("pcap_compile failed"));
    }
  }

  @Test
  void failedOpenRetainsNativeErrorAndValidHandleStillWorks() {
    IllegalStateException error = assertThrows(IllegalStateException.class,
        () -> PcapHandle.openOffline(FIXTURE + ".missing"));
    assertTrue(error.getMessage().startsWith("pcap_open_offline failed: "));
    PcapHandle handle = PcapHandle.openOffline(FIXTURE);
    try {
      assertNotNull(handle.pointer());
    } finally {
      handle.close();
      handle.close();
    }
  }
}
