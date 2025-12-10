package paclo.jnr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;
import org.junit.jupiter.api.Test;

class PcapErrorsAndHandleTest {
  @Test
  void fromErrbufReturnsTrimmedMessage() {
    Runtime rt = Runtime.getSystemRuntime();
    Pointer errbuf = Memory.allocate(rt, 64);
    errbuf.putString(0, "pcap-error\n", 64, StandardCharsets.UTF_8);

    assertEquals("pcap-error", PcapErrors.fromErrbuf(errbuf));
  }

  @Test
  void fromErrbufNullFallbacksToNoDetail() {
    assertEquals("(no detail)", PcapErrors.fromErrbuf(null));
  }

  @Test
  void lastErrorNullReturnsNoDetail() {
    assertEquals("(no detail)", PcapErrors.lastError(null));
  }

  @Test
  void openOfflineReturnsHandleAndClosesSafely() {
    Path pcapPath = Path.of("test/resources/dns-sample.pcap").toAbsolutePath();
    if (!Files.exists(pcapPath)) {
      throw new IllegalStateException("Missing test pcap: " + pcapPath);
    }

    try (PcapHandle handle = PcapHandle.openOffline(pcapPath.toString())) {
      assertNotNull(handle.pointer());
    }
  }
}
