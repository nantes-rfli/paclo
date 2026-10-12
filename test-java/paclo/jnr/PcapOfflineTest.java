package paclo.jnr;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import org.junit.jupiter.api.Test;

/**
 * Basic integration test that opens a sample PCAP and reads one packet.
 */
public class PcapOfflineTest {

  @Test
  public void readFirstPacketFromSamplePcap() {
    Path pcap = Paths.get("test/resources/dns-sample.pcap").toAbsolutePath();
    assertTrue(Files.isRegularFile(pcap), "dns-sample.pcap should exist");

    try (PcapHandle handle = PcapHandle.openOffline(pcap.toString())) {
      PointerByReference hdrRef = new PointerByReference();
      PointerByReference dataRef = new PointerByReference();

      int rc = PcapLibrary.INSTANCE.pcap_next_ex(handle.pointer(), hdrRef, dataRef);
      assertEquals(1, rc, "pcap_next_ex should return 1 (packet)");

      Pointer hdr = hdrRef.getValue();
      assertNotNull(hdr, "header pointer");

      long caplen = PcapHeader.caplen(hdr);
      long len = PcapHeader.len(hdr);

      assertTrue(caplen > 0, "caplen > 0");
      assertTrue(len >= caplen, "len >= caplen");
      assertNotNull(dataRef.getValue(), "data pointer");
    }
  }
  @Test
  public void detectOfflineLinkTypes() {
    String[] fixtures = {"dns-sample.pcap", "linktype-sll.pcap", "linktype-null.pcap"};
    // These three DLT values agree on supported Linux and macOS platforms.
    int[] dlts = {1, 113, 0};
    for (int i = 0; i < fixtures.length; i++) {
      Path path = Paths.get("test/resources", fixtures[i]).toAbsolutePath();
      try (PcapHandle handle = PcapHandle.openOffline(path.toString())) {
        assertEquals(dlts[i], PcapLibrary.INSTANCE.pcap_datalink(handle.pointer()));
      }
    }
  }
  @Test
  public void inactiveHandleHasNoValidLinkType() {
    jnr.ffi.Runtime runtime = jnr.ffi.Runtime.getSystemRuntime();
    Pointer errbuf = jnr.ffi.Memory.allocateDirect(runtime, 256);
    String device = System.getProperty("os.name").contains("Mac") ? "lo0" : "lo";
    Pointer handle = PcapConfigLibrary.INSTANCE.pcap_create(device, errbuf);
    assertNotNull(handle);
    try {
      assertTrue(PcapLibrary.INSTANCE.pcap_datalink(handle) < 0);
    } finally {
      PcapLibrary.INSTANCE.pcap_close(handle);
    }
  }
}
