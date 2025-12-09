package paclo.jnr;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Simple self-check to ensure JUnit discovery works in CI.
 */
public class JunitSelfTest {

  @Test
  public void junitDiscoveryWorks() {
    assertTrue(true);
  }
}
