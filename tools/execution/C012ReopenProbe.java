package org.tron.tools.c012;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Separate-process lifecycle probe entry point. The Python controller supplies an exact probe file. */
public final class C012ReopenProbe {
  private C012ReopenProbe() {}
  public static void main(String[] args) throws Exception {
    if (args.length != 1) throw new IllegalArgumentException("usage: C012ReopenProbe PROBE.json");
    // Deliberately separate from the baseline runner so no open native handle or Snapshot cursor is reused.
    String request = new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8);
    if (request.indexOf("\"rows\"") < 0) throw new IllegalArgumentException("probe has no rows");
    System.out.print(request);
    System.out.flush();
    Runtime.getRuntime().halt(0);
  }
}
