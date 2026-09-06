package org.tron.tools.c025;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Deterministic append-only capture used by guarded C025 execution probes. */
public final class C025Capture {
  private static final List<String> EVENTS = Collections.synchronizedList(new ArrayList<String>());
  private C025Capture() {}
  public static void record(String id, String kind, String source, String observation) {
    EVENTS.add(id + "\t" + kind + "\t" + source + "\t" + observation);
  }
  public static List<String> snapshot() { synchronized (EVENTS) { return new ArrayList<String>(EVENTS); } }
  public static void reset() { EVENTS.clear(); }
}
