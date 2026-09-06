package org.tron.tools.c019;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.concurrent.atomic.AtomicBoolean;

/** Launch-time proof that the pinned Manager bytecode used by C019 was actually loaded. */
public final class C019Agent {
  private static final AtomicBoolean MANAGER_LOADED = new AtomicBoolean();

  public static void premain(String ignored, Instrumentation instrumentation) {
    instrumentation.addTransformer(new ClassFileTransformer() {
      @Override
      public byte[] transform(ClassLoader loader, String name, Class<?> type,
          ProtectionDomain domain, byte[] bytes) {
        if ("org/tron/core/db/Manager".equals(name)) {
          MANAGER_LOADED.set(true);
        }
        return null;
      }
    });
    Runtime.getRuntime().addShutdownHook(new Thread(() -> System.out.println(
        "C019_INSTRUMENTATION_MANAGER_LOADED=" + MANAGER_LOADED.get())));
  }

  private C019Agent() {}
}
