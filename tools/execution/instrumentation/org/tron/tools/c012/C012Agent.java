package org.tron.tools.c012;

import java.lang.instrument.Instrumentation;

/** Java 8 premain: installs the transformer before any java-tron class is loaded. */
public final class C012Agent {
  private C012Agent() {}
  public static void premain(String ignored, Instrumentation instrumentation) {
    String testClass=required("c012.test.class"), testMethod=required("c012.test.method");
    instrumentation.addTransformer(new C012Transformer(testClass,testMethod),false);
  }
  private static String required(String name){String value=System.getProperty(name);if(value==null||value.isEmpty())throw new IllegalArgumentException("missing -D"+name);return value;}
}
