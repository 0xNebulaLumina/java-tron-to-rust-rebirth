package org.tron.core.actuator;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.junit.runner.JUnitCore;
import org.junit.runner.Request;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;
import org.tron.common.BaseTest;
import org.tron.tools.c012.C012Capture;

/** Runs exactly one selected pinned java-tron method and serializes invocation capture. */
public final class C013Oracle {
  private C013Oracle() {}
  private static String field(String json,String name){String marker="\""+name+"\"";int k=json.indexOf(marker),c=json.indexOf(':',k+marker.length()),s=json.indexOf('\"',c+1);if(k<0||c<0||s<0)throw new IllegalArgumentException("missing string field "+name);StringBuilder b=new StringBuilder();boolean esc=false;for(int i=s+1;i<json.length();i++){char x=json.charAt(i);if(esc){if(x=='n')b.append('\n');else if(x=='r')b.append('\r');else if(x=='t')b.append('\t');else b.append(x);esc=false;}else if(x=='\\')esc=true;else if(x=='\"')return b.toString();else b.append(x);}throw new IllegalArgumentException("unterminated "+name);}
  private static Map<String,Object> failure(Failure f){Throwable t=f.getException();LinkedHashMap<String,Object>m=new LinkedHashMap<String,Object>();m.put("exception_class",t.getClass().getName());m.put("message_is_null",t.getMessage()==null);m.put("message",t.getMessage());return m;}
  public static void main(String[] args)throws Exception{
    if(args.length!=1)throw new IllegalArgumentException("usage: C013Oracle REQUEST.json");
    String request=new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8);
    String id=field(request,"variant_id"),className=field(request,"java_test_class"),method=field(request,"java_test_method");
    if(!id.equals(System.getProperty("c012.stable.id"))||!className.equals(System.getProperty("c012.test.class"))||!method.equals(System.getProperty("c012.test.method")))throw new IllegalStateException("agent/request mismatch");
    BaseTest.temporaryFolder.create();Class.forName("org.tron.core.actuator.AbstractActuator",true,C013Oracle.class.getClassLoader());Class<?> testClass=Class.forName(className,true,C013Oracle.class.getClassLoader());if(testClass.getMethod(method).getParameterCount()!=0)throw new IllegalArgumentException("test takes arguments");
    Result r=new JUnitCore().run(Request.method(testClass,method));ArrayList<Object> failures=new ArrayList<Object>();for(Failure f:r.getFailures())failures.add(failure(f));
    LinkedHashMap<String,Object> junit=new LinkedHashMap<String,Object>();junit.put("variant_id",id);junit.put("java_test_class",className);junit.put("java_test_method",method);junit.put("run_count",r.getRunCount());junit.put("ignore_count",r.getIgnoreCount());junit.put("failure_count",r.getFailureCount());junit.put("successful",r.wasSuccessful());junit.put("failures",failures);
    C012Capture.verify();System.out.print("C013_CAPTURE="+C012Capture.finishJson(junit)+"\n");System.out.flush();Runtime.getRuntime().halt(0);
  }
}
