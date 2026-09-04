package org.tron.core.actuator;

import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import org.junit.runner.JUnitCore;
import org.junit.runner.Request;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

/** Runs selected pinned java-tron actuator tests; it never accepts expected observations. */
import org.tron.common.BaseTest;
public final class C012Oracle {
  private C012Oracle() {}

  private static String quote(String value) {
    StringBuilder out = new StringBuilder("\"");
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '\\': out.append("\\\\"); break;
        case '"': out.append("\\\""); break;
        case '\n': out.append("\\n"); break;
        case '\r': out.append("\\r"); break;
        case '\t': out.append("\\t"); break;
        default:
          if (c < 32) out.append(String.format("\\u%04x", (int) c));
          else out.append(c);
      }
    }
    return out.append('"').toString();
  }
  private static String hex(byte[] bytes) {
    char[] digits = "0123456789abcdef".toCharArray();
    char[] out = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      out[i * 2] = digits[(bytes[i] >>> 4) & 15];
      out[i * 2 + 1] = digits[bytes[i] & 15];
    }
    return new String(out);
  }

  private static boolean booleanField(String json, String name) {
    String marker = "\"" + name + "\"";
    int key = json.indexOf(marker);
    if (key < 0) return false;
    int colon = json.indexOf(':', key + marker.length());
    if (colon < 0) throw new IllegalArgumentException("invalid boolean field: " + name);
    String tail = json.substring(colon + 1).trim();
    if (tail.startsWith("true")) return true;
    if (tail.startsWith("false")) return false;
    throw new IllegalArgumentException("non-boolean field: " + name);
  }

  private static String captureJson(AbstractActuator.Capture capture) {
    org.tron.protos.Protocol.Transaction.Contract fullContract = capture.contract;
    String captureMode = "set_contract";
    if (fullContract == null) {
      fullContract = org.tron.protos.Protocol.Transaction.Contract.newBuilder()
          .setType(capture.constructorType).setParameter(capture.any).build();
      captureMode = "set_any_composed_with_constructor_type";
    }
    return "{\"actuator_identity\":" + quote(capture.actuatorClass)
        + ",\"capture_id\":" + capture.id
        + ",\"constructor_contract_type\":" + capture.constructorType.getNumber()
        + ",\"constructor_contract_type_name\":" + quote(capture.constructorType.name())
        + ",\"contract_capture_mode\":" + quote(captureMode)
        + ",\"contract_any_hex\":" + quote(hex(capture.any.toByteArray()))
        + ",\"contract_hex\":" + quote(hex(fullContract.toByteArray())) + "}";
  }

  private static String capturedRequest(boolean nonActuator, String testClassName) {
    List<AbstractActuator.Capture> populated = new ArrayList<>();
    for (AbstractActuator.Capture capture : AbstractActuator.snapshotC012Captures()) {
      if (capture.any != null || capture.contract != null) populated.add(capture);
    }
    Collections.sort(populated, Comparator.comparingLong(capture -> capture.id));
    if (nonActuator) {
      if (!populated.isEmpty()) {
        throw new IllegalStateException("explicit non-actuator case constructed a populated actuator");
      }
      return "{\"classification\":\"non_actuator\",\"actuator_identity\":null,"
          + "\"constructor_contract_type\":null,\"contract_any_hex\":null,\"contract_hex\":null,"
          + "\"all_captures\":[]}";
    }
    String expectedClass = testClassName.endsWith("Test")
        ? testClassName.substring(0, testClassName.length() - 4) : testClassName;
    List<AbstractActuator.Capture> matching = new ArrayList<>();
    for (AbstractActuator.Capture capture : populated) {
      if (capture.actuatorClass.equals(expectedClass)) matching.add(capture);
    }
    List<AbstractActuator.Capture> selectable = matching.isEmpty() ? populated : matching;
    if (selectable.isEmpty()) {
      throw new IllegalStateException("no populated actuator contract");
    }
    String selectedIdentity = selectable.get(0).actuatorClass;
    for (AbstractActuator.Capture capture : selectable) {
      if (!capture.actuatorClass.equals(selectedIdentity)) {
        throw new IllegalStateException("ambiguous actuator identities: "
            + selectedIdentity + "," + capture.actuatorClass);
      }
    }
    StringBuilder selectedContracts = new StringBuilder("[");
    for (int i = 0; i < selectable.size(); i++) {
      if (i != 0) selectedContracts.append(',');
      selectedContracts.append(captureJson(selectable.get(i)));
    }
    selectedContracts.append(']');
    StringBuilder all = new StringBuilder("[");
    for (int i = 0; i < populated.size(); i++) {
      if (i != 0) all.append(',');
      all.append(captureJson(populated.get(i)));
    }
    all.append(']');
    return "{\"classification\":\"actuator\",\"actuator_identity\":"
        + quote(selectedIdentity) + ",\"contracts\":" + selectedContracts
        + ",\"all_captures\":" + all + "}";
  }

  private static String field(String json, String name) {
    String marker = "\"" + name + "\"";
    int key = json.indexOf(marker);
    if (key < 0) throw new IllegalArgumentException("missing field: " + name);
    int colon = json.indexOf(':', key + marker.length());
    int start = json.indexOf('"', colon + 1);
    if (colon < 0 || start < 0) throw new IllegalArgumentException("non-string field: " + name);
    StringBuilder out = new StringBuilder();
    boolean escaped = false;
    for (int i = start + 1; i < json.length(); i++) {
      char c = json.charAt(i);
      if (escaped) {
        switch (c) {
          case 'n': out.append('\n'); break;
          case 'r': out.append('\r'); break;
          case 't': out.append('\t'); break;
          case '\\': case '"': out.append(c); break;
          default: throw new IllegalArgumentException("unsupported escape in " + name);
        }
        escaped = false;
      } else if (c == '\\') escaped = true;
      else if (c == '"') return out.toString();
      else out.append(c);
    }
    throw new IllegalArgumentException("unterminated field: " + name);
  }

  private static String failureJson(Failure failure) {
    Throwable error = failure.getException();
    return "{\"exception_class\":" + quote(error.getClass().getName())
        + ",\"message_utf8\":" + quote(error.getMessage() == null ? "" : error.getMessage()) + "}";
  }

  private static String run(Path requestPath) throws Exception {
    String json = new String(Files.readAllBytes(requestPath), StandardCharsets.UTF_8);
    String variant = field(json, "variant_id");
    String className = field(json, "java_test_class");
    String methodName = field(json, "java_test_method");
    boolean nonActuator = booleanField(json, "non_actuator");
    BaseTest.temporaryFolder.create();
    Class<?> testClass = Class.forName(className, true, C012Oracle.class.getClassLoader());
    if (testClass.getMethod(methodName).getParameterCount() != 0) {
      throw new IllegalArgumentException("test method takes arguments: " + className + "#" + methodName);
    }
    AbstractActuator.resetC012Captures();
    Result result = new JUnitCore().run(Request.method(testClass, methodName));
    List<Failure> failures = new ArrayList<>(result.getFailures());
    Collections.sort(failures, Comparator.comparing(Failure::toString));
    StringBuilder failureJson = new StringBuilder("[");
    for (int i = 0; i < failures.size(); i++) {
      if (i != 0) failureJson.append(',');
      failureJson.append(failureJson(failures.get(i)));
    }
    failureJson.append(']');
    return "{\"schema\":\"c012-java-test-observation-v2\",\"variant_id\":" + quote(variant)
        + ",\"java_test_class\":" + quote(className) + ",\"java_test_method\":" + quote(methodName)
        + ",\"run_count\":" + result.getRunCount() + ",\"ignore_count\":" + result.getIgnoreCount()
        + ",\"failure_count\":" + result.getFailureCount() + ",\"successful\":" + result.wasSuccessful()
        + ",\"failures\":" + failureJson + ",\"request_capture\":" + capturedRequest(nonActuator, className) + "}";
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 2 || !"--requests".equals(args[0])) {
      throw new IllegalArgumentException("usage: C012Oracle --requests REQUEST_DIR");
    }
    List<Path> requests = new ArrayList<>();
    try (DirectoryStream<Path> stream = Files.newDirectoryStream(Paths.get(args[1]), "*.json")) {
      for (Path path : stream) requests.add(path);
    }
    Collections.sort(requests, Comparator.comparing(path -> path.getFileName().toString()));
    StringBuilder output = new StringBuilder("{\"schema\":\"c012-java-test-batch-v2\",\"members\":[");
    for (int i = 0; i < requests.size(); i++) {
      if (i != 0) output.append(',');
      output.append(run(requests.get(i)));
    }
    output.append("]}\n");
    System.out.print(output);
    System.out.flush();
    Runtime.getRuntime().halt(0);
  }
}
