import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;
import org.tron.tools.c025.C025Capture;

public final class C025Oracle {
  private C025Oracle() {}

  private static String hex(byte[] value) {
    StringBuilder result = new StringBuilder(value.length * 2);
    for (byte item : value) result.append(String.format("%02x", item & 0xff));
    return result.toString();
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 1) throw new IllegalArgumentException("expected exact-row evidence TSV");
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    Set<String> ids = new HashSet<String>();
    int tests = 0;
    int methods = 0;
    int declarations = 0;
    BufferedReader input = new BufferedReader(new InputStreamReader(
        new FileInputStream(args[0]), StandardCharsets.UTF_8));
    try {
      String line;
      while ((line = input.readLine()) != null) {
        String[] fields = line.split("\\t", -1);
        if (fields.length != 4 || !ids.add(fields[0])) {
          throw new IllegalStateException("malformed or duplicate evidence row: " + line);
        }
        if ("java_test_execution".equals(fields[1])) {
          if (!fields[3].contains("input=") || !fields[3].contains("output=") || !fields[3].contains("error=") || !fields[3].contains("effect=")) throw new IllegalStateException("incomplete Java test behavior: " + fields[0]);
          tests++;
        } else if ("production_method_execution".equals(fields[1])) {
          if (!fields[3].contains("input=") || !fields[3].contains("output=") || !fields[3].contains("error=") || !fields[3].contains("effect=")) throw new IllegalStateException("incomplete production behavior: " + fields[0]);
          methods++;
        } else if ("source_declaration".equals(fields[1])) {
          if (!fields[3].contains("immutable_declaration_sha256=") || !fields[3].contains("source_file_sha256=") || !fields[3].contains("declaration_kind=")) throw new IllegalStateException("incomplete declaration identity: " + fields[0]);
          declarations++;
        } else throw new IllegalStateException("unknown evidence kind: " + fields[1]);
        digest.update((line + "\n").getBytes(StandardCharsets.UTF_8));
        C025Capture.record(fields[0], fields[1], fields[2], fields[3]);
      }
    } finally {
      input.close();
    }
    if (ids.isEmpty() || C025Capture.snapshot().size() != ids.size()) {
      throw new IllegalStateException("empty or incomplete C025 capture");
    }
    System.out.println("C025_JAVA_TEST_EXECUTIONS=" + tests);
    System.out.println("C025_PRODUCTION_METHOD_EXECUTIONS=" + methods);
    System.out.println("C025_SOURCE_DECLARATIONS=" + declarations);
    System.out.println("C025_EXACT_ROWS=" + ids.size());
    System.out.println("C025_CENTRAL_SHA256=" + hex(digest.digest()));
  }
}
