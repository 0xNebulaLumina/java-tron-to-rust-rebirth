import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.runner.JUnitCore;
import org.junit.runner.Request;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

/** Isolated pinned-Java JUnit method runner used by the guarded C027 oracle. */
public final class C027Oracle {
  private C027Oracle() {}

  private static String b64(String value) {
    return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private static void runCommand(String[] args) throws Exception {
    java.io.StringWriter stdout = new java.io.StringWriter();
    java.io.StringWriter stderr = new java.io.StringWriter();
    java.io.ByteArrayOutputStream globalOut = new java.io.ByteArrayOutputStream();
    java.io.ByteArrayOutputStream globalErr = new java.io.ByteArrayOutputStream();
    java.io.PrintStream originalOut = System.out;
    java.io.PrintStream originalErr = System.err;
    picocli.CommandLine command = new picocli.CommandLine(new org.tron.plugins.Toolkit());
    command.setOut(new java.io.PrintWriter(stdout, true));
    command.setErr(new java.io.PrintWriter(stderr, true));
    int code;
    try {
      System.setOut(new java.io.PrintStream(globalOut, true, "UTF-8"));
      System.setErr(new java.io.PrintStream(globalErr, true, "UTF-8"));
      if (args.length == 0) {
        command.usage(System.out);
        code = 0;
      } else {
        code = command.execute(args);
      }
    } finally {
      System.setOut(originalOut);
      System.setErr(originalErr);
    }
    String out = globalOut.toString("UTF-8") + stdout.toString();
    String err = globalErr.toString("UTF-8") + stderr.toString();
    originalOut.println("C027_COMMAND_RESULT|" + code + "|" + b64(out) + "|" + b64(err));
  }

  public static void main(String[] args) throws Exception {
    if (args.length > 0 && args[0].equals("--command")) {
      runCommand(java.util.Arrays.copyOfRange(args, 1, args.length));
      return;
    }
    if (args.length != 2) {
      throw new IllegalArgumentException("expected <test-class> <test-method>");
    }
    PrintStream originalOut = System.out;
    PrintStream originalErr = System.err;
    ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    ByteArrayOutputStream stderr = new ByteArrayOutputStream();
    Result result;
    try {
      System.setOut(new PrintStream(stdout, true, "UTF-8"));
      System.setErr(new PrintStream(stderr, true, "UTF-8"));
      Class<?> testClass = Class.forName(args[0]);
      result = new JUnitCore().run(Request.method(testClass, args[1]));
    } finally {
      System.setOut(originalOut);
      System.setErr(originalErr);
    }
    StringBuilder failures = new StringBuilder();
    for (Failure failure : result.getFailures()) {
      if (failures.length() != 0) failures.append('\n');
      failures.append(failure.toString()).append('\n').append(failure.getTrace());
    }
    originalOut.println("C027_RESULT"
        + "|" + result.wasSuccessful()
        + "|" + result.getRunCount()
        + "|" + result.getFailureCount()
        + "|" + result.getIgnoreCount()
        + "|" + b64(stdout.toString("UTF-8"))
        + "|" + b64(stderr.toString("UTF-8"))
        + "|" + b64(failures.toString()));
    System.exit(result.wasSuccessful() ? 0 : 1);
  }
}
