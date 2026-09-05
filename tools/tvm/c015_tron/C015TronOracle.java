import java.nio.file.*;
import java.util.regex.*;

/** Direct source oracle for the pinned java-tron PrecompiledContracts address/activation table. */
public final class C015TronOracle {
  public static void main(String[] args) throws Exception {
    String source = Files.readString(Path.of(args.length == 0
        ? "java-tron/actuator/src/main/java/org/tron/core/vm/PrecompiledContracts.java" : args[0]));
    Pattern address = Pattern.compile("private static final DataWord (\\w+)Addr = new DataWord\\(\\s*\"([0-9a-f]{64})\"\\)");
    Matcher matcher = address.matcher(source);
    while (matcher.find()) {
      String hex = matcher.group(2);
      long low = Long.parseUnsignedLong(hex.substring(56), 16);
      if (low == 9 || low == 10 || (low >= 0x1000005L && low <= 0x1000015L))
        System.out.println(matcher.group(1) + "," + hex.substring(56));
    }
  }
}
