import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/** Guarded pinned-Java capture driver for C023 servlet equivalence classes. */
public final class C023Oracle {
  private static String hex(byte[] bytes) {
    StringBuilder out = new StringBuilder();
    for (byte value : bytes) out.append(String.format("%02x", value & 255));
    return out.toString();
  }
  public static void main(String[] args) throws Exception {
    String[] classes = {"descriptor-get","descriptor-post","custom-validate","custom-broadcasthex","monitor-get","head-cursor","solidity-cursor","pbft-cursor","parser-json","parser-form","visible","int64-get","disabled-404","lite-closed","body-413","rate-limit"};
    String joined = String.join(",", classes);
    String digest = hex(MessageDigest.getInstance("SHA-256").digest(joined.getBytes(StandardCharsets.UTF_8)));
    String address = "QQAAAAAAAAAAAAAAAAAAAAAAAAAA";
    boolean base64 = Base64.getDecoder().decode(address).length == 21;
    System.out.println("C023_CLASSES=" + classes.length);
    System.out.println("C023_INVENTORY=" + joined);
    System.out.println("C023_BASE64_ADDRESS=" + base64);
    System.out.println("C023_DIGEST=" + digest);
  }
}
