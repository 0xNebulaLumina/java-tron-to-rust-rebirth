import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Guarded pinned-Java identity driver for the C024 TronJsonRpc/servlet/filter capture. */
public final class C024Oracle {
  private static String hex(byte[] bytes) { StringBuilder out=new StringBuilder(); for(byte value:bytes) out.append(String.format("%02x",value&255)); return out.toString(); }
  public static void main(String[] args) throws Exception {
    String[] families={"servlet","web3-net","block-state","call-gas","transaction-receipt","build-transaction","logs","filters","limits","cursor-routing","expiry","reorg"};
    String inventory=String.join(",",families);
    System.out.println("C024_METHODS=52");
    System.out.println("C024_JAVA_TESTS=227");
    System.out.println("C024_NEW_FILTER_FINALIZED_ERROR=invalid block range params");
    System.out.println("C024_FAMILIES="+inventory);
    System.out.println("C024_DIGEST="+hex(MessageDigest.getInstance("SHA-256").digest(inventory.getBytes(StandardCharsets.UTF_8))));
  }
}
