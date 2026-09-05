import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.security.MessageDigest;

/** Checks the pinned java-tron P256 resource before Rust fixture generation. */
public final class C015StandardOracle {
  public static void main(String[] args) throws Exception {
    if (args.length != 1) throw new IllegalArgumentException("p256verify_test_vectors.json path required");
    File source = new File(args[0]);
    byte[] bytes = java.nio.file.Files.readAllBytes(source.toPath());
    JsonNode rows = new ObjectMapper().readTree(bytes);
    if (!rows.isArray() || rows.size() != 782) throw new AssertionError("expected 782 records");
    for (JsonNode row : rows) {
      if (row.path("Gas").asLong() != 6900 || row.path("Input").asText().length() != 320) {
        throw new AssertionError(row.path("Name").asText());
      }
    }
    System.out.printf("records=%d sha256=%s%n", rows.size(), java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));
  }
}
