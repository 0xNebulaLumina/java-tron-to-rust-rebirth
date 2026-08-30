import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.tron.common.crypto.SignInterface;
import org.tron.common.crypto.SignUtils;
import org.tron.keystore.Credentials;
import org.tron.keystore.Wallet;
import org.tron.keystore.WalletFile;
import org.tron.keystore.WalletUtils;
import org.tron.common.parameter.CommonParameter;

/** Executable C005 adapter over the pinned java-tron keystore implementation. */
public final class C005Oracle {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3";
  private static final String PASSWORD = "correct horse battery staple";
  private static final String PRIVATE = "0000000000000000000000000000000000000000000000000000000000000001";
  private static final String SALT = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  private static final String IV = "202122232425262728292a2b2c2d2e2f";
  private static final String UUID = "00112233-4455-4677-8899-aabbccddeeff";
  private static final String EC_ADDRESS = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC";
  private static final String SM2_ADDRESS = "TUAyHbMzdj2dMAJxfKK7KrubmQdARvF1GH";

  public static void main(String[] args) throws Exception {
    if (args.length == 0 || "manifest".equals(args[0])) {
      JSON.writeValue(System.out, manifest());
    } else if ("java-create".equals(args[0])) {
      JSON.writeValue(System.out, javaCreate(engine(args)));
    } else if ("java-open".equals(args[0])) {
      String walletJson = new String(Base64.getDecoder().decode(args[2]), StandardCharsets.UTF_8);
      JSON.writeValue(System.out, javaOpen(walletJson, engine(args)));
    } else {
      throw new IllegalArgumentException("unknown mode: " + args[0]);
    }
  }

  private static boolean engine(String[] args) {
    if (args.length < 2 || !("ec".equals(args[1]) || "sm2".equals(args[1]))) {
      throw new IllegalArgumentException("engine must be ec or sm2");
    }
    boolean ec = "ec".equals(args[1]);
    configureEngine(ec);
    return ec;
  }

  private static void configureEngine(boolean ec) {
    CommonParameter.getInstance().cryptoEngine = ec ? "ECKey" : "SM2";
  }

  private static Map<String, Object> manifest() throws Exception {
    Map<String, Object> root = map();
    root.put("schema_version", 1);
    root.put("java_revision", REVISION);
    Map<String, Object> inputs = map();
    inputs.put("password", PASSWORD); inputs.put("private_key_hex", PRIVATE);
    inputs.put("salt_hex", SALT); inputs.put("iv_hex", IV); inputs.put("uuid", UUID);
    root.put("deterministic_inputs", inputs);
    List<Map<String, Object>> rows = new ArrayList<>();
    rows.add(cross("C005.CROSS.SCRYPT.EC", "scrypt", true));
    rows.add(cross("C005.CROSS.SCRYPT.SM2", "scrypt", false));
    rows.add(cross("C005.CROSS.PBKDF2.EC", "pbkdf2", true));
    rows.add(cross("C005.CROSS.PBKDF2.SM2", "pbkdf2", false));
    rows.add(pbkdf2MissingDklen());
    rows.add(error("C005.ERROR.WRONG_PASSWORD", "decrypt", "Invalid password provided"));
    rows.add(error("C005.ERROR.VERSION", "schema", "Wallet version is not supported"));
    rows.add(versionIntegerOverflow());
    rows.add(error("C005.ERROR.MISSING_CRYPTO", "schema", "Missing crypto section"));
    rows.add(error("C005.ERROR.CIPHER", "schema", "Wallet cipher is not supported"));
    rows.add(error("C005.ERROR.KDF", "schema", "KDF type is not supported"));
    rows.add(error("C005.ERROR.PRF", "decrypt", "Unsupported prf:hmac-sha1"));
    rows.add(password("C005.PASSWORD.WHITESPACE", "  six words remain  "));
    rows.add(password("C005.PASSWORD.BOM", "\ufeffsecret\r\n"));
    rows.add(password("C005.PASSWORD.EMPTY", ""));
    rows.add(password("C005.PASSWORD.SHORT", "12345"));
    rows.add(decision("C005.PASSWORD.MULTILINE", "password_file", "java_source", "Java KeystoreCliUtils.readPassword rejects password files containing multiple lines."));
    rows.add(decision("C005.PASSWORD.MALFORMED_UTF8", "password_file", "rust_security_strengthening", "Java Scanner decoding is platform-configured; Rust defines deterministic UTF-8 lossy replacement."));
    String[] javaDirect = {"DIRECT.SYMLINK", "DIRECT.UNQUOTED", "DIRECT.CORRUPT", "WRITE.CLEANUP", "WRITE.MODE"};
    for (String id : javaDirect) rows.add(filesystem("C005." + id, "java_execution", javaFilesystemProbe(id)));
    String[] strengthened = {"NEW.INJECTED", "IMPORT.DUPLICATE", "IMPORT.OVERWRITE", "LIST.CORRUPT", "LIST.BOM", "LIST.MULTILINE", "LIST.SYMLINK", "LIST.PERMISSIONS", "LIST.OWNERSHIP", "UPDATE.PASSWORD", "UPDATE.WRONG_PASSWORD", "UPDATE.DUPLICATE", "UPDATE.SYMLINK_SWAP", "WINDOWS.LIMIT"};
    for (String id : strengthened) rows.add(filesystem("C005." + id, "rust_security_strengthening", filesystemDecision(id)));
    root.put("vectors", rows);
    return root;
  }

  private static Map<String, Object> cross(String id, String kdf, boolean ec) throws Exception {
    configureEngine(ec);
    String walletJson = deterministicWallet(kdf, ec);
    Map<String, Object> opened = javaOpen(walletJson, ec);
    if (!PRIVATE.equals(opened.get("private_key_hex"))) throw new AssertionError(id + " private key");
    Map<String, Object> row = map();
    row.put("id", id); row.put("kind", "cross_open"); row.put("direction", "rust_deterministic_create_to_java_open");
    row.put("java_api", "WalletUtils.loadCredentials/Credentials.getSignInterface");
    row.put("key_engine", ec ? "secp256k1" : "sm2"); row.put("checksum_engine", ec ? "secp256k1" : "sm2");
    row.put("kdf", kdf); row.put("private_key_hex", PRIVATE); row.put("wallet_json", walletJson);
    return row;
  }

  private static Map<String, Object> pbkdf2MissingDklen() throws Exception {
    configureEngine(true);
    String id = "C005.CROSS.PBKDF2.MISSING_DKLEN.EC";
    String walletJson = deterministicWallet("pbkdf2", true).replace("\"dklen\":32,", "");
    WalletFile file = JSON.readValue(walletJson, WalletFile.class);
    WalletFile.Aes128CtrKdfParams params = (WalletFile.Aes128CtrKdfParams) file.getCrypto().getKdfparams();
    if (params.getDklen() != 0) throw new AssertionError(id + " default dklen");
    Map<String, Object> opened = javaOpen(walletJson, true);
    if (!PRIVATE.equals(opened.get("private_key_hex"))) throw new AssertionError(id + " private key");
    Map<String, Object> row = map();
    row.put("id", id); row.put("kind", "cross_open"); row.put("direction", "pbkdf2_missing_dklen_java_and_rust_open");
    row.put("java_api", "ObjectMapper.readValue/WalletFile.Aes128CtrKdfParams.getDklen/WalletUtils.loadCredentials");
    row.put("key_engine", "secp256k1"); row.put("checksum_engine", "secp256k1"); row.put("kdf", "pbkdf2");
    row.put("java_default_dklen", params.getDklen()); row.put("private_key_hex", PRIVATE); row.put("wallet_json", walletJson);
    return row;
  }

  private static Map<String, Object> javaCreate(boolean ec) throws Exception {
    SignInterface sign = SignUtils.fromPrivate(hex(PRIVATE), ec);
    WalletFile wallet = Wallet.createLight(PASSWORD, sign);
    Path dir = Files.createTempDirectory("c005-java-create-");
    try {
      Path path = dir.resolve("wallet.json");
      WalletUtils.writeWalletFile(wallet, path.toFile());
      Credentials credentials = WalletUtils.loadCredentials(PASSWORD, path.toFile(), ec);
      Map<String, Object> out = map();
      out.put("direction", "java_random_create_to_rust_open");
      out.put("java_api", "Wallet.createLight/WalletUtils.writeWalletFile/WalletUtils.loadCredentials/Credentials");
      out.put("wallet_json", JSON.writeValueAsString(wallet));
      out.put("private_key_hex", hx(credentials.getSignInterface().getPrivateKey()));
      out.put("address", credentials.getAddress());
      return out;
    } finally { deleteTree(dir); }
  }

  private static Map<String, Object> javaOpen(String walletJson, boolean ec) throws Exception {
    Path dir = Files.createTempDirectory("c005-java-open-");
    try {
      Path path = dir.resolve("wallet.json");
      Files.write(path, walletJson.getBytes(StandardCharsets.UTF_8));
      Credentials credentials = WalletUtils.loadCredentials(PASSWORD, path.toFile(), ec);
      Map<String, Object> out = map();
      out.put("private_key_hex", hx(credentials.getSignInterface().getPrivateKey()));
      out.put("address", credentials.getAddress());
      return out;
    } finally { deleteTree(dir); }
  }

  private static Map<String, Object> error(String id, String kind, String expected) throws Exception {
    configureEngine(true);
    WalletFile file = JSON.readValue(deterministicWallet(id.contains("PRF") ? "pbkdf2" : "scrypt", true), WalletFile.class);
    String password = PASSWORD;
    if (id.endsWith("WRONG_PASSWORD")) password = "incorrect";
    else if (id.endsWith("VERSION")) file.setVersion(2);
    else if (id.endsWith("MISSING_CRYPTO")) file.setCrypto(null);
    else if (id.endsWith("CIPHER")) file.getCrypto().setCipher("aes-256-gcm");
    else if (id.endsWith("KDF")) file.getCrypto().setKdf("argon2");
    else if (id.endsWith("PRF")) ((WalletFile.Aes128CtrKdfParams) file.getCrypto().getKdfparams()).setPrf("hmac-sha1");
    String actual;
    try { Credentials.create(Wallet.decrypt(password, file, true)); throw new AssertionError(id + " unexpectedly succeeded"); }
    catch (org.tron.core.exception.CipherException e) { actual = e.getMessage(); }
    if (!expected.equals(actual)) throw new AssertionError(id + ": " + actual);
    Map<String, Object> row = map(); row.put("id", id); row.put("kind", kind); row.put("expected", actual); row.put("java_api", "Wallet.decrypt"); return row;
  }
  private static Map<String, Object> versionIntegerOverflow() throws Exception {
    String walletJson = deterministicWallet("scrypt", true).replace("\"version\":3", "\"version\":4294967299");
    String actual;
    try {
      JSON.readValue(walletJson, WalletFile.class);
      throw new AssertionError("C005.ERROR.VERSION_INT_OVERFLOW unexpectedly succeeded");
    } catch (com.fasterxml.jackson.core.JsonProcessingException error) {
      actual = error.getOriginalMessage();
    }
    if (!actual.contains("4294967299") || !actual.contains("out of range of int")) {
      throw new AssertionError("C005.ERROR.VERSION_INT_OVERFLOW: " + actual);
    }
    Map<String, Object> row = map();
    row.put("id", "C005.ERROR.VERSION_INT_OVERFLOW");
    row.put("kind", "schema_json");
    row.put("expected", actual);
    row.put("java_api", "ObjectMapper.readValue/WalletFile.setVersion(int)");
    row.put("wallet_json", walletJson);
    return row;
  }


  private static void openWithPassword(String walletJson, boolean ec, String password) throws Exception {
    WalletFile file = JSON.readValue(walletJson, WalletFile.class); Credentials.create(Wallet.decrypt(password, file, ec));
  }

  private static Map<String, Object> password(String id, String input) {
    String normalized = WalletUtils.stripPasswordLine(input);
    Map<String, Object> row = map(); row.put("id", id); row.put("kind", "password"); row.put("input", input);
    row.put("normalized", normalized); row.put("valid", WalletUtils.passwordValid(normalized)); row.put("java_api", "WalletUtils.stripPasswordLine/passwordValid"); return row;
  }

  private static String javaFilesystemProbe(String id) throws Exception {
    configureEngine(true);
    Path dir = Files.createTempDirectory("c005-java-fs-");
    try {
      Path target = dir.resolve("target.json"); Files.write(target, deterministicWallet("scrypt", true).getBytes(StandardCharsets.UTF_8));
      if ("DIRECT.SYMLINK".equals(id)) { Path link=dir.resolve("link.json"); Files.createSymbolicLink(link, target.getFileName()); WalletUtils.loadCredentials(PASSWORD, link.toFile(), true); return "WalletUtils.loadCredentials follows configured symlink after warning"; }
      if ("DIRECT.UNQUOTED".equals(id)) { String loose=deterministicWallet("scrypt", true).replaceFirst("\\{\\\"address\\\"", "{address"); Files.write(target, loose.getBytes(StandardCharsets.UTF_8)); WalletUtils.loadCredentials(PASSWORD, target.toFile(), true); return "WalletUtils.loadCredentials accepts unquoted field names"; }
      if ("DIRECT.CORRUPT".equals(id)) { Files.write(target, "{".getBytes(StandardCharsets.UTF_8)); try { WalletUtils.loadCredentials(PASSWORD,target.toFile(),true); } catch (com.fasterxml.jackson.core.JsonProcessingException expected) { return "WalletUtils.loadCredentials surfaces corrupt JSON"; } throw new AssertionError(id); }
      WalletFile wallet=JSON.readValue(deterministicWallet("scrypt",true),WalletFile.class); Path output=dir.resolve("out.json");
      if ("WRITE.MODE".equals(id)) { WalletUtils.writeWalletFile(wallet,output.toFile()); String mode=PosixFilePermissions.toString(Files.getPosixFilePermissions(output)); if (!"rw-------".equals(mode)) throw new AssertionError(mode); return "WalletUtils.writeWalletFile creates owner-read/write-only output"; }
      Files.createDirectory(output); try { WalletUtils.writeWalletFile(wallet,output.toFile()); } catch (Exception expected) { try (java.util.stream.Stream<Path> paths=Files.list(dir)) { if (paths.anyMatch(p->p.getFileName().toString().startsWith("keystore-"))) throw new AssertionError("temporary file leaked"); } return "WalletUtils.writeWalletFile removes temporary file after failed replace"; } throw new AssertionError(id);
    } finally { deleteTree(dir); }
  }

  private static String filesystemDecision(String id) {
    if (id.startsWith("LIST.")) return "Java has no secure directory-list API; Rust rejects symlinks/insecure ownership or mode and reports malformed entries explicitly.";
    if (id.startsWith("IMPORT.")) return "Java generateWalletFile replaces name collisions and has no duplicate-address/force policy; Rust separates duplicate force from overwrite.";
    if (id.startsWith("UPDATE.")) return "Java has no atomic password-update API; Rust uniquely resolves address, refuses symlink swaps, and preserves original bytes on failure.";
    if ("NEW.INJECTED".equals(id)) return "Java Wallet randomness is ambient SecureRandom; Rust supports injected randomness for deterministic verification without weakening production randomness.";
    return "Java non-POSIX permissions are best-effort and do not fsync the directory; Rust returns an explicit WindowsPermissionsBestEffort decision.";
  }

  private static Map<String, Object> filesystem(String id, String basis, String decision) { Map<String,Object> row=map(); row.put("id",id); row.put("kind","filesystem"); row.put("oracle_basis",basis); row.put("decision",decision); return row; }
  private static Map<String, Object> decision(String id,String kind,String basis,String text) { Map<String,Object> row=map();row.put("id",id);row.put("kind",kind);row.put("oracle_basis",basis);row.put("decision",text);return row; }

  private static String deterministicWallet(String kdf, boolean ec) {
    String address=ec?EC_ADDRESS:SM2_ADDRESS;
    String cipher=kdf.equals("scrypt")?"1f578b7cbed5ef355df449ab940dc3b6404c2422bb7a6588feeebeae34f21806":"791a2f36aa1ce0c4822e744ac3a1a8a7982dcb938e9ecf10a52dc038766bb5e8";
    String mac=kdf.equals("scrypt")?"270a215c9f282709e377ed53200dc6c9b25188dc3df04d8648f5c1b6e19b5e2f":"b99fa60132b61365e8ad323dbea6fe4f997616189b2047ccd0ccaceff21698e2";
    String params=kdf.equals("scrypt")?"{\"dklen\":32,\"n\":4096,\"p\":6,\"r\":8,\"salt\":\""+SALT+"\"}":"{\"c\":4096,\"dklen\":32,\"prf\":\"hmac-sha256\",\"salt\":\""+SALT+"\"}";
    return "{\"address\":\""+address+"\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\""+IV+"\"},\"ciphertext\":\""+cipher+"\",\"kdf\":\""+kdf+"\",\"kdfparams\":"+params+",\"mac\":\""+mac+"\"},\"id\":\""+UUID+"\",\"version\":3}";
  }
  private static byte[] hex(String s){byte[] out=new byte[s.length()/2];for(int i=0;i<out.length;i++)out[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16);return out;}
  private static String hx(byte[] b){StringBuilder out=new StringBuilder();for(byte x:b)out.append(String.format("%02x",x&255));return out.toString();}
  private static Map<String,Object> map(){return new LinkedHashMap<>();}
  private static void deleteTree(Path root)throws Exception{if(root==null||!Files.exists(root))return;try(java.util.stream.Stream<Path>s=Files.walk(root)){for(Path p:(Iterable<Path>)s.sorted(java.util.Comparator.reverseOrder())::iterator)Files.deleteIfExists(p);}}
}
