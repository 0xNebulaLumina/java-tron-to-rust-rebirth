import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.tron.plugins.ArchiveManifest;
import org.tron.plugins.DbLite;
import org.tron.plugins.utils.DBUtils;
import org.tron.plugins.utils.db.DBInterface;
import org.tron.plugins.utils.db.DBIterator;
import org.tron.plugins.utils.db.DbTool;
import org.tron.protos.Protocol;
import picocli.CommandLine;

/** Deterministic, guarded direct-fixture oracle for the fifteen C027 stable rows. */
public final class C027DirectOracle {
  private static final String[] STORES = {"block", "block-index", "trans",
      "transactionRetStore", "transactionHistoryStore", "properties", "account",
      "balance-trace", "account-trace"};
  private static final String[] ARCHIVE_STORES = {"block", "block-index", "trans",
      "transactionRetStore", "transactionHistoryStore"};
  private static final Map<String, Case> CASES = cases();
  private static final Pattern ELAPSED = Pattern.compile("(?i)(take|use) \\d+ (ms|s|seconds)");

  private C027DirectOracle() {}

  private static final class Case {
    final String id;
    final String scenario;
    final String family;
    final String engine;
    final int checkpoint;
    final boolean excludeTrace;
    Case(String id, String scenario, String family, String engine, int checkpoint,
        boolean excludeTrace) {
      this.id = id; this.scenario = scenario; this.family = family; this.engine = engine;
      this.checkpoint = checkpoint; this.excludeTrace = excludeTrace;
    }
  }

  private static Map<String, Case> cases() {
    Map<String, Case> m = new LinkedHashMap<>();
    add(m, "TCASE-07830A292D3A80E9", "LITE_LEVELDB_CP_V1", "lite", "LEVELDB", 1, false);
    add(m, "TCASE-CA377A3F0CCDED17", "LITE_LEVELDB_CP_V2", "lite", "LEVELDB", 2, false);
    add(m, "TCASE-73568EC3033FC84A", "LITE_ROCKSDB_CP_V1", "lite", "ROCKSDB", 1, false);
    add(m, "TCASE-1FDB8C6B77896021", "LITE_ROCKSDB_CP_V2", "lite", "ROCKSDB", 2, false);
    add(m, "TCASE-3B94179296286BCD", "LITE_ROCKSDB_CP_V1_EXCLUDE_TRACE", "lite", "ROCKSDB", 1, true);
    archive(m, "TCASE-33EEDFFAB5FC8144", "ArchiveManifest", "run_m0");
    archive(m, "TCASE-D4165B20F5BBC217", "ArchiveManifest", "help");
    archive(m, "TCASE-892F022C31111AF5", "ArchiveManifest", "m128");
    archive(m, "TCASE-B532B3C191E369CE", "ArchiveManifest", "missing");
    archive(m, "TCASE-3A01FB6DB1A5BBF4", "ArchiveManifest", "empty");
    archive(m, "TCASE-383C2B80F66DB9F7", "DbArchive", "run_m0");
    archive(m, "TCASE-AD54D4A6DCF4213B", "DbArchive", "help");
    archive(m, "TCASE-192ACD8D077B5743", "DbArchive", "m128");
    archive(m, "TCASE-14BCC78F75EA5FB8", "DbArchive", "missing");
    archive(m, "TCASE-6B5CB0A372F3CC1E", "DbArchive", "empty");
    Map<String, Case> byName = new LinkedHashMap<>();
    for (Case c : m.values()) {
      byName.put(c.id, c);
      byName.put(c.scenario, c);
    }
    return Collections.unmodifiableMap(byName);
  }

  private static void add(Map<String, Case> m, String id, String scenario, String family,
      String engine, int checkpoint, boolean exclude) {
    m.put(id, new Case(id, scenario, family, engine, checkpoint, exclude));
  }
  private static void archive(Map<String, Case> m, String id, String family, String scenario) {
    add(m, id, family + "_" + scenario, family, "MIXED", 0, false);
  }

  /**
   * Machine interface: C027DirectOracle SCENARIO_OR_STABLE_ID PRIVATE_EMPTY_SANDBOX.
   * The launcher must supply -Dc027.java.identity.id=FULL_GUARDED_CLASSPATH_ID.
   * Exactly one final stdout line is emitted: C027_DIRECT=BASE64(CANONICAL_JSON).
   */
  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      throw new IllegalArgumentException("expected SCENARIO_OR_STABLE_ID PRIVATE_EMPTY_SANDBOX");
    }
    Case c = CASES.get(args[0]);
    if (c == null) throw new IllegalArgumentException("unknown C027 direct case: " + args[0]);
    String identity = requiredProperty("c027.java.identity.id");
    Path root = Paths.get(args[1]).toAbsolutePath().normalize();
    requireEmptyDirectory(root);
    Map<String, Object> result;
    try {
      result = "lite".equals(c.family) ? runLite(c, root, identity) : runArchive(c, root, identity);
    } finally {
      DbLite.reSetRecentBlks();
      DbTool.close();
    }
    String encoded = Base64.getEncoder().encodeToString(json(result).getBytes(StandardCharsets.UTF_8));
    System.out.println("C027_DIRECT=" + encoded);
  }

  private static Map<String, Object> runLite(Case c, Path root, String identity) throws Exception {
    Path full = root.resolve("full");
    Path dataset = root.resolve("dataset");
    Files.createDirectory(full);
    Files.createDirectory(dataset);
    seedLite(full, c.engine, c.checkpoint);
    DbLite.setRecentBlks(3);
    List<Object> observations = new ArrayList<>();
    observations.add(executeLite(root, new String[] {"-o", "split", "-t", "snapshot", "-fn",
        full.toString(), "-ds", dataset.toString()}, c.excludeTrace));
    DbTool.close();
    assertLiteState(logicalState(dataset.resolve("snapshot")), Arrays.asList(0L, 3L, 4L, 5L),
        true, c.excludeTrace, "snapshot");
    addLaterHistory(full, c.engine);
    observations.add(executeLite(root, new String[] {"-o", "split", "-t", "history", "-fn",
        full.toString(), "-ds", dataset.toString()}, false));
    DbTool.close();
    assertLiteState(logicalState(dataset.resolve("history")),
        Arrays.asList(0L,1L,2L,3L,4L,5L,6L,7L), false, true, "history");
    observations.add(executeLite(root, new String[] {"-o", "merge", "-fn",
        dataset.resolve("snapshot").toString(), "-ds", dataset.resolve("history").toString()}, false));
    DbTool.close();
    assertLiteState(logicalState(dataset.resolve("snapshot")),
        Arrays.asList(0L,1L,2L,3L,4L,5L), true, c.excludeTrace, "merge");
    Map<String, Object> out = base(c, identity);
    out.put("observations", observations);
    out.put("final_state", logicalState(dataset.resolve("snapshot")));
    out.put("final_tree_hash", treeHash(root));
    out.put("effects", effectsLite(dataset.resolve("snapshot"), c.excludeTrace));
    return out;
  }

  private static Map<String, Object> executeLite(Path root, String[] argv, boolean exclude)
      throws Exception {
    List<String> actual = new ArrayList<>(Arrays.asList(argv));
    if (exclude) actual.add("--exclude-historical-balance");
    Map<String, Object> before = logicalState(root);
    String treeBefore = treeHash(root);
    Capture cap = capture(new Invokable() {
      public int run() { return new CommandLine(new DbLite()).execute(actual.toArray(new String[0])); }
    }, root);
    DbTool.close();
    Map<String, Object> row = new LinkedHashMap<>();
    row.put("argv", normalizeArgs(actual, root));
    require(cap.code == 0, "DbLite command failed: " + cap.code);
    row.put("logical_exit", cap.code);
    row.put("process_exit", cap.code & 255);
    row.put("logical_code_mod_256_contract", true);
    row.put("stdout", cap.stdout);
    row.put("stderr", cap.stderr);
    row.put("stdout_base64", cap.stdoutBase64);
    row.put("stderr_base64", cap.stderrBase64);
    row.put("tree_before", treeBefore);
    row.put("tree_after", treeHash(root));
    row.put("state_before_hash", sha(json(before)));
    Map<String, Object> after = logicalState(root);
    row.put("state_after_hash", sha(json(after)));
    row.put("mutations", mutations(before, after));
    return row;
  }

  private static Map<String, Object> runArchive(Case c, Path root, String identity) throws Exception {
    Path database = root.resolve("database");
    Files.createDirectory(database);
    if (!"empty".equals(suffix(c)) && !"missing".equals(suffix(c)) && !"help".equals(suffix(c))) {
      seedArchive(database);
    }
    Path target = "missing".equals(suffix(c)) ? root.resolve("missing") : database;
    List<String> argv = new ArrayList<>();
    if ("help".equals(suffix(c))) argv.add("-h");
    else { argv.add("-d"); argv.add(target.toString()); if ("m128".equals(suffix(c))) {
      argv.add("-m"); argv.add("128"); } }
    Map<String, String> manifestsBefore = manifestHashes(database);
    String treeBefore = treeHash(root);
    Capture cap;
    if ("ArchiveManifest".equals(c.family)) {
      final String[] directArgs = argv.toArray(new String[0]);
      cap = capture(new Invokable() { public int run() { return ArchiveManifest.run(directArgs); }}, root);
    } else {
      List<String> toolkitArgs = new ArrayList<>();
      toolkitArgs.add("db");
      toolkitArgs.add("archive");
      toolkitArgs.addAll(argv);
      final String[] directArgs = toolkitArgs.toArray(new String[0]);
      cap = capture(new Invokable() { public int run() {
        return new CommandLine(new org.tron.plugins.Toolkit()).execute(directArgs);
      }}, root);
      argv = toolkitArgs;
    }
    DbTool.close();
    Map<String, String> manifestsAfter = manifestHashes(database);
    Map<String, Object> state = logicalState(database);
    String treeAfter = treeHash(root);
    int expected = "missing".equals(suffix(c)) ? 404 : 0;
    require(cap.code == expected, c.scenario + " exit " + cap.code + " != " + expected);
    assertArchive(c, manifestsBefore, manifestsAfter);
    if ("help".equals(suffix(c)) || "missing".equals(suffix(c)) || "empty".equals(suffix(c))) {
      require(treeBefore.equals(treeAfter), c.scenario + " mutated fixture tree");
      try (Stream<Path> children = Files.list(database)) {
        require(!children.findAny().isPresent(), c.scenario + " created database children");
      }
      if ("missing".equals(suffix(c))) {
        require(!Files.exists(target), c.scenario + " created missing target");
      }
    }
    Map<String, Object> out = base(c, identity);
    out.put("argv", normalizeArgs(argv, root));
    out.put("logical_exit", cap.code);
    out.put("process_exit", cap.code & 255);
    out.put("logical_code_mod_256_contract", true);
    out.put("stdout", cap.stdout);
    out.put("stderr", cap.stderr);
    out.put("stdout_base64", cap.stdoutBase64);
    out.put("stderr_base64", cap.stderrBase64);
    out.put("tree_before", treeBefore);
    out.put("tree_after", treeAfter);
    out.put("state", state);
    out.put("manifest_hashes_before", manifestsBefore);
    out.put("manifest_hashes_after", manifestsAfter);
    out.put("effects", map("changed_manifests", changed(manifestsBefore, manifestsAfter),
        "assertions_passed", true));
    return out;
  }

  private static String suffix(Case c) { return c.scenario.substring(c.scenario.indexOf('_') + 1); }

  private static void seedLite(Path full, String engine, int checkpoint) throws Exception {
    for (String store : STORES) db(full, store, engine);
    for (long h = 0; h <= 5; h++) putBlock(full, h);
    DBInterface properties = db(full, "properties", engine);
    properties.put(bytes("latest_block_header_number"), longBytes(5));
    db(full, "account", engine).put(bytes("alice"), bytes("base-account"));
    db(full, "balance-trace", engine).put(longBytes(2), bytes("balance-2"));
    db(full, "account-trace", engine).put(longBytes(2), bytes("account-2"));
    DBInterface cp;
    if (checkpoint == 1) {
      cp = db(full, "tmp", engine);
    } else {
      Files.createDirectories(full.resolve("checkpoint"));
      cp = db(full.resolve("checkpoint"), "0000000000000001", engine);
    }
    cp.put(checkpointKey("account", bytes("alice")), putValue(bytes("checkpoint-account")));
    cp.put(checkpointKey("properties", bytes("latest_block_header_number")), putValue(longBytes(5)));
    DbTool.close();
  }

  private static void addLaterHistory(Path full, String engine) throws Exception {
    for (long h = 6; h <= 7; h++) putBlock(full, h);
    db(full, "properties", engine).put(bytes("latest_block_header_number"), longBytes(7));
    DBInterface cp = Files.isDirectory(full.resolve("checkpoint"))
        ? db(full.resolve("checkpoint"), "0000000000000001", engine)
        : db(full, "tmp", engine);
    cp.put(checkpointKey("properties", bytes("latest_block_header_number")), putValue(longBytes(7)));
    DbTool.close();
  }

  private static void putBlock(Path root, long h) throws Exception {
    String engine = engine(root.resolve("block"));
    Protocol.Transaction tx = Protocol.Transaction.newBuilder().setRawData(
        Protocol.Transaction.raw.newBuilder().setTimestamp(2000 + h)).build();
    Protocol.Block block = Protocol.Block.newBuilder().setBlockHeader(
        Protocol.BlockHeader.newBuilder().setRawData(
            Protocol.BlockHeader.raw.newBuilder().setNumber(h).setTimestamp(1000 + h)))
        .addTransactions(tx).build();
    byte[] id = MessageDigest.getInstance("SHA-256").digest(block.getBlockHeader().getRawData().toByteArray());
    System.arraycopy(longBytes(h), 0, id, 0, 8);
    byte[] txid = DBUtils.getTransactionId(tx).getBytes();
    db(root, "block", engine).put(id, block.toByteArray());
    db(root, "block-index", engine).put(longBytes(h), id);
    db(root, "trans", engine).put(txid, longBytes(h));
    db(root, "transactionRetStore", engine).put(longBytes(h), bytes("ret-" + h));
    db(root, "transactionHistoryStore", engine).put(txid, bytes("history-" + h));
  }
  private static void seedArchive(Path database) throws Exception {
    DBInterface account = db(database, "account", "LEVELDB");
    account.put(bytes("alice"), bytes("one"));
    db(database, "market_pair_price_to_order", "LEVELDB");
    DBInterface rocks = db(database, "store", "ROCKSDB");
    rocks.put(bytes("key"), bytes("rocks"));
    DbTool.close();
  }

  private static DBInterface db(Path parent, String name, String engine) throws Exception {
    return DbTool.getDB(parent.toString(), name,
        "ROCKSDB".equals(engine) ? DbTool.DbType.RocksDB : DbTool.DbType.LevelDB);
  }

  private static String engine(Path db) {
    try {
      Properties p = new Properties();
      try (java.io.InputStream in = Files.newInputStream(db.resolve("engine.properties"))) { p.load(in); }
      return p.getProperty("ENGINE", "LEVELDB").toUpperCase();
    } catch (Exception e) { return "LEVELDB"; }
  }

  private static Map<String, Object> logicalState(Path root) throws Exception {
    TreeMap<String, Object> state = new TreeMap<>();
    if (!Files.exists(root)) return new LinkedHashMap<>(state);
    try (Stream<Path> paths = Files.walk(root)) {
      List<Path> engines = new ArrayList<>();
      paths.filter(p -> p.getFileName().toString().equals("engine.properties"))
          .sorted(Comparator.comparing(p -> root.relativize(p).toString())).forEach(engines::add);
      for (Path marker : engines) {
        Path dir = marker.getParent();
        String rel = root.relativize(dir).toString().replace('\\', '/');
        DBInterface database = DbTool.getDB(dir.getParent().toString(), dir.getFileName().toString());
        TreeMap<String, String> rows = new TreeMap<>();
        try (DBIterator it = database.iterator()) {
          for (it.seekToFirst(); it.hasNext(); it.next()) rows.put(hex(it.getKey()), hex(it.getValue()));
        }
        state.put(rel, map("engine", engine(dir), "rows", rows,
            "hash", sha(json(rows))));
      }
    }
    DbTool.close();
    return new LinkedHashMap<>(state);
  }

  private static Map<String, String> manifestHashes(Path root) throws Exception {
    TreeMap<String, String> out = new TreeMap<>();
    if (!Files.exists(root)) return out;
    try (Stream<Path> paths = Files.walk(root)) {
      for (Path p : (Iterable<Path>) paths.filter(Files::isRegularFile).sorted()::iterator) {
        String n = p.getFileName().toString();
        if (n.startsWith("MANIFEST-")) out.put(root.relativize(p).toString().replace('\\', '/'), sha(Files.readAllBytes(p)));
      }
    }
    return out;
  }

  private static String treeHash(Path root) throws Exception {
    MessageDigest d = MessageDigest.getInstance("SHA-256");
    if (Files.exists(root)) {
      try (Stream<Path> paths = Files.walk(root)) {
        for (Path p : (Iterable<Path>) paths.sorted(
            Comparator.comparing(x -> root.relativize(x).toString()))::iterator) {
          if (p.equals(root)) continue;
          String name = p.getFileName().toString();
          boolean dbPhysical = Files.isRegularFile(p)
              && Files.exists(p.getParent().resolve("engine.properties"))
              && !name.equals("engine.properties");
          if (dbPhysical) continue;
          update(d, root.relativize(p).toString().replace('\\', '/'));
          update(d, Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS) ? "D" : "F");
          if (Files.isRegularFile(p) && !name.equals("engine.properties")) {
            if (name.endsWith(".properties")) update(d, canonicalProperties(p));
            else d.update(Files.readAllBytes(p));
          }
          if (name.equals("engine.properties")) update(d, engine(p.getParent()));
        }
      }
    }
    return hex(d.digest());
  }

  private static Map<String, Object> effectsLite(Path snapshot, boolean exclude) throws Exception {
    Map<String, Object> state = logicalState(snapshot);
    List<String> present = new ArrayList<>(state.keySet());
    return map("archive_heights", deriveBlockHeights(state), "info_removed",
        !Files.exists(snapshot.resolve("info.properties")), "stores", present,
        "trace_policy", exclude ? "excluded_permanently" : "retained");
  }

  @SuppressWarnings("unchecked")
  private static List<Long> deriveBlockHeights(Map<String, Object> state) {
    List<Long> heights = new ArrayList<>();
    Object entry = state.get("block-index");
    if (!(entry instanceof Map)) return heights;
    Object rows = ((Map<String, Object>) entry).get("rows");
    if (!(rows instanceof Map)) return heights;
    for (Object key : ((Map<?, ?>) rows).keySet()) {
      byte[] raw = unhex(String.valueOf(key));
      if (raw.length == 8) heights.add(ByteBuffer.wrap(raw).getLong());
    }
    Collections.sort(heights);
    return heights;
  }

  @SuppressWarnings("unchecked")
  private static void assertLiteState(Map<String, Object> state, List<Long> heights,
      boolean stateExpected, boolean tracesAbsent, String phase) {
    require(deriveBlockHeights(state).equals(heights),
        phase + " block heights mismatch: " + deriveBlockHeights(state) + " != " + heights);
    if ("snapshot".equals(phase)) {
      for (String db : Arrays.asList("block", "block-index", "trans")) {
        require(state.containsKey(db), phase + " missing " + db);
      }
      require(!state.containsKey("transactionRetStore"), "snapshot retained transaction results");
      require(!state.containsKey("transactionHistoryStore"), "snapshot retained transaction history");
      require(rows(state, "trans").size() == heights.size() - 1,
          "snapshot recent transaction count mismatch");
    } else {
      for (String db : ARCHIVE_STORES) require(state.containsKey(db), phase + " missing " + db);
      java.util.Set<String> expectedRet = new java.util.TreeSet<>();
      for (Long height : heights) expectedRet.add(hex(longBytes(height)));
      require(rows(state, "transactionRetStore").keySet().equals(expectedRet),
          phase + " transaction result keys mismatch");
      if ("history".equals(phase)) {
        require(rows(state, "trans").keySet().equals(rows(state, "transactionHistoryStore").keySet()),
            "history transaction/history key mismatch");
      } else {
        require(rows(state, "transactionHistoryStore").keySet().containsAll(rows(state, "trans").keySet()),
            "merge lost retained transaction history");
        require(rows(state, "transactionHistoryStore").size() == heights.size() + 2,
            "merge later transaction-history retention mismatch");
      }
      require(rows(state, "trans").size() == heights.size(), phase + " transaction count mismatch");
    }
    require(state.containsKey("account") == stateExpected, phase + " account policy mismatch");
    require(state.containsKey("properties") == stateExpected, phase + " properties policy mismatch");
    require(state.containsKey("balance-trace") != tracesAbsent, phase + " balance trace mismatch");
    require(state.containsKey("account-trace") != tracesAbsent, phase + " account trace mismatch");
    if (stateExpected) {
      require(hex(bytes("checkpoint-account")).equals(rows(state, "account").get(hex(bytes("alice")))),
          phase + " checkpoint account overlay missing");
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, String> rows(Map<String, Object> state, String db) {
    return (Map<String, String>) ((Map<String, Object>) state.get(db)).get("rows");
  }

  private static void assertArchive(Case c, Map<String, String> before, Map<String, String> after) {
    List<String> changed = changed(before, after);
    if ("run_m0".equals(suffix(c))) {
      require(!changed.isEmpty(), c.scenario + " did not rewrite account manifest");
      for (String path : changed) require(path.startsWith("account/"),
          c.scenario + " changed unexpected manifest: " + path);
    } else if ("m128".equals(suffix(c))) {
      require(changed.isEmpty(), c.scenario + " rewrote manifest at m=128");
    } else {
      require(changed.isEmpty(), c.scenario + " unexpectedly changed manifests: " + changed);
    }
  }

  private static void require(boolean condition, String message) {
    if (!condition) throw new IllegalStateException(message);
  }

  private static byte[] unhex(String value) {
    byte[] out = new byte[value.length() / 2];
    for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(value.substring(i*2,i*2+2),16);
    return out;
  }

  private static List<String> changed(Map<String, String> a, Map<String, String> b) {
    List<String> out = new ArrayList<>();
    TreeMap<String, String> all = new TreeMap<>(a); all.putAll(b);
    for (String k : all.keySet()) if (!java.util.Objects.equals(a.get(k), b.get(k))) out.add(k);
    return out;
  }

  private static List<Object> mutations(Map<String, Object> a, Map<String, Object> b) {
    List<Object> out = new ArrayList<>();
    TreeMap<String, Object> all = new TreeMap<>(a); all.putAll(b);
    for (String k : all.keySet()) if (!java.util.Objects.equals(a.get(k), b.get(k)))
      out.add(map("path", k, "before", a.containsKey(k), "after", b.containsKey(k)));
    return out;
  }

  private interface Invokable { int run() throws Exception; }
  private static final class Capture {
    int code; String stdout; String stderr; String stdoutBase64; String stderrBase64;
  }
  private static Capture capture(Invokable run, Path root) throws Exception {
    PrintStream oldOut = System.out, oldErr = System.err;
    ByteArrayOutputStream out = new ByteArrayOutputStream(), err = new ByteArrayOutputStream();
    Capture c = new Capture();
    try {
      System.setOut(new PrintStream(out, true, "UTF-8"));
      System.setErr(new PrintStream(err, true, "UTF-8"));
      c.code = run.run();
    } finally { System.setOut(oldOut); System.setErr(oldErr); }
    c.stdout = normalize(new String(out.toByteArray(), StandardCharsets.UTF_8), root);
    c.stderr = normalize(new String(err.toByteArray(), StandardCharsets.UTF_8), root);
    c.stdoutBase64 = Base64.getEncoder().encodeToString(c.stdout.getBytes(StandardCharsets.UTF_8));
    c.stderrBase64 = Base64.getEncoder().encodeToString(c.stderr.getBytes(StandardCharsets.UTF_8));
    return c;
  }

  private static String canonicalProperties(Path path) throws Exception {
    Properties properties = new Properties();
    try (java.io.InputStream in = Files.newInputStream(path)) { properties.load(in); }
    StringBuilder out = new StringBuilder();
    for (String key : new java.util.TreeSet<>(properties.stringPropertyNames())) {
      out.append(key).append('=').append(properties.getProperty(key)).append('\n');
    }
    return out.toString();
  }

  private static String normalize(String value, Path root) {
    String s = value.replace(root.toString(), "$FIXTURE").replace("\\r\\n", "\\n");
    s = s.replaceAll("\\.bak_\\d+", ".bak_<epoch>");
    return ELAPSED.matcher(s).replaceAll("$1 <elapsed> $2");
  }
  private static List<String> normalizeArgs(List<String> args, Path root) {
    List<String> out = new ArrayList<>();
    for (String a : args) out.add(a.replace(root.toString(), "$FIXTURE"));
    return out;
  }

  private static byte[] checkpointKey(String db, byte[] key) {
    byte[] name = bytes(db); ByteBuffer b = ByteBuffer.allocate(4 + name.length + key.length);
    b.putInt(name.length).put(name).put(key); return b.array();
  }
  private static byte[] putValue(byte[] value) { byte[] out = new byte[value.length + 1]; out[0] = 3;
    System.arraycopy(value, 0, out, 1, value.length); return out; }
  private static byte[] longBytes(long v) { return ByteBuffer.allocate(8).putLong(v).array(); }
  private static byte[] bytes(String s) { return s.getBytes(StandardCharsets.UTF_8); }
  private static void update(MessageDigest d, String s) { d.update(bytes(s)); d.update((byte) 0); }
  private static String sha(String s) throws Exception { return sha(bytes(s)); }
  private static String sha(byte[] b) throws Exception { return hex(MessageDigest.getInstance("SHA-256").digest(b)); }
  private static String hex(byte[] b) { StringBuilder s = new StringBuilder(b.length * 2);
    for (byte x : b) s.append(String.format("%02x", x & 255)); return s.toString(); }

  private static String requiredProperty(String name) {
    String value = System.getProperty(name);
    if (value == null || value.isEmpty()) throw new IllegalArgumentException("missing -D" + name);
    return value;
  }
  private static void requireEmptyDirectory(Path root) throws Exception {
    if (!Files.isDirectory(root)) throw new IllegalArgumentException("fixture root must exist and be a directory");
    try (Stream<Path> s = Files.list(root)) { if (s.findAny().isPresent())
      throw new IllegalArgumentException("fixture root must be empty"); }
  }

  private static Map<String, Object> base(Case c, String identity) {
    return map("schema", "c027-java-direct-observation.v1", "stable_id", c.id,
        "scenario", c.scenario, "family", c.family, "engine", c.engine,
        "checkpoint", c.checkpoint, "exclude_historical_balance", c.excludeTrace,
        "java_identity_id", identity);
  }
  @SuppressWarnings("unchecked") private static <K,V> Map<K,V> map(Object... kv) {
    LinkedHashMap<K,V> m = new LinkedHashMap<>(); for (int i=0;i<kv.length;i+=2) m.put((K)kv[i],(V)kv[i+1]); return m;
  }

  private static String json(Object value) {
    if (value == null) return "null";
    if (value instanceof Boolean || value instanceof Number) return value.toString();
    if (value instanceof String) return quote((String)value);
    if (value instanceof Map) { StringBuilder s=new StringBuilder("{"); boolean first=true;
      for (Object e0:((Map<?,?>)value).entrySet()) { Map.Entry<?,?> e=(Map.Entry<?,?>)e0;
        if(!first)s.append(',');first=false;s.append(quote(String.valueOf(e.getKey()))).append(':').append(json(e.getValue())); }
      return s.append('}').toString(); }
    if (value instanceof Iterable) { StringBuilder s=new StringBuilder("["); boolean first=true;
      for(Object x:(Iterable<?>)value){if(!first)s.append(',');first=false;s.append(json(x));}return s.append(']').toString();}
    throw new IllegalArgumentException("unsupported JSON value " + value.getClass());
  }
  private static String quote(String v) { StringBuilder s=new StringBuilder("\"");
    for(int i=0;i<v.length();i++){char c=v.charAt(i);switch(c){case '\"':s.append("\\\"");break;case '\\':s.append("\\\\");break;
      case '\b':s.append("\\b");break;case '\f':s.append("\\f");break;case '\n':s.append("\\n");break;case '\r':s.append("\\r");break;case '\t':s.append("\\t");break;
      default:if(c<32)s.append(String.format("\\u%04x",(int)c));else s.append(c);}}return s.append('\"').toString();}
}
