import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/** Dependency-free pinned C010 oracle. Emits tab-separated id/input/expected rows. */
public final class C010Oracle {
  private record Row(String id, String input, String expected) {}

  private static long recover(long usage, long latest, long window, long now) {
    long delta = now - latest;
    if (delta >= window) return 0;
    long averageUsage = Math.floorDiv(Math.addExact(Math.multiplyExact(usage, 1_000_000L), window - 1), window);
    long decayedAverage = Math.round(averageUsage * ((window - delta) / (double) window));
    return Math.multiplyExact(decayedAverage, window) / 1_000_000L;
  }
  private static long recoverPrecise(long usage, long latest, long storedWindow, long standardWindow, long now) {
    long window = storedWindow < 1000 ? standardWindow : storedWindow / 1000;
    return recover(usage, latest, window, now);
  }


  private static String hex(byte[] bytes) {
    StringBuilder out = new StringBuilder(bytes.length * 2);
    for (byte value : bytes) out.append(String.format("%02x", value & 0xff));
    return out.toString();
  }

  private static byte[] sha256(byte[] value) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(value);
  }

  private static String sha256(String value) throws Exception {
    return hex(sha256(value.getBytes(StandardCharsets.UTF_8)));
  }

  private static byte[] concat(byte[]... values) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] value : values) out.writeBytes(value);
    return out.toByteArray();
  }

  private static byte[] varint(long value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    while ((value & ~0x7fL) != 0) { out.write((int) (value & 0x7f) | 0x80); value >>>= 7; }
    out.write((int) value);
    return out.toByteArray();
  }

  private static byte[] bytesField(int field, byte[] value) {
    return concat(varint((long) field << 3 | 2), varint(value.length), value);
  }

  private static byte[] intField(int field, long value) {
    return value == 0 ? new byte[0] : concat(varint((long) field << 3), varint(value));
  }

  private static byte[] genesisTransaction(byte[] address, long balance) {
    byte[] owner = "0x000000000000000000000".getBytes(StandardCharsets.US_ASCII);
    byte[] transfer = concat(bytesField(1, owner), bytesField(2, address), intField(3, balance));
    byte[] any = concat(bytesField(1, "type.googleapis.com/protocol.TransferContract".getBytes(StandardCharsets.US_ASCII)), bytesField(2, transfer));
    byte[] contract = concat(intField(1, 1), bytesField(2, any));
    return bytesField(1, bytesField(11, contract));
  }

  private static Row genesisVector() throws Exception {
    byte[] firstAddress = new byte[21]; firstAddress[0] = 0x41; java.util.Arrays.fill(firstAddress, 1, 21, (byte) 0x11);
    byte[] secondAddress = new byte[21]; secondAddress[0] = 0x41; java.util.Arrays.fill(secondAddress, 1, 21, (byte) 0x22);
    byte[] first = genesisTransaction(firstAddress, 7);
    byte[] second = genesisTransaction(secondAddress, 9);
    byte[] merkle = sha256(concat(sha256(first), sha256(second)));
    byte[] headerRaw = concat(bytesField(2, merkle), bytesField(3, new byte[] {0}), bytesField(9, "A new system must allow existing systems to be linked together without requiring any central control or coordination".getBytes(StandardCharsets.US_ASCII)));
    byte[] headerHash = sha256(headerRaw);
    byte[] blockId = headerHash.clone(); java.util.Arrays.fill(blockId, 0, 8, (byte) 0);
    byte[] block = concat(bytesField(1, first), bytesField(1, second), bytesField(2, bytesField(1, headerRaw)));
    String expected = "tx0=" + hex(first) + ",tx1=" + hex(second) + ",merkle=" + hex(merkle) + ",block_id=" + hex(blockId) + ",block=" + hex(block);
    return new Row("genesis:accounts-witnesses-assets-block", "timestamp=0,parent=00,balances=7+9,owner=0x000000000000000000000", expected);
  }
  private static Row genesisStoreRows() throws Exception {
    byte[] firstAddress = new byte[21]; firstAddress[0] = 0x41; java.util.Arrays.fill(firstAddress, 1, 21, (byte) 0x11);
    byte[] secondAddress = new byte[21]; secondAddress[0] = 0x41; java.util.Arrays.fill(secondAddress, 1, 21, (byte) 0x22);
    byte[] first = genesisTransaction(firstAddress, 7);
    byte[] second = genesisTransaction(secondAddress, 9);
    byte[] merkle = sha256(concat(sha256(first), sha256(second)));
    byte[] headerRaw = concat(bytesField(2, merkle), bytesField(3, new byte[] {0}), bytesField(9, "A new system must allow existing systems to be linked together without requiring any central control or coordination".getBytes(StandardCharsets.US_ASCII)));
    byte[] blockId = sha256(headerRaw); java.util.Arrays.fill(blockId, 0, 8, (byte) 0);
    String expected = "recent-block:0000=" + hex(java.util.Arrays.copyOfRange(blockId, 8, 16))
        + ",witness_schedule:active_witnesses=" + hex(concat(firstAddress, secondAddress));
    return new Row("genesis:persisted-store-rows", "height=0,witnesses=4111*20+4122*20", expected);
  }


  public static void main(String[] args) throws Exception {
    List<Row> rows = new ArrayList<>();
    rows.add(genesisVector());
    rows.add(genesisStoreRows());
    rows.add(new Row("genesis:network-genesis-mismatch", "stored=alpha,configured=beta", "incompatible-chain"));
    rows.add(new Row("genesis:transaction-id-raw-data", "transaction_id=sha256(raw_data),merkle_leaf=sha256(transaction)", "separate-hash-boundaries"));
    rows.add(new Row("genesis:advanced-state-restart", "immutable-genesis=match,live-derived-stores=advanced", "existing-chain"));
    rows.add(new Row("genesis:substituted-genesis-rejected", "genesis-block-or-chain-id=substituted", "corrupt-state"));
    rows.add(new Row("genesis:substituted-marker-rejected", "genesis-commitment-marker=substituted", "incompatible-chain"));
    rows.add(new Row("dynamic-defaults:fresh-chain-defaults", "TOTAL_SIGN_NUM:int,MEMO_FEE:long", "4,8"));
    rows.add(new Row("dynamic-defaults:missing-only-migration", "existing=7,default=9", "7"));
    rows.add(new Row("dynamic-defaults:leading-space-property", "key= ALLOW_SAME_TOKEN_NAME,default=CommonParameter.getInstance().getAllowSameTokenName()", "long,key_utf8= ALLOW_SAME_TOKEN_NAME"));
    rows.add(new Row("dynamic-slots:atomic-precommit-retry", "slots=63/128,index=127,filled=true;fault=append|flush|sync;reopen,retry", "fault:slots=63,index=127;reopen:slots=63,index=127;retry:slots=64,index=0"));
    rows.add(new Row("dynamic-slots:filled-percentage", "filled=64,total=128", "50"));
    rows.add(new Row("fork-boundaries:before-at-after", "hardFork=100,interval=10;hardForkMin=-9223372036854775808;maintenanceCurrentMinMax,interval=1;interval=0,-1", "99:false,100:true,101:true;hardForkMin:timestamp-overflow;maintenanceMax:timestamp-overflow,no-write;maintenanceMin:-9223372036854775807;intervalNonPositive:invalid-interval,no-write"));
    rows.add(new Row("fork-boundaries:version-number-int-encoding", "prepopulated=00000000;activate=6;reopen;malformed=0000000000000006", "encoding=int32;activated=00000006;reopen=6,length=4;malformed=invalid-length,no-write"));
    rows.add(new Row("fork-quorum:current-membership", "active=identities-each-decision;growth,shrink,stale-short,stale-long,malformed,no-premature", "identity-mapped,java-resize,atomic-publish"));
    rows.add(new Row("resources:legacy-window", "usage=100,latest=10,window=20,now=15", Long.toString(recover(100, 10, 20, 15))));
    rows.add(new Row("resources:precision-window", "usage=1000,latest=10,storedWindow=2000000,standardWindow=2000,now=11", Long.toString(recoverPrecise(1000, 10, 2_000_000, 2_000, 11))));
    rows.add(new Row("resources:precision-window-midpoint", "usage=1000,latest=10,storedWindow=2000000,standardWindow=2000,now=1010", Long.toString(recoverPrecise(1000, 10, 2_000_000, 2_000, 1010))));
    rows.add(new Row("resources:precision-window-stored-1", "usage=1000,latest=10,storedWindow=1,standardWindow=2000,now=11", Long.toString(recoverPrecise(1000, 10, 1, 2_000, 11))));
    rows.add(new Row("resources:precision-window-stored-999", "usage=1000,latest=10,storedWindow=999,standardWindow=2000,now=11", Long.toString(recoverPrecise(1000, 10, 999, 2_000, 11))));
    rows.add(new Row("resources:precision-window-stored-1000", "usage=1000,latest=10,storedWindow=1000,standardWindow=2000,now=11", Long.toString(recoverPrecise(1000, 10, 1000, 2_000, 11))));
    rows.add(new Row("resources:adaptive-energy", "base=1000,current=2000,average=11,target=10,rate=99/100", "1980"));
    rows.add(new Row("resources:adaptive-energy-base-floor", "base=1000,current=1000,average=11,target=10,rate=99/100", "1000"));
    rows.add(new Row("resources:fee-sinks", "balance=100,fee=7", "pool=7,burn=7,blackhole=7,balance=93"));
    rows.add(new Row("resources:weight-max-overflow", "current=9223372036854775807,delta=1", "arithmetic-overflow,no-write"));
    rows.add(new Row("resources:weight-min-overflow", "current=-9223372036854775808,delta=-1", "arithmetic-overflow,no-write"));
    rows.add(new Row("resources:weight-clamp-interaction", "current=-5,delta=3,newReward=true", "0"));
    rows.add(new Row("resources:adaptive-ratio-zero", "total=100,current=80,target=20,ratio=0", "invalid-ratio,total=100,current=80,target=20"));
    rows.add(new Row("resources:adaptive-ratio-negative", "total=100,current=80,target=20,ratio=-4", "invalid-ratio,total=100,current=80,target=20"));
    rows.add(new Row("resources:adaptive-no-partial-write", "storedTotal=100,storedCurrent=80,storedTarget=20,newTotal=200,ratio=0", "total=100,current=80,target=20"));
    rows.add(new Row("asset-transitions:legacy-dual-write", "name=USDT,id=1000001,sameName=false", "legacy+v2"));
    rows.add(new Row("asset-transitions:v2-only", "name=USDT,id=1000001,sameName=true", "v2"));
    rows.add(new Row("asset-transitions:externalized-balances", "USDT=7,id=1000001,optimize=true", "account-asset:1000001=7"));
    rows.add(new Row("trie-rlp:empty-root", "rlp=80", "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"));
    rows.add(new Row("trie-rlp:inline-child", "key=01,value=01", "child-length<32"));
    rows.add(new Row("trie-rlp:hashed-child", "key=01,value=64-bytes", "child-length>=32"));
    rows.add(new Row("trie-rlp:insertion-order", "a=1,b=2", "same-root-reversed"));
    rows.add(new Row("trie-rlp:shared-prefix", "keys=11*32,11*31+12,22*32", "same-root-reversed"));
    rows.add(new Row("trie-rlp:single-tron-account-root", "address=411111111111111111111111111111111111111111,key_rlp=95411111111111111111111111111111111111111111,value=1a1541111111111111111111111111111111111111111120075803", "6bb3e919f2027ff7ce0d7581a5ee6814161a798dfec064471e91fb5beb165c89"));
    rows.add(new Row("trie-rlp:single-tron-account-node", "address=411111111111111111111111111111111111111111,key_rlp=95411111111111111111111111111111111111111111,value=1a1541111111111111111111111111111111111111111120075803", "f49720954111111111111111111111111111111111111111119b1a1541111111111111111111111111111111111111111120075803"));
    rows.add(new Row("trie-rlp:shared-prefix-root", "addresses=411111111111111111111111111111111111111111+411111111111111111111111111111111111111112+412222222222222222222222222222222222222222,paths=raw-rlp-nibbles", "51932f64129c93edaadc133fa24deafe9916ec914dd69d968f5fdddd150fa502"));
    rows.add(new Row("trie-rlp:shared-prefix-node", "addresses=411111111111111111111111111111111111111111+411111111111111111111111111111111111111112+412222222222222222222222222222222222222222,paths=raw-rlp-nibbles", "e583009541a05877f63628347e5ed54ab882f1d561b85680a9eec39095601aef441a21dac407"));
    rows.add(new Row("trie-limits:address-exact-max", "address-bytes=21", "accepted"));
    rows.add(new Row("trie-limits:address-over-limit", "address-bytes=22", "address-too-long"));
    rows.add(new Row("trie-limits:value-exact-max", "value-bytes=4,max=4", "accepted"));
    rows.add(new Row("trie-limits:value-over-limit", "value-bytes=5,max=4", "value-too-large"));
    rows.add(new Row("trie-limits:leaf-exact-max", "leaves=2,max=2", "accepted"));
    rows.add(new Row("trie-limits:leaf-over-limit", "leaves=3,max=2", "leaf-limit-exceeded"));
    rows.add(new Row("trie-limits:total-bytes-exact-max", "value-bytes=2+3,max=5", "accepted"));
    rows.add(new Row("trie-limits:total-bytes-over-limit", "value-bytes=2+3+1,max=5", "total-bytes-limit-exceeded"));
    rows.add(new Row("trie-limits:node-bytes-exact-max", "encoded-node-bytes=36,max=36", "accepted"));
    rows.add(new Row("trie-limits:node-bytes-over-limit", "encoded-node-bytes=36,max=35", "node-bytes-limit-exceeded"));
    rows.add(new Row("trie-limits:depth-exact-max", "nibble-depth=64,max=64", "accepted"));
    rows.add(new Row("trie-limits:depth-over-limit", "nibble-depth=64,max=63", "depth-limit-exceeded"));
    rows.add(new Row("forced-root:report-vs-validation", "supplied=00*32,logical=nonzero", "report-supplied,validation-mismatch"));
    rows.add(new Row("duplicate-leaf:last-value-replaces", "key=01,first=a,last=b", "b"));
    rows.add(new Row("duplicate-leaf:bounded-replacement", "key=11*31+12,first=2,last=9", "same-root-as-single-last-value"));
    rows.add(new Row("schema-migrations:manifest-version", "source=1,target=2", "2"));
    rows.add(new Row("schema-migrations:recomputed-root", "rows=account+dynamic", sha256("account/alice=balance=7;asset-v2=1000001:3\ndynamic/ALLOW_SAME_TOKEN_NAME=1")));
    rows.add(new Row("schema-migrations:pre-switch-rollback", "fault=data-synced", "source-visible"));
    rows.add(new Row("schema-migrations:post-switch-resume", "fault=manifest-switched", "target-visible"));
    rows.add(new Row("schema-migrations:restart-idempotence", "resume=2", "no-op"));
    rows.add(new Row("schema-migrations:preflight-crash", "fault=preflight", "source-visible"));
    rows.add(new Row("schema-migrations:staging-created-crash", "fault=staging-created", "source-visible"));
    rows.add(new Row("schema-migrations:data-written-crash", "fault=data-written", "source-visible"));
    rows.add(new Row("schema-migrations:data-synced-crash", "fault=data-synced", "source-visible"));
    rows.add(new Row("schema-migrations:journal-synced-crash", "fault=journal-synced", "target-visible-after-resume"));
    rows.add(new Row("schema-migrations:backup-synced-crash", "fault=backup-synced", "target-visible-after-resume"));
    rows.add(new Row("schema-migrations:generation-published-crash", "fault=generation-published", "target-visible-after-resume"));
    rows.add(new Row("schema-migrations:manifest-switched-crash", "fault=manifest-switched", "target-visible-after-resume"));
    rows.add(new Row("schema-migrations:directory-synced-crash", "fault=directory-synced", "target-visible-after-resume"));
    for (Row row : rows) System.out.println(row.id + "\t" + row.input + "\t" + row.expected);
  }
}
