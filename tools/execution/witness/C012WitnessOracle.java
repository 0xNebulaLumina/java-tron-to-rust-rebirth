package org.tron.core.actuator;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.tron.common.application.TronApplicationContext;
import org.tron.common.utils.ByteArray;
import org.tron.core.ChainBaseManager;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.TransactionResultCapsule;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.config.DefaultConfig;
import org.tron.core.config.args.Args;
import org.tron.core.db2.ISession;
import org.tron.core.db2.core.SnapshotManager;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.Transaction.Contract;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.WitnessContract.VoteWitnessContract;
import org.tron.protos.contract.WitnessContract.VoteWitnessContract.Vote;
import org.tron.protos.contract.WitnessContract.WitnessCreateContract;
import org.tron.protos.contract.WitnessContract.WitnessUpdateContract;

/** Deterministic, direct Java evidence for the C012 witness actuator family. */
public final class C012WitnessOracle {
  private static final byte[] OWNER = ByteArray.fromHexString("41abd4b9367799eaa3197fecb144eb71de1e049abc");
  private static final byte[] CANDIDATE = ByteArray.fromHexString("41548794500882809695a8a687866e76d4271a1abc");
  private static final byte[] MISSING = ByteArray.fromHexString("41548794500882809695a8a687866e76d4271a1aed");
  private static final byte[] BAD = ByteArray.fromHexString("aaaa");
  private static final byte[] BLACKHOLE = ByteArray.fromHexString("410000000000000000000000000000000000000000");
  private static final long FEE = 100_000_000L;
  private static final String URL = "https://tron.network";
  private static final String NEW_URL = "https://tron.org";

  private final TronApplicationContext app;
  private final ChainBaseManager chain;
  private final SnapshotManager snapshots;
  private static final List<String> rows = new ArrayList<>();

  private C012WitnessOracle(Path db) {
    Args.setParam(new String[] {"--output-directory", db.toString(), "--p2p-disable", "true"}, "config-test.conf");
    app = new TronApplicationContext(DefaultConfig.class);
    chain = app.getBean(ChainBaseManager.class);
    snapshots = app.getBean(SnapshotManager.class);
  }

  private static String hex(byte[] value) { return ByteArray.toHexString(value); }
  private static String q(String value) { return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""; }
  private static String entry(byte[] value) { return value == null ? "null" : q(hex(value)); }
  private byte[] account(byte[] key) { AccountCapsule c = chain.getAccountStore().get(key); return c == null ? null : c.getInstance().toByteArray(); }
  private byte[] witness(byte[] key) { WitnessCapsule c = chain.getWitnessStore().get(key); return c == null ? null : c.getInstance().toByteArray(); }
  private byte[] votes(byte[] key) { org.tron.core.capsule.VotesCapsule c = chain.getVotesStore().get(key); return c == null ? null : c.getInstance().toByteArray(); }
  private static String delta(String store, byte[] key, byte[] before, byte[] after) { return "{\"store\":"+q(store)+",\"key_hex\":"+q(hex(key))+",\"before_hex\":"+entry(before)+",\"after_hex\":"+entry(after)+"}"; }

  private void reset(long ownerBalance, boolean ownerWitness, long power, boolean candidateAccount, boolean candidateWitness) {
    chain.getAccountStore().delete(OWNER); chain.getAccountStore().delete(CANDIDATE); chain.getAccountStore().delete(MISSING);
    chain.getWitnessStore().delete(OWNER); chain.getWitnessStore().delete(CANDIDATE); chain.getWitnessStore().delete(MISSING);
    chain.getVotesStore().delete(OWNER);
    AccountCapsule owner = new AccountCapsule(ByteString.copyFromUtf8("owner"), ByteString.copyFrom(OWNER), AccountType.Normal, ownerBalance);
    if (power > 0) owner.setFrozenForBandwidth(power, 0L);
    chain.getAccountStore().put(OWNER, owner);
    if (ownerWitness) chain.getWitnessStore().put(OWNER, new WitnessCapsule(ByteString.copyFrom(OWNER), 0, URL));
    if (candidateAccount) chain.getAccountStore().put(CANDIDATE, new AccountCapsule(ByteString.copyFromUtf8("candidate"), ByteString.copyFrom(CANDIDATE), AccountType.Normal, 300));
    if (candidateWitness) chain.getWitnessStore().put(CANDIDATE, new WitnessCapsule(ByteString.copyFrom(CANDIDATE), 10, URL));
    chain.getDynamicPropertiesStore().saveAccountUpgradeCost(FEE);
    chain.getDynamicPropertiesStore().saveTotalCreateWitnessFee(7L);
    chain.getDynamicPropertiesStore().saveAllowMultiSign(1L);
    chain.getDynamicPropertiesStore().saveAllowNewResourceModel(0L);
    chain.getDynamicPropertiesStore().saveAllowBlackHoleOptimization(0L);
  }

  private void scenario(String id, Contract full, AbstractActuator actuator, byte[] primary, String kind) throws Exception {
    byte[] blackhole=chain.getAccountStore().getBlackholeAddress();
    byte[] a0=account(primary), w0=witness(primary), v0=votes(primary), b0=account(blackhole);
    byte[] d0=ByteArray.fromLong(chain.getDynamicPropertiesStore().getTotalCreateWitnessCost());
    TransactionResultCapsule result = new TransactionResultCapsule(); String error=""; boolean ok=false;
    byte[] a1, w1, v1, b1, d1;
    try (ISession outer = snapshots.buildSession(true)) {
      try (ISession execution = snapshots.buildSession(true)) {
        try { actuator.setChainBaseManager(chain).setContract(full); actuator.validate(); actuator.execute(result); ok=true; execution.commit(); }
        catch (Exception e) { error=e.getMessage()==null?"":e.getMessage(); }
      }
      a1=account(primary); w1=witness(primary); v1=votes(primary); b1=account(blackhole); d1=ByteArray.fromLong(chain.getDynamicPropertiesStore().getTotalCreateWitnessCost());
    }
    byte[] ar=account(primary), wr=witness(primary), vr=votes(primary), br=account(blackhole), dr=ByteArray.fromLong(chain.getDynamicPropertiesStore().getTotalCreateWitnessCost());
    List<String> ds=new ArrayList<>();
    if(!Arrays.equals(a0,a1)) ds.add(delta("Account",primary,a0,a1));
    if(!Arrays.equals(w0,w1)) ds.add(delta("Witness",primary,w0,w1));
    if(!Arrays.equals(v0,v1)) ds.add(delta("Votes",primary,v0,v1));
    if(!Arrays.equals(b0,b1)) ds.add(delta("Account",blackhole,b0,b1));
    if(!Arrays.equals(d0,d1)) ds.add(delta("DynamicProperties","TOTAL_CREATE_WITNESS_FEE".getBytes(StandardCharsets.UTF_8),d0,d1));
    Contract persisted=Contract.parseFrom(full.toByteArray());
    rows.add("{\"variant_id\":"+q(id)+",\"kind\":"+q(kind)+",\"contract_hex\":"+q(hex(persisted.toByteArray()))+",\"contract_any_hex\":"+q(hex(persisted.getParameter().toByteArray()))+",\"blackhole_key_hex\":"+q(hex(blackhole))+",\"success\":"+ok+",\"error\":"+q(error)+",\"result_code\":"+result.getInstance().getRetValue()+",\"fee\":"+result.getInstance().getFee()+",\"asset_issue_id_hex\":"+q(hex(result.getInstance().getAssetIssueID().getBytes(StandardCharsets.UTF_8)))+",\"deltas\":["+String.join(",",ds)+"],\"commit_account_hex\":"+entry(a1)+",\"commit_witness_hex\":"+entry(w1)+",\"commit_votes_hex\":"+entry(v1)+",\"commit_blackhole_hex\":"+entry(b1)+",\"commit_dynamic_hex\":"+entry(d1)+",\"revoke_account_hex\":"+entry(ar)+",\"revoke_witness_hex\":"+entry(wr)+",\"revoke_votes_hex\":"+entry(vr)+",\"revoke_blackhole_hex\":"+entry(br)+",\"revoke_dynamic_hex\":"+entry(dr)+"}");
  }

  private static Contract contract(ContractType type, Any any) { return Contract.newBuilder().setType(type).setParameter(any).build(); }
  private void create(String id, byte[] owner, byte[] url) throws Exception { WitnessCreateContract c=WitnessCreateContract.newBuilder().setOwnerAddress(ByteString.copyFrom(owner)).setUrl(ByteString.copyFrom(url)).build(); scenario(id,contract(ContractType.WitnessCreateContract,Any.pack(c)),new WitnessCreateActuator(),owner,"create"); }
  private void update(String id, byte[] owner, byte[] url) throws Exception { WitnessUpdateContract c=WitnessUpdateContract.newBuilder().setOwnerAddress(ByteString.copyFrom(owner)).setUpdateUrl(ByteString.copyFrom(url)).build(); scenario(id,contract(ContractType.WitnessUpdateContract,Any.pack(c)),new WitnessUpdateActuator(),owner,"update"); }
  private void vote(String id, byte[] owner, long... counts) throws Exception { VoteWitnessContract.Builder c=VoteWitnessContract.newBuilder().setOwnerAddress(ByteString.copyFrom(owner)); for(long count:counts)c.addVotes(Vote.newBuilder().setVoteAddress(ByteString.copyFrom(CANDIDATE)).setVoteCount(count)); scenario(id,contract(ContractType.VoteWitnessContract,Any.pack(c.build())),new VoteWitnessActuator(),owner,"vote"); }

  private void run(String id) throws Exception {
    switch (id) {
      case "witness-create-success-default-permission": reset(200_000_000_000L,false,0,true,true); create(id,OWNER,URL.getBytes(StandardCharsets.UTF_8)); break;
      case "witness-create-existing": reset(200_000_000_000L,true,0,true,true); create(id,OWNER,URL.getBytes(StandardCharsets.UTF_8)); break;
      case "witness-create-invalid-address": reset(200_000_000_000L,false,0,true,true); create(id,BAD,URL.getBytes(StandardCharsets.UTF_8)); break;
      case "witness-create-empty-url": reset(200_000_000_000L,false,0,true,true); create(id,OWNER,new byte[0]); break;
      case "witness-create-insufficient-balance": reset(FEE-1,false,0,true,true); create(id,OWNER,URL.getBytes(StandardCharsets.UTF_8)); break;
      case "witness-create-missing-account": reset(200_000_000_000L,false,0,true,true); create(id,MISSING,URL.getBytes(StandardCharsets.UTF_8)); break;
      case "witness-update-success": reset(1,true,0,true,true); update(id,OWNER,NEW_URL.getBytes(StandardCharsets.UTF_8)); break;
      case "witness-update-empty-url": reset(1,true,0,true,true); update(id,OWNER,new byte[0]); break;
      case "witness-update-missing-witness": reset(1,false,0,true,true); update(id,OWNER,NEW_URL.getBytes(StandardCharsets.UTF_8)); break;
      case "vote-success-reward-before-reload": reset(1,true,2_000_000L,true,true); vote(id,OWNER,1); break;
      case "vote-duplicate-order": reset(1,true,3_000_000L,true,true); vote(id,OWNER,1,1,1); break;
      case "vote-insufficient-power": reset(1,true,0,true,true); vote(id,OWNER,1); break;
      case "vote-missing-candidate-account": reset(1,true,2_000_000L,false,true); vote(id,OWNER,1); break;
      case "vote-missing-witness": reset(1,true,2_000_000L,true,false); vote(id,OWNER,1); break;
      case "vote-nonpositive": reset(1,true,2_000_000L,true,true); vote(id,OWNER,0); break;
      default: throw new IllegalArgumentException(id);
    }
  }

  private String json() { return "{\"schema\":\"c012-witness-real-v1\",\"java_revision\":\"4a21592f95e37908b21bc3f611c6e7a1a67f09f3\",\"jdk\":\"8\",\"source_method_count\":30,\"scenario_count\":"+rows.size()+",\"execution_model\":\"fresh-database-per-scenario; nested execution commit observed in parent then parent revoke observed at root\",\"stable_ids\":[\"TCASE-0C3973926C580E23\",\"TCASE-114223AE3B4005C1\",\"TCASE-144207F246D3996D\",\"TCASE-1759AB28D83FFBD1\",\"TCASE-1C63F818089EAC1C\",\"TCASE-2562BB36C2724142\",\"TCASE-31680E30EB7E67FC\",\"TCASE-5B51E4838875DA31\",\"TCASE-5E15A6A247E10E30\",\"TCASE-6191ACFED7C38024\",\"TCASE-67189D92322C23C8\",\"TCASE-71AF0A989B79D610\",\"TCASE-764C8F17A2FA73AE\",\"TCASE-8106D8D3B67972AA\",\"TCASE-8B6650B8003FD547\",\"TCASE-96DA2C4827F0F315\",\"TCASE-9F67A3E0DDF90924\",\"TCASE-AE6568C2CD72C88E\",\"TCASE-BFBC4B9EA96D29A6\",\"TCASE-C2DC20F04D52AF82\",\"TCASE-CD03932A6A50DB2A\",\"TCASE-D0A60F7B4CCAC62A\",\"TCASE-D1CFD16190ABC1DA\",\"TCASE-D3EFFF06E674C529\",\"TCASE-D5F8BCD4C82E9436\",\"TCASE-DA059C406B6F9DB8\",\"TCASE-DFEE79101A774EAA\",\"TCASE-E18285E3DA6CD709\",\"TCASE-ECC115A467CD50B8\",\"TCASE-EF78EA45874E6E03\"],\"equivalence_justification\":\"Thirty assigned JUnit methods reduce to fifteen distinct direct contract/state boundaries without skipped contracts; repeated assertions within multi-step methods map to the same explicit boundary. Each row is independently executed against a fresh Java database and records committed state plus root state after revoke.\",\"scenarios\":["+String.join(",",rows)+"]}\n"; }
  public static void main(String[] args) throws Exception {
    if(args.length!=1)throw new IllegalArgumentException("output path required");
    String[] ids={"witness-create-success-default-permission","witness-create-existing","witness-create-invalid-address","witness-create-empty-url","witness-create-insufficient-balance","witness-create-missing-account","witness-update-success","witness-update-empty-url","witness-update-missing-witness","vote-success-reward-before-reload","vote-duplicate-order","vote-insufficient-power","vote-missing-candidate-account","vote-missing-witness","vote-nonpositive"};
    Path root=Files.createTempDirectory("c012-witness-"); C012WitnessOracle last=null;
    for(String id:ids){last=new C012WitnessOracle(root.resolve(id));try{last.run(id);}finally{last.app.close();Args.clearParam();}}
    Files.write(new File(args[0]).toPath(),last.json().getBytes(StandardCharsets.UTF_8)); System.out.flush(); Runtime.getRuntime().halt(0);
  }

}
