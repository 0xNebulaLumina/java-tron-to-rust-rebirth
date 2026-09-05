import com.google.protobuf.ByteString;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.tron.common.TestConstants;
import org.tron.common.utils.ForkController;
import org.tron.consensus.dpos.DposService;
import org.tron.consensus.dpos.DposSlot;
import org.tron.consensus.dpos.MaintenanceManager;
import org.tron.consensus.dpos.StatisticManager;
import org.tron.core.ChainBaseManager;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.config.DefaultConfig;
import org.tron.core.config.args.Args;
import org.tron.core.consensus.ProposalController;
import org.tron.core.db.Manager;
import org.tron.core.service.MortgageService;
import org.tron.core.store.DynamicPropertiesStore;
import org.tron.protos.Protocol;
import org.tron.core.services.WitnessProductBlockService;
import org.tron.core.db.TronStoreWithRevoking;
import org.tron.core.db2.ISession;

public final class C017Oracle {
  private static final long GENESIS = 1_600_000_000_000L;
  private static final long FIXED = 1_600_000_090_000L;
  private static final class Row implements Comparable<Row> {
    final String store; final byte[] key; final byte[] value;
    Row(String store, byte[] key, byte[] value) { this.store=store; this.key=key; this.value=value; }
    public int compareTo(Row other) { int c=store.compareTo(other.store); return c!=0?c:compare(key,other.key); }
  }
  private static int compare(byte[] a,byte[] b){for(int i=0;i<Math.min(a.length,b.length);i++){int c=Integer.compare(a[i]&255,b[i]&255);if(c!=0)return c;}return Integer.compare(a.length,b.length);}
  private static byte[] address(int n){byte[] out=new byte[21];out[0]=0x41;Arrays.fill(out,1,21,(byte)n);return out;}
  private static String hex(byte[] bytes){StringBuilder s=new StringBuilder();for(byte b:bytes)s.append(String.format("%02x",b&255));return s.toString();}
  private static void field(ByteArrayOutputStream out,byte[] bytes){out.write((bytes.length>>>24)&255);out.write((bytes.length>>>16)&255);out.write((bytes.length>>>8)&255);out.write(bytes.length&255);out.write(bytes,0,bytes.length);}
  private static String root(Collection<Row> source)throws Exception{List<Row> rows=new ArrayList<>(source);Collections.sort(rows);ByteArrayOutputStream out=new ByteArrayOutputStream();for(Row row:rows){field(out,row.store.getBytes("UTF-8"));field(out,row.key);field(out,row.value);}return hex(MessageDigest.getInstance("SHA-256").digest(out.toByteArray()));}
  private static String quote(String value){return "\""+value.replace("\\","\\\\").replace("\"","\\\"")+"\"";}
  private static String rowsJson(List<Row> rows){List<String> out=new ArrayList<>();for(Row r:rows)out.add("{\"store\":"+quote(r.store)+",\"key\":"+quote(hex(r.key))+",\"value\":"+quote(hex(r.value))+"}");return "["+String.join(",",out)+"]";}
  private static void set(Object target,String name,Object value)throws Exception{Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);f.set(target,value);}
  private static BlockCapsule block(long number,long time,ByteString witness,int version){Protocol.BlockHeader.raw raw=Protocol.BlockHeader.raw.newBuilder().setNumber(number).setTimestamp(time).setWitnessAddress(witness).setVersion(version).build();return new BlockCapsule(Protocol.Block.newBuilder().setBlockHeader(Protocol.BlockHeader.newBuilder().setRawData(raw)).build());}
  private static List<Row> allRows(AnnotationConfigApplicationContext context){List<Row> rows=new ArrayList<>();Set<String> seen=new HashSet<>();for(TronStoreWithRevoking<?> store:context.getBeansOfType(TronStoreWithRevoking.class).values()){String name=store.getDb().getDbName();if(name==null||!seen.add(name))continue;try{Iterator<Map.Entry<byte[],byte[]>> it=store.getRevokingDB().iterator();while(it.hasNext()){Map.Entry<byte[],byte[]> e=it.next();rows.add(new Row(name,e.getKey(),e.getValue()));}}catch(UnsupportedOperationException inaccessible){/* TxCacheDB deliberately exposes no logical iterator. */}}Collections.sort(rows);return rows;}
  private static List<Row> headRows(AnnotationConfigApplicationContext context){return allRows(context);}
  private static String cursorJson(DynamicPropertiesStore dynamic){return "{\"latest_block_header_number\":"+quote(hex(dynamic.getUnchecked("latest_block_header_number".getBytes()).getData()))+",\"next_maintenance_time\":"+quote(hex(dynamic.getUnchecked("NEXT_MAINTENANCE_TIME".getBytes()).getData()))+"}";}
  private static String snapshot(String step,AnnotationConfigApplicationContext context,DynamicPropertiesStore dynamic)throws Exception{List<Row> rows=headRows(context);return "{\"step\":"+quote(step)+",\"event\":"+quote(step)+",\"cursor\":"+cursorJson(dynamic)+",\"rows\":"+rowsJson(rows)+",\"root\":"+quote(root(rows))+"}";}
  public static void main(String[] args)throws Exception{
    Path db=Files.createTempDirectory("c017-real-java-");Args.setParam(new String[]{"-d",db.toString(),"--p2p-disable","true"},TestConstants.TEST_CONF);
    AnnotationConfigApplicationContext context=new AnnotationConfigApplicationContext(DefaultConfig.class);
    try {
      ChainBaseManager chain=context.getBean(ChainBaseManager.class);Manager manager=context.getBean(Manager.class);DynamicPropertiesStore dynamic=chain.getDynamicPropertiesStore();
      DposService dpos=context.getBean(DposService.class);DposSlot slot=context.getBean(DposSlot.class);StatisticManager statistic=context.getBean(StatisticManager.class);MaintenanceManager maintenance=context.getBean(MaintenanceManager.class);MortgageService mortgage=context.getBean(MortgageService.class);
      long[] votes={1000,999,998,997,996,995,994,993,992,991,990,989,988,987,986,985,984,983,982,981,980,979,978,977,976,975,974};List<ByteString> active=new ArrayList<>();
      for(int i=0;i<27;i++){byte[] a=address(i);ByteString bs=ByteString.copyFrom(a);active.add(bs);WitnessCapsule w=new WitnessCapsule(Protocol.Witness.newBuilder().setAddress(bs).setVoteCount(votes[i]).setIsJobs(true).setLatestBlockNum(i).build());AccountCapsule ac=new AccountCapsule(Protocol.Account.newBuilder().setAddress(bs).setBalance(1_000_000L+i).build());chain.getWitnessStore().put(a,w);chain.getAccountStore().put(a,ac);}
      chain.getWitnessScheduleStore().saveActiveWitnesses(active);chain.getWitnessScheduleStore().saveCurrentShuffledWitnesses(active);
      dynamic.saveLatestBlockHeaderNumber(0);dynamic.saveLatestBlockHeaderTimestamp(GENESIS);dynamic.saveNextMaintenanceTime(FIXED);dynamic.saveMaintenanceTimeInterval(18_000);dynamic.saveLatestSolidifiedBlockNum(0);dynamic.saveLatestProposalNum(0);dynamic.saveCurrentCycleNumber(0);dynamic.saveChangeDelegation(1);dynamic.saveRemoveThePowerOfTheGr(0);dynamic.saveWitnessPayPerBlock(10);dynamic.saveWitness127PayPerBlock(100);
      set(dpos,"genesisBlockTime",GENESIS);set(slot,"dposService",dpos);set(maintenance,"dposService",dpos);
      dpos.updateWitness(active);List<Integer> schedule=new ArrayList<>();for(ByteString a:chain.getWitnessScheduleStore().getActiveWitnesses())schedule.add(a.byteAt(1)&255);
      List<Row> initial=allRows(context);String initialRoot=root(initial);List<String> events=new ArrayList<>();List<String> snapshots=new ArrayList<>();List<Integer> produced=new ArrayList<>();List<Integer> missed=new ArrayList<>();
      long queried;boolean forkPass;List<Row> head;String headRoot;String dynamicNumber;String dynamicMaintenance;
      WitnessProductBlockService duplicateService=new WitnessProductBlockService();long futureTime=FIXED+30_000_000L;ByteString localWitness=active.get(7);duplicateService.validWitnessProductTwoBlock(block(400,futureTime,localWitness,5));duplicateService.validWitnessProductTwoBlock(block(400,futureTime,localWitness,6));WitnessProductBlockService.CheatWitnessInfo futureDuplicate=duplicateService.queryCheatWitnessInfo().values().iterator().next();if(duplicateService.queryCheatWitnessInfo().size()!=1||futureDuplicate.getBlockCapsuleSet().size()!=2)throw new AssertionError("future local witness duplicate was not retained");
      try(ISession outer=manager.getRevokingStore().buildSession()){
        dynamic.saveLatestBlockHeaderNumber(29);dynamic.saveLatestBlockHeaderTimestamp(FIXED-3_000);BlockCapsule production=block(30,FIXED,slot.getScheduledWitness(1),5);if(!dpos.validBlock(production))throw new AssertionError("DposService.validBlock rejected scheduled block");statistic.applyBlock(production);produced.add(production.getWitnessAddress().byteAt(1)&255);events.add("statistic.applyBlock");snapshots.add(snapshot("statistic.applyBlock",context,dynamic));
        mortgage.payBlockReward(active.get(0).toByteArray(),10);queried=mortgage.queryReward(active.get(0).toByteArray());mortgage.withdrawReward(active.get(0).toByteArray());events.add("mortgage.reward-query-withdraw");snapshots.add(snapshot("mortgage.reward-query-withdraw",context,dynamic));
        maintenance.doMaintenance();events.add("maintenance.doMaintenance");snapshots.add(snapshot("maintenance.doMaintenance",context,dynamic));
        ProposalController.createInstance(manager).processProposals();events.add("proposal.processProposals");snapshots.add(snapshot("proposal.processProposals",context,dynamic));
        dynamic.saveNextMaintenanceTime(FIXED+18_000);dpos.applyBlock(production);events.add("dpos.applyBlock");snapshots.add(snapshot("dpos.applyBlock",context,dynamic));
        ForkController.instance().init(chain);ForkController.instance().update(production);forkPass=ForkController.instance().pass(5);events.add("fork.update");snapshots.add(snapshot("fork.update",context,dynamic));
        head=headRows(context);headRoot=root(head);dynamicNumber=hex(dynamic.getUnchecked("latest_block_header_number".getBytes()).getData());dynamicMaintenance=hex(dynamic.getUnchecked("NEXT_MAINTENANCE_TIME".getBytes()).getData());
      }
      List<Row> rollback=allRows(context);String rollbackRoot=root(rollback);if(!rollbackRoot.equals(initialRoot))throw new AssertionError("outer revoking session failed to restore full logical state");
      System.out.println("{\"schema\":\"c017-java-oracle-v4\",\"root_schema\":\"canonical-db-name+raw-key+raw-value-v1\",\"rollback_event\":\"outer-session-close\",\"genesis_time\":"+GENESIS+",\"fixed_time\":"+FIXED+",\"witnesses\":27,\"future_local_duplicate\":{\"cheat_entries\":"+duplicateService.queryCheatWitnessInfo().size()+",\"blocks\":"+futureDuplicate.getBlockCapsuleSet().size()+"},\"initial_rows\":"+rowsJson(initial)+",\"initial_root\":"+quote(initialRoot)+",\"schedule\":"+schedule.toString().replace(" ","")+",\"produced\":"+produced.toString().replace(" ","")+",\"missed\":"+missed+",\"reward_query\":"+queried+",\"fork_pass\":"+forkPass+",\"dynamic_bytes\":{\"LATEST_BLOCK_HEADER_NUMBER\":"+quote(dynamicNumber)+",\"NEXT_MAINTENANCE_TIME\":"+quote(dynamicMaintenance)+"},\"snapshots\":["+String.join(",",snapshots)+"],\"events\":"+events.toString().replace(" ","").replaceAll("([A-Za-z.\\-]+)","\\\"$1\\\"")+",\"head_rows\":"+rowsJson(head)+",\"head_root\":"+quote(headRoot)+",\"rollback_rows\":"+rowsJson(rollback)+",\"rollback_root\":"+quote(rollbackRoot)+"}");
      System.out.flush();
      System.exit(0);
    } finally { context.close();Args.clearParam(); }
  }
}
