// Java 8-compatible C008 logical codec oracle, compiled against pinned java-tron protobufs.
import com.google.protobuf.ByteString;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Message;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.tron.common.utils.ByteArray;
import org.tron.core.capsule.BytesCapsule;
import org.tron.protos.Protocol;

public final class C008Oracle {
  private static final String[][] STORES = {
    {"Account","account"},{"AccountIdIndex","accountid-index"},{"AccountIndex","account-index"},{"AccountAsset","account-asset"},
    {"AssetIssue","asset-issue"},{"AssetIssueV2","asset-issue-v2"},{"Block","block"},{"BlockIndex","block-index"},
    {"Transaction","trans"},{"TransactionCache","trans-cache"},{"TransactionRet","transactionRetStore"},{"TransactionHistory","transactionHistoryStore"},
    {"RecentBlock","recent-block"},{"RecentTransaction","recent-transaction"},{"Contract","contract"},{"Abi","abi"},{"Code","code"},
    {"ContractState","contract-state"},{"StorageRow","storage-row"},{"Witness","witness"},{"WitnessSchedule","witness_schedule"},{"Votes","votes"},
    {"Proposal","proposal"},{"Exchange","exchange"},{"ExchangeV2","exchange-v2"},{"MarketAccount","market_account"},{"MarketOrder","market_order"},
    {"MarketPairToPrice","market_pair_to_price"},{"MarketPairPriceToOrder","market_pair_price_to_order"},{"DelegatedResource","DelegatedResource"},
    {"DelegatedResourceAccountIndex","DelegatedResourceAccountIndex"},{"DynamicProperties","properties"},{"IncrementalMerkleTree","IncrementalMerkleTree"},
    {"Nullifier","nullifier"},{"ZkProof","zkProof"},{"TreeBlockIndex","tree-block-index"},{"SectionBloom","section-bloom"},{"AccountTrace","account-trace"},
    {"BalanceTrace","balance-trace"},{"Delegation","delegation"},{"Pbft","pbft-sign-data"},{"RewardVi","reward-vi"},{"Common","common"},
    {"Checkpoint","checkpoint"},{"Temporary","tmp"}
  };
  // Capsule inventory class, actual generated protobuf class. Null denotes a genuinely raw capsule.
  private static final String[][] CAPSULES = {
    {"AbiCapsule","org.tron.protos.contract.SmartContractOuterClass$SmartContract$ABI"},
    {"AccountCapsule","org.tron.protos.Protocol$Account"},{"AccountTraceCapsule","org.tron.protos.contract.BalanceContract$AccountTrace"},
    {"AssetIssueCapsule","org.tron.protos.contract.AssetIssueContractOuterClass$AssetIssueContract"},
    {"BlockBalanceTraceCapsule","org.tron.protos.contract.BalanceContract$BlockBalanceTrace"},{"BlockCapsule","org.tron.protos.Protocol$Block"},
    {"BytesCapsule",null},{"CodeCapsule",null},{"ContractCapsule","org.tron.protos.contract.SmartContractOuterClass$SmartContract"},
    {"ContractStateCapsule","org.tron.protos.contract.SmartContractOuterClass$ContractState"},{"DelegatedResourceAccountIndexCapsule","org.tron.protos.Protocol$DelegatedResourceAccountIndex"},
    {"DelegatedResourceCapsule","org.tron.protos.Protocol$DelegatedResource"},{"ExchangeCapsule","org.tron.protos.Protocol$Exchange"},
    {"IncrementalMerkleTreeCapsule","org.tron.protos.contract.ShieldContract$IncrementalMerkleTree"},
    {"IncrementalMerkleVoucherCapsule","org.tron.protos.contract.ShieldContract$IncrementalMerkleVoucher"},
    {"MarketAccountOrderCapsule","org.tron.protos.Protocol$MarketAccountOrder"},{"MarketOrderCapsule","org.tron.protos.Protocol$MarketOrder"},
    {"MarketOrderIdListCapsule","org.tron.protos.Protocol$MarketOrderIdList"},{"MarketPriceCapsule","org.tron.protos.Protocol$MarketPrice"},
    {"PbftSignCapsule","org.tron.protos.Protocol$PBFTCommitResult"},{"PedersenHashCapsule","org.tron.protos.contract.ShieldContract$PedersenHash"},
    {"ProposalCapsule","org.tron.protos.Protocol$Proposal"},{"ProtoCapsule",null},{"ReceiptCapsule","org.tron.protos.Protocol$ResourceReceipt"},
    {"StorageRowCapsule",null},{"TransactionCapsule","org.tron.protos.Protocol$Transaction"},{"TransactionInfoCapsule","org.tron.protos.Protocol$TransactionInfo"},
    {"TransactionResultCapsule","org.tron.protos.Protocol$Transaction$Result"},{"TransactionRetCapsule","org.tron.protos.Protocol$TransactionRet"},
    {"VotesCapsule","org.tron.protos.Protocol$Votes"},{"WitnessCapsule","org.tron.protos.Protocol$Witness"}
  };

  public static void main(String[] args) throws Exception {
    if (!ByteArray.class.getName().equals("org.tron.common.utils.ByteArray")) throw new AssertionError();
    byte[] account = Protocol.Account.newBuilder().setAddress(ByteString.copyFrom(new byte[]{0x41, 1})).setBalance(2).build().toByteArray();
    for (int i=0;i<STORES.length;i++) {
      String kind=STORES[i][0]; byte[] key=key(kind,i+1); byte[] value=value(kind,i+1,account);
      System.out.println("store\tstore-"+kind+"\t"+kind+"\t"+STORES[i][1]+"\t"+hex(key)+"\t"+hex(value)+"\t\t");
    }
    for (int i=0;i<CAPSULES.length;i++) {
      String capsule=CAPSULES[i][0], className=CAPSULES[i][1];
      if (className==null) {
        byte[] raw=new BytesCapsule(new byte[]{(byte)(i+1),0x55}).getData();
        System.out.println("capsule\tcapsule-"+capsule+"\t"+capsule+"\t\t\t"+hex(raw)+"\t\t");
      } else {
        Message prototype=(Message)Class.forName(className).getMethod("getDefaultInstance").invoke(null);
        Message.Builder builder=prototype.newBuilderForType(); FieldDescriptor field=populate(builder,i+1); byte[] known=builder.buildPartial().toByteArray();
        if (known.length==0) throw new AssertionError("empty protobuf for "+capsule);
        byte[] unknown=concat(known,new byte[]{(byte)0xf8,0x07,0x01});
        System.out.println("capsule\tcapsule-"+capsule+"\t"+capsule+"\t\t\t"+hex(known)+"\t"+hex(unknown)+"\t"+field.getNumber());
      }
    }
  }

  private static FieldDescriptor populate(Message.Builder builder,int seed) {
    for (FieldDescriptor field:builder.getDescriptorForType().getFields()) {
      Object value=field.getJavaType()==FieldDescriptor.JavaType.MESSAGE ? populatedMessage(builder,field,seed) : scalar(field,seed);
      if (value==null) continue;
      if (field.isRepeated()) builder.addRepeatedField(field,value); else builder.setField(field,value);
      return field;
    }
    throw new AssertionError("no settable field in "+builder.getDescriptorForType().getFullName());
  }
  private static Message populatedMessage(Message.Builder parent,FieldDescriptor field,int seed) {
    Message.Builder child=parent.newBuilderForField(field); populate(child,seed+1); return child.buildPartial();
  }
  private static Object scalar(FieldDescriptor f,int n) {
    switch(f.getJavaType()) {
      case INT:return n; case LONG:return (long)n; case FLOAT:return (float)n; case DOUBLE:return (double)n; case BOOLEAN:return true;
      case STRING:return "c008-"+n; case BYTE_STRING:return ByteString.copyFrom(new byte[]{0x41,(byte)n});
      case ENUM:return f.getEnumType().getValues().get(Math.min(1,f.getEnumType().getValues().size()-1)); default:return null;
    }
  }
  private static byte[] key(String kind,int n){if(kind.equals("Account"))return new byte[]{0x41,1};if(kind.equals("AccountIdIndex"))return "mixed-case-id".toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);if(kind.equals("AccountIndex"))return "account-name".getBytes(StandardCharsets.UTF_8);if(kind.equals("AccountAsset"))return concat(new byte[]{0x41,1},"1000001".getBytes(StandardCharsets.UTF_8));if(kind.equals("RecentBlock"))return new byte[]{0x12,0x34};if(kind.equals("WitnessSchedule"))return "active_witnesses".getBytes(StandardCharsets.UTF_8);if(kind.equals("StorageRow"))return concat(sequence(16,1),sequence(16,17));if(kind.equals("MarketPairToPrice"))return concat(rightPad("1000001",19),rightPad("1000002",19));if(kind.equals("MarketPairPriceToOrder"))return concat(rightPad("1000001",19),rightPad("1000002",19),i64(1),i64(2));if(kind.equals("DelegatedResource"))return concat(new byte[]{2},sequence(21,1),sequence(21,22));return i64(n);}
  private static byte[] value(String kind,int n,byte[] account){if(kind.equals("Account"))return account;if(kind.equals("AccountAsset")||kind.equals("BlockIndex")||kind.equals("TransactionHistory"))return i64(n);if(kind.equals("RecentBlock"))return capsuleBytes(sequence(8,8));if(kind.equals("Code"))return capsuleBytes(new byte[]{0x60,0,0x56});if(kind.equals("StorageRow"))return capsuleBytes(sequence(32,1));if(kind.equals("WitnessSchedule"))return capsuleBytes(concat(sequence(21,1),sequence(21,22)));if(kind.equals("ZkProof"))return capsuleBytes(new byte[]{1});if(kind.equals("MarketPairToPrice"))return capsuleBytes(i64(n));return capsuleBytes(new byte[0]);}
  private static byte[] capsuleBytes(byte[] value){return new BytesCapsule(value).getData();} private static byte[] rightPad(String s,int n){byte[]in=s.getBytes(StandardCharsets.UTF_8),out=new byte[n];System.arraycopy(in,0,out,0,in.length);return out;} private static byte[] i64(long n){byte[]b=new byte[8];for(int i=7;i>=0;i--){b[i]=(byte)n;n>>=8;}return b;} private static byte[] sequence(int n,int start){byte[]b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(start+i);return b;} private static byte[] concat(byte[]...xs){int n=0;for(byte[]x:xs)n+=x.length;byte[]o=new byte[n];int p=0;for(byte[]x:xs){System.arraycopy(x,0,o,p,x.length);p+=x.length;}return o;} private static String hex(byte[]b){StringBuilder s=new StringBuilder(b.length*2);for(byte x:b)s.append(String.format("%02x",x&255));return s.toString();}
}
