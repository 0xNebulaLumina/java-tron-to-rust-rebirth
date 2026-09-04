package org.tron.core.actuator;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.tron.common.TestConstants;
import org.tron.common.utils.ByteArray;
import org.tron.core.ChainBaseManager;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.ContractCapsule;
import org.tron.core.capsule.TransactionResultCapsule;
import org.tron.core.config.DefaultConfig;
import org.tron.core.config.args.Args;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.contract.SmartContractOuterClass.SmartContract;
import org.tron.protos.Protocol.Transaction.Contract;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.AssetIssueContractOuterClass.AssetIssueContract;
import org.tron.protos.contract.BalanceContract.TransferContract;

/** Direct deterministic Java actuator evidence for C012.02. */
public final class C012TransferReal {
  private static final byte[] OWNER=ByteArray.fromHexString("41548794500882809695a8a687866e76d4271a1abc");
  private static final byte[] TO=ByteArray.fromHexString("41abd4b9367799eaa3197fecb144eb71de1e049abc");
  private static final byte[] MISSING=ByteArray.fromHexString("41548794500882809695a8a687866e76d4271a3422");
  private static final byte[] NO_OWNER=ByteArray.fromHexString("41548794500882809695a8a687866e76d4271a3456");
  private static final long OWNER_BALANCE=9_999_999L, TO_BALANCE=100_001L, CREATE_FEE=100_000L;
  private C012TransferReal() {}
  private static String q(String s){return "\""+s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n")+"\"";}
  private static String hex(byte[] b){return ByteArray.toHexString(b);} private static String nh(byte[] b){return b==null?"null":q(hex(b));}
  private static byte[] data(AccountCapsule a){return a==null?null:a.getData();}
  private static AccountCapsule account(byte[] address,String name,AccountType type,long balance){return new AccountCapsule(ByteString.copyFromUtf8(name),ByteString.copyFrom(address),type,balance);}
  private static String delta(byte[] key,byte[] before,byte[] after){return "{\"store\":\"Account\",\"key_hex\":"+q(hex(key))+",\"before_hex\":"+nh(before)+",\"after_hex\":"+nh(after)+"}";}
  public static void main(String[] args)throws Exception{
    if(args.length!=3||!"--scenario".equals(args[0]))throw new IllegalArgumentException("usage: --scenario ID DB_DIR");
    String id=args[1],db=args[2]; Args.setParam(new String[]{"--output-directory",db},TestConstants.TEST_CONF);
    AnnotationConfigApplicationContext spring=new AnnotationConfigApplicationContext(DefaultConfig.class); String observation;
    try{
      ChainBaseManager m=spring.getBean(ChainBaseManager.class);
      m.getDynamicPropertiesStore().saveLatestBlockHeaderTimestamp(1_700_000_000_000L); m.getDynamicPropertiesStore().saveCreateNewAccountFeeInSystemContract(CREATE_FEE); m.getDynamicPropertiesStore().saveAllowMultiSign(0); m.getDynamicPropertiesStore().saveAllowBlackHoleOptimization(0); m.getDynamicPropertiesStore().saveForbidTransferToContract(0); m.getDynamicPropertiesStore().saveAllowTvmCompatibleEvm(0);
      AccountCapsule owner=account(OWNER,"owner",AccountType.Normal,OWNER_BALANCE); AccountCapsule to=account(TO,"to",AccountType.Normal,TO_BALANCE); m.getAccountStore().put(OWNER,owner); m.getAccountStore().put(TO,to);
      byte[] ownerAddress=OWNER,toAddress=TO; long amount=100L; Any any; ContractType type=ContractType.TransferContract;
      if(id.equals("perfect"))amount=OWNER_BALANCE;
      else if(id.equals("more"))amount=OWNER_BALANCE+1;
      else if(id.equals("invalid-owner"))ownerAddress=new byte[]{(byte)0xaa,(byte)0xaa};
      else if(id.equals("invalid-to"))toAddress=new byte[]{(byte)0xbb};
      else if(id.equals("self"))toAddress=OWNER;
      else if(id.equals("missing-owner"))ownerAddress=NO_OWNER;
      else if(id.equals("new-account")){toAddress=MISSING;amount=1_000_000L;}
      else if(id.equals("zero"))amount=0;
      else if(id.equals("negative"))amount=-100;
      else if(id.equals("recipient-overflow")){to.setBalance(Long.MAX_VALUE);m.getAccountStore().put(TO,to);amount=1;}
      else if(id.equals("insufficient-fee")){owner.setBalance(-10_000L);m.getAccountStore().put(OWNER,owner);toAddress=MISSING;amount=100;}
      else if(id.startsWith("contract-")){to=account(TO,"contract",AccountType.Contract,TO_BALANCE);m.getAccountStore().put(TO,to);if(id.equals("contract-forbid"))m.getDynamicPropertiesStore().saveForbidTransferToContract(1);if(id.startsWith("contract-compatible")){m.getDynamicPropertiesStore().saveAllowTvmCompatibleEvm(1);if(id.equals("contract-compatible-v1")){SmartContract sc=SmartContract.newBuilder().setContractAddress(ByteString.copyFrom(TO)).setOriginAddress(ByteString.copyFrom(OWNER)).setVersion(1).build();m.getContractStore().put(TO,new ContractCapsule(sc));}}}
      TransferContract msg=TransferContract.newBuilder().setOwnerAddress(ByteString.copyFrom(ownerAddress)).setToAddress(ByteString.copyFrom(toAddress)).setAmount(amount).build(); any=Any.pack(msg);
      if(id.equals("wrong-type")){any=Any.pack(AssetIssueContract.getDefaultInstance());}
      Contract full=Contract.newBuilder().setType(type).setParameter(any).build(); TransferActuator actuator=new TransferActuator(); actuator.setChainBaseManager(m).setAny(any);
      byte[] ownerBefore=data(m.getAccountStore().get(OWNER)),toBefore=data(m.getAccountStore().get(TO)),missingBefore=data(m.getAccountStore().get(MISSING)); TransactionResultCapsule result=new TransactionResultCapsule();String error=null;
      try{if(id.equals("no-contract"))actuator.setAny(null);if(id.equals("null-manager"))actuator.setChainBaseManager(null);actuator.validate();actuator.execute(id.equals("null-result")?null:result);}catch(Exception e){error=e.getMessage();}
      byte[] ownerAfter=data(m.getAccountStore().get(OWNER)),toAfter=data(m.getAccountStore().get(TO)),missingAfter=data(m.getAccountStore().get(MISSING));List<String> changed=new ArrayList<>();if(!java.util.Arrays.equals(ownerBefore,ownerAfter))changed.add(delta(OWNER,ownerBefore,ownerAfter));if(!java.util.Arrays.equals(toBefore,toAfter))changed.add(delta(TO,toBefore,toAfter));if(!java.util.Arrays.equals(missingBefore,missingAfter))changed.add(delta(MISSING,missingBefore,missingAfter));
      observation="{\"scenario_id\":"+q(id)+",\"contract_type\":"+type.getNumber()+",\"contract_hex\":"+q(hex(full.toByteArray()))+",\"any_hex\":"+q(hex(any.toByteArray()))+",\"result\":{\"code\":"+q(result.getInstance().getRet().name())+",\"error\":"+(error==null?"null":q(error))+",\"fee\":"+result.getInstance().getFee()+",\"asset_id_hex\":"+q(hex(result.getInstance().getAssetIssueID().getBytes("UTF-8")))+"},\"changed\":["+String.join(",",changed)+"],\"committed_reopen\":{\"owner_hex\":"+nh(ownerAfter)+",\"to_hex\":"+nh(toAfter)+",\"missing_hex\":"+nh(missingAfter)+"},\"rollback_root\":{\"owner_hex\":"+nh(ownerBefore)+",\"to_hex\":"+nh(toBefore)+",\"missing_hex\":"+nh(missingBefore)+"}}";
    }finally{}
    System.out.println("C012_TRANSFER_REAL="+Base64.getEncoder().encodeToString(observation.getBytes("UTF-8")));System.out.flush();Runtime.getRuntime().halt(0);
  }
}
