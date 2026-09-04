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
import org.tron.core.capsule.TransactionResultCapsule;
import org.tron.core.config.DefaultConfig;
import org.tron.core.config.args.Args;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.Key;
import org.tron.protos.Protocol.Permission;
import org.tron.protos.Protocol.Permission.PermissionType;
import org.tron.protos.Protocol.Transaction.Contract;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.AccountContract.AccountCreateContract;
import org.tron.protos.contract.AccountContract.AccountPermissionUpdateContract;
import org.tron.protos.contract.AccountContract.AccountUpdateContract;
import org.tron.protos.contract.AccountContract.SetAccountIdContract;

/** Direct deterministic Java actuator evidence for C012.01. */
public final class C012AccountReal {
  private static final byte[] OWNER = ByteArray.fromHexString("41548794500882809695a8a687866e76d4271a1abc");
  private static final byte[] TARGET = ByteArray.fromHexString("41abd4b9367799eaa3197fecb144eb71de1e049abc");
  private static final byte[] KEY = ByteArray.fromHexString("418cfc572cc20ca18b636bdd93b4fb15ea84cc2b4e");
  private static final long BALANCE = 100_000_000L;
  private C012AccountReal() {}
  private static String q(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""; }
  private static String hex(byte[] b) { return ByteArray.toHexString(b); }
  private static String nh(byte[] b) { return b == null ? "null" : q(hex(b)); }
  private static byte[] data(AccountCapsule a) { return a == null ? null : a.getData(); }
  private static AccountCapsule account(byte[] address, String name, long balance) {
    return new AccountCapsule(ByteString.copyFromUtf8(name), ByteString.copyFrom(address), AccountType.Normal, balance);
  }
  private static Permission permission(PermissionType type, int id, String name, long threshold, byte[] operations, byte[]... keys) {
    Permission.Builder b = Permission.newBuilder().setType(type).setId(id).setPermissionName(name).setThreshold(threshold).setParentId(0).setOperations(ByteString.copyFrom(operations));
    for (byte[] key : keys) b.addKeys(Key.newBuilder().setAddress(ByteString.copyFrom(key)).setWeight(1));
    return b.build();
  }
  private static String delta(String store, byte[] key, byte[] before, byte[] after) {
    return "{\"store\":"+q(store)+",\"key_hex\":"+q(hex(key))+",\"before_hex\":"+nh(before)+",\"after_hex\":"+nh(after)+"}";
  }
  public static void main(String[] args) throws Exception {
    if (args.length != 3 || !"--scenario".equals(args[0])) throw new IllegalArgumentException("usage: --scenario ID DB_DIR");
    String id=args[1], db=args[2];
    Args.setParam(new String[]{"--output-directory",db}, TestConstants.TEST_CONF);
    AnnotationConfigApplicationContext spring=new AnnotationConfigApplicationContext(DefaultConfig.class);
    String observation;
    try {
      ChainBaseManager m=spring.getBean(ChainBaseManager.class);
      m.getDynamicPropertiesStore().saveLatestBlockHeaderTimestamp(1_700_000_000_000L);
      m.getDynamicPropertiesStore().saveAllowMultiSign(1);
      m.getDynamicPropertiesStore().saveTotalSignNum(5);
      m.getDynamicPropertiesStore().saveAllowUpdateAccountName(0);
      m.getDynamicPropertiesStore().saveCreateNewAccountFeeInSystemContract(100_000L);
      m.getDynamicPropertiesStore().saveAllowBlackHoleOptimization(0);
      AccountCapsule owner=account(OWNER,id.startsWith("update-")?"":"owner",BALANCE); m.getAccountStore().put(OWNER,owner);
      byte[] ownerBefore=data(owner), targetBefore=null, indexBefore=null;
      Any any; ContractType type; Actuator actuator;
      if (id.startsWith("create-")) {
        byte[] ownerAddress=OWNER, target=TARGET;
        if (id.equals("create-existing")) { m.getAccountStore().put(TARGET,account(TARGET,"target",1)); targetBefore=data(m.getAccountStore().get(TARGET)); }
        if (id.equals("create-missing-owner")) { ownerAddress=KEY; }
        if (id.equals("create-invalid-target")) { target=new byte[]{1,2,3}; }
        if (id.equals("create-insufficient")) { owner.setBalance(1); m.getAccountStore().put(OWNER,owner); ownerBefore=data(owner); }
        AccountCreateContract msg=AccountCreateContract.newBuilder().setOwnerAddress(ByteString.copyFrom(ownerAddress)).setAccountAddress(ByteString.copyFrom(target)).build();
        any=Any.pack(msg); type=ContractType.AccountCreateContract; actuator=new CreateAccountActuator(); ((CreateAccountActuator)actuator).setChainBaseManager(m).setAny(any);
      } else if (id.startsWith("update-")) {
        byte[] address=id.equals("update-invalid-address")?new byte[]{1,2}:id.equals("update-missing")?KEY:OWNER;
        if (id.equals("update-existing-name")) { AccountCapsule used=account(KEY,"alice",1); m.getAccountIndexStore().put(used); }
        AccountUpdateContract msg=AccountUpdateContract.newBuilder().setOwnerAddress(ByteString.copyFrom(address)).setAccountName(ByteString.copyFromUtf8(id.equals("update-empty")?"":"alice")).build();
        any=Any.pack(msg); type=ContractType.AccountUpdateContract; actuator=new UpdateAccountActuator(); ((UpdateAccountActuator)actuator).setChainBaseManager(m).setAny(any);
      } else if (id.startsWith("setid-")) {
        byte[] address=id.equals("setid-invalid-address")?new byte[]{1}:id.equals("setid-missing")?KEY:OWNER;
        byte[] accountId=(id.equals("setid-invalid-id")?"short":id.equals("setid-duplicate")?"DUPLICATE":"Account-01").getBytes("UTF-8");
        if (id.equals("setid-already-set")) { owner.setAccountId("Old-id-01".getBytes("UTF-8")); m.getAccountStore().put(OWNER,owner); ownerBefore=data(owner); }
        if (id.equals("setid-duplicate")) { AccountCapsule used=account(KEY,"used",1); used.setAccountId(accountId); m.getAccountIdIndexStore().put(used); }
        SetAccountIdContract msg=SetAccountIdContract.newBuilder().setOwnerAddress(ByteString.copyFrom(address)).setAccountId(ByteString.copyFrom(accountId)).build();
        any=Any.pack(msg); type=ContractType.SetAccountIdContract; actuator=new SetAccountIdActuator(); ((SetAccountIdActuator)actuator).setChainBaseManager(m).setAny(any);
      } else {
        byte[] address=id.equals("permission-invalid-address")?new byte[]{1}:id.equals("permission-missing")?KEY:OWNER;
        Permission ownerPermission=permission(id.equals("permission-owner-type")?PermissionType.Active:PermissionType.Owner,0,"owner",id.equals("permission-threshold")?0:1,new byte[0],OWNER);
        Permission active=permission(PermissionType.Active,2,"active",1,id.equals("permission-operations")?new byte[1]:new byte[32],OWNER);
        AccountPermissionUpdateContract.Builder b=AccountPermissionUpdateContract.newBuilder().setOwnerAddress(ByteString.copyFrom(address));
        if (!id.equals("permission-owner-missing")) b.setOwner(ownerPermission);
        if (!id.equals("permission-active-missing")) b.addActives(active);
        AccountPermissionUpdateContract msg=b.build(); any=Any.pack(msg); type=ContractType.AccountPermissionUpdateContract; actuator=new AccountPermissionUpdateActuator(); ((AccountPermissionUpdateActuator)actuator).setChainBaseManager(m).setAny(any);
      }
      Contract contract=Contract.newBuilder().setType(type).setParameter(any).build();
      TransactionResultCapsule result=new TransactionResultCapsule(); String error=null;
      try { actuator.validate(); actuator.execute(result); } catch(Exception e) { error=e.getMessage(); }
      byte[] ownerAfter=data(m.getAccountStore().get(OWNER)), targetAfter=data(m.getAccountStore().get(TARGET));
      List<String> changed=new ArrayList<>(); if(!java.util.Arrays.equals(ownerBefore,ownerAfter)) changed.add(delta("Account",OWNER,ownerBefore,ownerAfter)); if(!java.util.Arrays.equals(targetBefore,targetAfter)) changed.add(delta("Account",TARGET,targetBefore,targetAfter));
      String changedJson="["+String.join(",",changed)+"]";
      observation="{\"scenario_id\":"+q(id)+",\"contract_type\":"+type.getNumber()+",\"contract_hex\":"+q(hex(contract.toByteArray()))+",\"any_hex\":"+q(hex(any.toByteArray()))+",\"result\":{\"code\":"+q(result.getInstance().getRet().name())+",\"error\":"+(error==null?"null":q(error))+",\"fee\":"+result.getInstance().getFee()+",\"asset_id_hex\":"+q(hex(result.getAssetIssueID().getBytes("UTF-8")))+"},\"changed\":"+changedJson+",\"committed_reopen\":{\"owner_hex\":"+nh(ownerAfter)+",\"target_hex\":"+nh(targetAfter)+"},\"rollback_root\":{\"owner_hex\":"+nh(ownerBefore)+",\"target_hex\":"+nh(targetBefore)+"}}";
    } finally { }
    System.out.println("C012_ACCOUNT_REAL="+Base64.getEncoder().encodeToString(observation.getBytes("UTF-8")));
    System.out.flush();
    Runtime.getRuntime().halt(0);
}
}
