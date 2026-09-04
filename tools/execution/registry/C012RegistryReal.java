package org.tron.core.actuator;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import java.util.Base64;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.tron.common.TestConstants;
import org.tron.common.utils.ByteArray;
import org.tron.core.ChainBaseManager;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.TransactionResultCapsule;
import org.tron.core.config.DefaultConfig;
import org.tron.core.config.args.Args;
import org.tron.core.db2.ISession;
import org.tron.core.db2.core.SnapshotManager;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.Transaction.Contract;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.BalanceContract.TransferContract;

/** Direct, deterministic Java evidence for the built-in registry boundary. */
public final class C012RegistryReal {
  private static final byte[] OWNER = ByteArray.fromHexString("41548794500882809695a8a687866e76d4271a1abc");
  private static final byte[] RECIPIENT = ByteArray.fromHexString("41abd4b9367799eaa3197fecb144eb71de1e049abc");
  private static final long OWNER_BALANCE = 9_999_999L;
  private static final long RECIPIENT_BALANCE = 100_001L;

  private C012RegistryReal() {}
  private static String q(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""; }
  private static String hex(byte[] b) { return ByteArray.toHexString(b); }
  private static String nullableHex(byte[] b) { return b == null ? "null" : q(hex(b)); }

  public static void main(String[] args) throws Exception {
    if (args.length != 3 || !"--scenario".equals(args[0])) throw new IllegalArgumentException("usage: --scenario ID DB_DIR");
    String id = args[1];
    Args.setParam(new String[] {"--output-directory", args[2]}, TestConstants.TEST_CONF);
    AnnotationConfigApplicationContext spring = new AnnotationConfigApplicationContext(DefaultConfig.class);
    try {
      ChainBaseManager manager = spring.getBean(ChainBaseManager.class);
      manager.getDynamicPropertiesStore().saveLatestBlockHeaderTimestamp(1_700_000_000_000L);
      AccountCapsule owner = new AccountCapsule(ByteString.copyFromUtf8("owner"), ByteString.copyFrom(OWNER), AccountType.Normal, OWNER_BALANCE);
      AccountCapsule recipient = new AccountCapsule(ByteString.copyFromUtf8("recipient"), ByteString.copyFrom(RECIPIENT), AccountType.Normal, RECIPIENT_BALANCE);
      manager.getAccountStore().put(OWNER, owner);
      manager.getAccountStore().put(RECIPIENT, recipient);
      byte[] ownerBefore = owner.getData();
      byte[] recipientBefore = recipient.getData();

      byte[] contractOwner = OWNER;
      byte[] contractTo = RECIPIENT;
      long amount = 100;
      String typeUrl = "type.googleapis.com/protocol.TransferContract";
      int type = ContractType.TransferContract_VALUE;
      if (id.equals("TCASE-5ECE89EE9480F885")) contractOwner = new byte[] {1,2,3,4};
      if (id.equals("TCASE-60950B6D506E1515")) contractTo = OWNER;
      if (id.equals("TCASE-57A0E49CA779D734")) amount = OWNER_BALANCE + 1;
      if (id.equals("TCASE-5B51E4838875DA31")) contractOwner = ByteArray.fromHexString("41548794500882809695a8a687866e76d4271a3456");
      if (id.equals("TCASE-5D1C840070F54FAB")) typeUrl = "type.googleapis.com/protocol.AccountUpdateContract";
      if (id.equals("TCASE-5E15A6A247E10E30")) contractOwner = new byte[0];

      TransferContract message = TransferContract.newBuilder().setOwnerAddress(ByteString.copyFrom(contractOwner)).setToAddress(ByteString.copyFrom(contractTo)).setAmount(amount).build();
      Any any = Any.newBuilder().setTypeUrl(typeUrl).setValue(message.toByteString()).build();
      Contract contract = Contract.newBuilder().setTypeValue(type).setParameter(any).build();
      SnapshotManager snapshots = spring.getBean(SnapshotManager.class);
      TransferActuator actuator = new TransferActuator();
      actuator.setChainBaseManager(manager).setAny(any);
      TransactionResultCapsule result = new TransactionResultCapsule();
      String error = null;
      try (ISession session = snapshots.buildSession(true)) {
        try { actuator.validate(); actuator.execute(result); session.commit(); } catch (Exception e) { error = e.getMessage(); }
      }
      AccountCapsule ownerAfterCapsule = manager.getAccountStore().get(OWNER);
      AccountCapsule recipientAfterCapsule = manager.getAccountStore().get(RECIPIENT);
      byte[] ownerAfter = ownerAfterCapsule == null ? null : ownerAfterCapsule.getData();
      byte[] recipientAfter = recipientAfterCapsule == null ? null : recipientAfterCapsule.getData();
      String resultCode = result.getInstance().getRet().name();
      long fee = result.getInstance().getFee();
      byte[] assetId = result.getInstance().getAssetIssueID().getBytes("UTF-8");
      try (ISession ignored = snapshots.buildSession(true)) {
        if (error == null) {
          TransferActuator revokeActuator = new TransferActuator();
          revokeActuator.setChainBaseManager(manager).setAny(any);
          revokeActuator.validate();
          revokeActuator.execute(new TransactionResultCapsule());
        }
      }
      byte[] ownerRevoked = manager.getAccountStore().get(OWNER).getData();
      byte[] recipientRevoked = manager.getAccountStore().get(RECIPIENT).getData();
      String changed = "[";
      boolean comma = false;
      if (!java.util.Arrays.equals(ownerBefore, ownerAfter)) { changed += "{\"store\":\"Account\",\"key_hex\":"+q(hex(OWNER))+",\"before_hex\":"+q(hex(ownerBefore))+",\"after_hex\":"+nullableHex(ownerAfter)+"}"; comma=true; }
      if (!java.util.Arrays.equals(recipientBefore, recipientAfter)) { if(comma) changed += ","; changed += "{\"store\":\"Account\",\"key_hex\":"+q(hex(RECIPIENT))+",\"before_hex\":"+q(hex(recipientBefore))+",\"after_hex\":"+nullableHex(recipientAfter)+"}"; }
      changed += "]";
      String observation = "{\"stable_id\":"+q(id)+",\"contract_type\":"+type+",\"contract_hex\":"+q(hex(contract.toByteArray()))+",\"any_hex\":"+q(hex(any.toByteArray()))+",\"owner_hex\":"+q(hex(contractOwner))+",\"result\":{\"code\":"+q(resultCode)+",\"error\":"+(error==null?"null":q(error))+",\"fee\":"+fee+",\"asset_id_hex\":"+q(hex(assetId))+"},\"changed\":"+changed+",\"committed_reopen\":{\"owner_hex\":"+nullableHex(ownerAfter)+",\"recipient_hex\":"+nullableHex(recipientAfter)+"},\"revoked_reopen\":{\"owner_hex\":"+nullableHex(ownerRevoked)+",\"recipient_hex\":"+nullableHex(recipientRevoked)+"},\"rollback_root\":{\"owner_hex\":"+q(hex(ownerBefore))+",\"recipient_hex\":"+q(hex(recipientBefore))+"}}";
      System.out.println("C012_REGISTRY_REAL=" + Base64.getEncoder().encodeToString(observation.getBytes("UTF-8")));
      System.out.flush();
      Runtime.getRuntime().halt(0);
    } finally { Args.clearParam(); }
  }
}
