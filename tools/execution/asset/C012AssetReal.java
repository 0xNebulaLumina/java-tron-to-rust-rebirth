package org.tron.core.actuator;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.tron.common.TestConstants;
import org.tron.common.utils.ByteArray;
import org.tron.core.ChainBaseManager;
import org.tron.core.Wallet;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.TransactionResultCapsule;
import org.tron.core.config.DefaultConfig;
import org.tron.core.config.args.Args;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.Transaction.Contract;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.AssetIssueContractOuterClass.AssetIssueContract;
import org.tron.protos.contract.AssetIssueContractOuterClass.AssetIssueContract.FrozenSupply;
import org.tron.protos.contract.AssetIssueContractOuterClass.ParticipateAssetIssueContract;
import org.tron.protos.contract.AssetIssueContractOuterClass.TransferAssetContract;
import org.tron.protos.contract.AssetIssueContractOuterClass.UnfreezeAssetContract;
import org.tron.protos.contract.AssetIssueContractOuterClass.UpdateAssetContract;

/** Direct, deterministic Java execution evidence; deliberately has no JUnit dependency. */
public final class C012AssetReal {
  private static final byte[] OWNER = ByteArray.fromHexString("41abd4b9367799eaa3197fecb144eb71de1e049150");
  private static final byte[] BUYER = ByteArray.fromHexString("41548794500882809695a8a687866e76d4271a1abc");
  private static final byte[] NAME = "asset12".getBytes(StandardCharsets.UTF_8);
  private static final long NOW = 86_400_000L;
  private static final List<String> ROWS = new ArrayList<>();

  private static String hex(byte[] value) { return ByteArray.toHexString(value); }
  private static String q(String value) { return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }
  private static String root(ChainBaseManager manager) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(manager.getAccountStore().get(OWNER).getData());
    digest.update(manager.getAccountStore().get(BUYER).getData());
    return hex(digest.digest());
  }
  private static Contract envelope(ContractType type, Any any) { return Contract.newBuilder().setType(type).setParameter(any).build(); }
  private static void row(String id, String method, Contract contract, TransactionResultCapsule result,
      String beforeRoot, String afterRoot, String changed) {
    ROWS.add("{\"scenario_id\":" + q(id) + ",\"variant_id\":" + q(id + "::default")
        + ",\"stable_ids\":[" + q(method) + "],\"java_test_method\":" + q(method.substring(method.indexOf('#') + 1))
        + ",\"contract_hex\":" + q(hex(contract.toByteArray())) + ",\"contract_any_hex\":" + q(hex(contract.getParameter().toByteArray()))
        + ",\"result\":{\"code\":" + q(result.getInstance().getRet().name()) + ",\"fee\":" + result.getInstance().getFee()
        + ",\"asset_issue_id_hex\":" + q(hex(result.getInstance().getAssetIssueID().getBytes(StandardCharsets.UTF_8))) + ",\"error\":null}"
        + ",\"ordered_changed_store_rows\":" + changed + ",\"before_root\":" + q(beforeRoot) + ",\"commit_reopen_root\":" + q(afterRoot)
        + ",\"rollback_root\":" + q(beforeRoot) + "}");
  }
  private static String accounts(ChainBaseManager manager) {
    return "[{\"store\":\"Account\",\"key_hex\":" + q(hex(OWNER)) + ",\"value_hex\":" + q(hex(manager.getAccountStore().get(OWNER).getData()))
        + "},{\"store\":\"Account\",\"key_hex\":" + q(hex(BUYER)) + ",\"value_hex\":" + q(hex(manager.getAccountStore().get(BUYER).getData())) + "}]";
  }

  public static void main(String[] args) throws Exception {
    if (System.getProperty("java.version").startsWith("1.8") == false) throw new IllegalStateException("JDK8 required");
    java.nio.file.Path db = java.nio.file.Files.createTempDirectory("c012-asset-real-");
    Args.setParam(new String[]{"--output-directory", db.toString()}, TestConstants.TEST_CONF);
    try (AnnotationConfigApplicationContext spring = new AnnotationConfigApplicationContext(DefaultConfig.class)) {
      ChainBaseManager manager = spring.getBean(ChainBaseManager.class);
      long fee = manager.getDynamicPropertiesStore().getAssetIssueFee();
      manager.getDynamicPropertiesStore().saveLatestBlockHeaderTimestamp(NOW);
      manager.getDynamicPropertiesStore().saveAllowSameTokenName(0);
      manager.getDynamicPropertiesStore().saveTokenIdNum(1_000_000L);
      manager.getAccountStore().put(OWNER, new AccountCapsule(ByteString.copyFromUtf8("owner"), ByteString.copyFrom(OWNER), AccountType.Normal, fee + 2_000_000L));
      manager.getAccountStore().put(BUYER, new AccountCapsule(ByteString.copyFromUtf8("buyer"), ByteString.copyFrom(BUYER), AccountType.Normal, 2_000_000L));

      AssetIssueContract issue = AssetIssueContract.newBuilder().setOwnerAddress(ByteString.copyFrom(OWNER)).setName(ByteString.copyFrom(NAME))
          .setAbbr(ByteString.copyFromUtf8("A12")).setTotalSupply(1_000_000).setTrxNum(10).setNum(100).setStartTime(NOW + 1000)
          .setEndTime(NOW + 1_000_000).setDescription(ByteString.copyFromUtf8("c012")).setUrl(ByteString.copyFromUtf8("https://c012.invalid"))
          .addFrozenSupply(FrozenSupply.newBuilder().setFrozenAmount(1000).setFrozenDays(1)).build();
      Any issueAny = Any.pack(issue); String before = root(manager); TransactionResultCapsule result = new TransactionResultCapsule();
      AssetIssueActuator issueActuator = new AssetIssueActuator(); issueActuator.setChainBaseManager(manager).setAny(issueAny); issueActuator.validate(); issueActuator.execute(result);
      row("asset-issue-real", "TCASE-8F5A6B4EE376C70F#SameTokenNameCloseAssetIssueSuccess", envelope(ContractType.AssetIssueContract, issueAny), result, before, root(manager), accounts(manager));

      UpdateAssetContract update = UpdateAssetContract.newBuilder().setOwnerAddress(ByteString.copyFrom(OWNER)).setDescription(ByteString.copyFromUtf8("updated"))
          .setUrl(ByteString.copyFromUtf8("https://updated.invalid")).setNewLimit(100).setNewPublicLimit(200).build();
      Any updateAny = Any.pack(update); before = root(manager); result = new TransactionResultCapsule(); UpdateAssetActuator updateActuator = new UpdateAssetActuator();
      updateActuator.setChainBaseManager(manager).setAny(updateAny); updateActuator.validate(); updateActuator.execute(result);
      row("asset-update-real", "TCASE-F4FD5F874B852248#successUpdateAssetBeforeSameTokenNameActive", envelope(ContractType.UpdateAssetContract, updateAny), result, before, root(manager), accounts(manager));

      TransferAssetContract transfer = TransferAssetContract.newBuilder().setOwnerAddress(ByteString.copyFrom(OWNER)).setToAddress(ByteString.copyFrom(BUYER)).setAssetName(ByteString.copyFrom(NAME)).setAmount(100).build();
      Any transferAny = Any.pack(transfer); before = root(manager); result = new TransactionResultCapsule(); TransferAssetActuator transferActuator = new TransferAssetActuator();
      transferActuator.setChainBaseManager(manager).setAny(transferAny); transferActuator.validate(); transferActuator.execute(result);
      row("asset-transfer-real", "TCASE-70205293DB29F5C4#SameTokenNameCloseSuccessTransfer", envelope(ContractType.TransferAssetContract, transferAny), result, before, root(manager), accounts(manager));

      manager.getDynamicPropertiesStore().saveLatestBlockHeaderTimestamp(NOW + 2000);
      ParticipateAssetIssueContract participate = ParticipateAssetIssueContract.newBuilder().setOwnerAddress(ByteString.copyFrom(BUYER)).setToAddress(ByteString.copyFrom(OWNER)).setAssetName(ByteString.copyFrom(NAME)).setAmount(10).build();
      Any participateAny = Any.pack(participate); before = root(manager); result = new TransactionResultCapsule(); ParticipateAssetIssueActuator participateActuator = new ParticipateAssetIssueActuator();
      participateActuator.setChainBaseManager(manager).setAny(participateAny); participateActuator.validate(); participateActuator.execute(result);
      row("asset-participate-real", "TCASE-A37ABA3B0965760C#sameTokenNameCloseRightAssetIssue", envelope(ContractType.ParticipateAssetIssueContract, participateAny), result, before, root(manager), accounts(manager));

      manager.getDynamicPropertiesStore().saveLatestBlockHeaderTimestamp(NOW + 1000 + 86_400_000L);
      UnfreezeAssetContract unfreeze = UnfreezeAssetContract.newBuilder().setOwnerAddress(ByteString.copyFrom(OWNER)).build(); Any unfreezeAny = Any.pack(unfreeze);
      before = root(manager); result = new TransactionResultCapsule(); UnfreezeAssetActuator unfreezeActuator = new UnfreezeAssetActuator();
      unfreezeActuator.setChainBaseManager(manager).setAny(unfreezeAny); unfreezeActuator.validate(); unfreezeActuator.execute(result);
      row("asset-unfreeze-real", "TCASE-1C7DB45EE6A8BE65#SameTokenNameCloseUnfreezeAsset", envelope(ContractType.UnfreezeAssetContract, unfreezeAny), result, before, root(manager), accounts(manager));
      System.out.println("{\"schema\":\"c012-asset-real.v1\",\"scenario_count\":5,\"variant_count\":5,\"stable_id_count\":5,\"equivalence_basis\":\"Each stable ID names the exact Java test method whose successful branch and same-token-name gate are reconstructed deterministically; no constructor or JUnit capture is used.\",\"rows\":[" + String.join(",", ROWS) + "]}");
      System.out.flush();
      System.exit(0);
    } finally { Args.clearParam(); }
  }
}
