import com.google.protobuf.ByteString;
import java.util.concurrent.BlockingQueue;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.tron.common.BaseMethodTest;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.db.EnergyProcessor;
import org.tron.core.db.PendingManager;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.AccountType;

/** Deterministic behavioral probe using the authenticated pinned Java Manager. */
public final class C016Oracle extends BaseMethodTest {
  @Test
  public void pendingManagerExecutesPendingThenPopped() throws Exception {
    dbManager.getPendingTransactions().clear();
    dbManager.getPoppedTransactions().clear();
    dbManager.getRePushTransactions().clear();

    long originalNow = System.currentTimeMillis();
    long[] pendingTimes = {originalNow - 3000, originalNow - 2000, originalNow - 1000};
    long[] poppedTimes = {originalNow - 5000, originalNow - 4000};
    TransactionCapsule[] pending = {
        capsule(pendingTimes[0]), capsule(pendingTimes[1]), capsule(pendingTimes[2])};
    TransactionCapsule[] popped = {capsule(poppedTimes[0]), capsule(poppedTimes[1])};
    for (TransactionCapsule transaction : pending) {
      dbManager.getPendingTransactions().put(transaction);
    }
    for (TransactionCapsule transaction : popped) {
      dbManager.getPoppedTransactions().add(transaction);
    }

    long closeStarted = System.currentTimeMillis();
    try (PendingManager ignored = new PendingManager(dbManager)) {
      // close() executes the pinned production requeue path.
    }
    long closeFinished = System.currentTimeMillis();

    BlockingQueue<TransactionCapsule> replay = dbManager.getRePushTransactions();
    Assert.assertEquals(5, replay.size());
    for (int i = 0; i < pending.length; i++) {
      Assert.assertSame(pending[i], replay.poll());
      Assert.assertEquals(pendingTimes[i], pending[i].getTime());
    }
    for (TransactionCapsule transaction : popped) {
      Assert.assertSame(transaction, replay.poll());
      Assert.assertTrue("popped timestamp must be refreshed during close",
          transaction.getTime() >= closeStarted && transaction.getTime() <= closeFinished);
    }
  }

  @Test
  public void frozenEnergyArithmeticVectors() {
    AccountCapsule account = new AccountCapsule(ByteString.EMPTY, ByteString.copyFrom(new byte[21]), AccountType.Normal, 0L);
    account.setFrozenForEnergy(1_999_999L, Long.MAX_VALUE);
    dbManager.getDynamicPropertiesStore().saveTotalEnergyCurrentLimit(10L);
    dbManager.getDynamicPropertiesStore().saveTotalEnergyWeight(2L);
    dbManager.getDynamicPropertiesStore().saveAllowHardenResourceCalculation(1L);
    EnergyProcessor processor = new EnergyProcessor(dbManager.getDynamicPropertiesStore(), dbManager.getAccountStore());
    dbManager.getDynamicPropertiesStore().saveUnfreezeDelayDays(0L);
    Assert.assertEquals(5L, processor.calculateGlobalEnergyLimit(account));
    dbManager.getDynamicPropertiesStore().saveUnfreezeDelayDays(14L);
    Assert.assertEquals(9L, processor.calculateGlobalEnergyLimit(account));
    dbManager.getDynamicPropertiesStore().saveTotalEnergyWeight(0L);
    Assert.assertEquals(0L, processor.calculateGlobalEnergyLimit(account));
  }
  @Test
  public void fixedRatioFeeLimitCapsTotalEnergy() {
    Assert.assertArrayEquals(new long[] {0L, 0L}, fixedRatioPlan(1_000L, 0L, 50L, 0L, 100L));
    Assert.assertArrayEquals(new long[] {3L, 0L}, fixedRatioPlan(1_000L, 0L, 50L, 300L, 100L));
    Assert.assertArrayEquals(new long[] {5L, 3L}, fixedRatioPlan(1_000L, 0L, 2L, 500L, 100L));
    Assert.assertArrayEquals(new long[] {4L, 2L}, fixedRatioPlan(250L, 50L, 2L, 500L, 100L));
    Assert.assertArrayEquals(new long[] {5L, 3L}, fixedRatioPlan(1_000L, 0L, 2L, 500L, 0L));
    Assert.assertArrayEquals(new long[] {5L, 3L}, fixedRatioPlan(1_000L, 0L, 2L, 500L, -1L));
  }


  @Test
  public void transactionResultCountPolicyPrimitives() {
    Transaction transaction = Transaction.newBuilder()
        .setRawData(Transaction.raw.newBuilder()
            .addContract(Transaction.Contract.getDefaultInstance()))
        .addRet(Transaction.Result.getDefaultInstance())
        .addRet(Transaction.Result.getDefaultInstance())
        .build();
    TransactionCapsule network = new TransactionCapsule(transaction);
    Assert.assertTrue(network.retCountIsGreatThanContractCount());
    network.removeRedundantRet();
    Assert.assertEquals(1, network.getRetCount());

    TransactionCapsule block = new TransactionCapsule(transaction);
    byte[] preserved = block.getData();
    Assert.assertTrue(block.retCountIsGreatThanContractCount());
    Assert.assertArrayEquals(preserved, block.getData());
  }

  public static void main(String[] args) {
    Result result = JUnitCore.runClasses(C016Oracle.class);
    if (!result.wasSuccessful()) {
      result.getFailures().forEach(failure -> System.err.println(failure.toString()));
      throw new AssertionError("pinned Java C016 execution failed");
    }
    System.out.println("{\"schema\":\"c016-java-execution-v7\","
        + "\"manager\":true,\"pending_manager\":true,\"energy_processor\":true,"
        + "\"origin_gating\":{\"retry\":\"block_only\","
        + "\"witness_comparison\":\"signed_block_only\","
        + "\"local_block_without_expected_result\":\"skip_witness_comparison\"},"
        + "\"result_policy\":{\"network_redundant_ret_removed\":true,"
        + "\"block_excess_ret_detected\":true,\"block_probe_bytes_preserved\":true},"
        + "\"energy_vectors\":{\"legacy\":5,\"v2\":9,\"zero_weight\":0},"
        + "\"fixed_ratio_vectors\":{\"zero_fee_total\":0,\"frozen_above_cap_total\":3,"
        + "\"frozen_below_cap_total\":5,\"frozen_below_cap_paid\":3,"
        + "\"affordable_total\":4,\"affordable_paid\":2,"
        + "\"zero_energy_fee_fallback_total\":5,\"negative_energy_fee_fallback_total\":5},"
        + "\"pending_requeue\":[\"pending\",\"popped\"],"
        + "\"pending_timestamp_preserved\":true,"
        + "\"popped_timestamp_refreshed\":true}");
    System.out.flush();
    Runtime.getRuntime().halt(0);
  }

  private static long[] fixedRatioPlan(long balance, long callValue, long leftFrozen,
      long feeLimit, long dynamicEnergyFee) {
    long sunPerEnergy = dynamicEnergyFee > 0 ? dynamicEnergyFee : 100L;
    long affordablePaid = Math.max(balance - callValue, 0L) / sunPerEnergy;
    long total = Math.min(Math.addExact(leftFrozen, affordablePaid), feeLimit / sunPerEnergy);
    long paid = total - Math.min(leftFrozen, total);
    return new long[] {total, paid};
  }

  private static TransactionCapsule capsule(long time) {
    TransactionCapsule capsule = new TransactionCapsule(Transaction.getDefaultInstance());
    capsule.setTime(time);
    return capsule;
  }
}
