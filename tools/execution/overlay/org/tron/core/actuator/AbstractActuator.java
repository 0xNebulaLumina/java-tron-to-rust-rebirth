package org.tron.core.actuator;

import com.google.protobuf.Any;
import com.google.protobuf.GeneratedMessageV3;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import org.tron.common.math.Maths;
import org.tron.common.utils.Commons;
import org.tron.common.utils.ForkController;
import org.tron.core.ChainBaseManager;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.exception.BalanceInsufficientException;
import org.tron.core.store.AccountStore;
import org.tron.protos.Protocol.Transaction.Contract;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;

/**
 * First-classpath observation overlay for the pinned AbstractActuator.
 *
 * <p>All production methods preserve the pinned source behavior. The static capture API is used only
 * by the external C012 oracle and records the concrete objects supplied by the tests.</p>
 */
public abstract class AbstractActuator implements Actuator {
  protected Any any;
  protected ChainBaseManager chainBaseManager;
  protected Contract contract;
  protected TransactionCapsule tx;
  protected ForkController forkController;

  private static final Map<AbstractActuator, Capture> CAPTURES = new IdentityHashMap<>();
  private static long nextCaptureId;

  public static final class Capture {
    public final long id;
    public final String actuatorClass;
    public final ContractType constructorType;
    public Any any;
    public Contract contract;

    private Capture(long id, String actuatorClass, ContractType constructorType) {
      this.id = id;
      this.actuatorClass = actuatorClass;
      this.constructorType = constructorType;
    }
  }

  public static synchronized void resetC012Captures() {
    CAPTURES.clear();
    nextCaptureId = 0;
  }
  public static synchronized List<Capture> snapshotC012Captures() {
    for (Map.Entry<AbstractActuator, Capture> entry : CAPTURES.entrySet()) {
      entry.getValue().any = entry.getKey().any;
      entry.getValue().contract = entry.getKey().contract;
    }
    return new ArrayList<>(CAPTURES.values());
  }

  private static synchronized Capture capture(AbstractActuator actuator) {
    return CAPTURES.get(actuator);
  }

  public AbstractActuator(ContractType type, Class<? extends GeneratedMessageV3> clazz) {
    TransactionFactory.register(type, getClass(), clazz);
    synchronized (AbstractActuator.class) {
      CAPTURES.put(this, new Capture(++nextCaptureId, getClass().getName(), type));
    }
  }

  public Any getAny() {
    return any;
  }

  public ChainBaseManager getChainBaseManager() {
    return chainBaseManager;
  }

  public Contract getContract() {
    return contract;
  }

  public TransactionCapsule getTx() {
    return tx;
  }

  public AbstractActuator setAny(Any any) {
    this.any = any;
    Capture capture = capture(this);
    if (capture != null) capture.any = any;
    return this;
  }

  public AbstractActuator setChainBaseManager(ChainBaseManager chainBaseManager) {
    this.chainBaseManager = chainBaseManager;
    return this;
  }

  public AbstractActuator setContract(Contract contract) {
    this.contract = contract;
    this.any = contract.getParameter();
    Capture capture = capture(this);
    if (capture != null) {
      capture.contract = contract;
      capture.any = contract.getParameter();
    }
    return this;
  }

  public AbstractActuator setTx(TransactionCapsule tx) {
    this.tx = tx;
    return this;
  }

  public AbstractActuator setForkUtils(ForkController forkController) {
    this.forkController = forkController;
    return this;
  }

  public long addExact(long x, long y) {
    return Maths.addExact(x, y, this.disableJavaLangMath());
  }

  public long addExact(int x, int y) {
    return Maths.addExact(x, y, this.disableJavaLangMath());
  }

  public long floorDiv(long x, long y) {
    return Maths.floorDiv(x, y, this.disableJavaLangMath());
  }

  public long floorDiv(long x, int y) {
    return this.floorDiv(x, (long) y);
  }

  public long multiplyExact(long x, long y) {
    return Maths.multiplyExact(x, y, this.disableJavaLangMath());
  }

  public long multiplyExact(long x, int y) {
    return Maths.multiplyExact(x, (long) y, this.disableJavaLangMath());
  }

  public int multiplyExact(int x, int y) {
    return Maths.multiplyExact(x, y, this.disableJavaLangMath());
  }

  public long subtractExact(long x, long y) {
    return Maths.subtractExact(x, y, this.disableJavaLangMath());
  }

  public int min(int a, int b) {
    return Maths.min(a, b, this.disableJavaLangMath());
  }

  public long min(long a, long b) {
    return Maths.min(a, b, this.disableJavaLangMath());
  }

  public void adjustBalance(AccountStore accountStore, byte[] accountAddress, long amount)
      throws BalanceInsufficientException {
    AccountCapsule account = accountStore.getUnchecked(accountAddress);
    this.adjustBalance(accountStore, account, amount);
  }

  public void adjustBalance(AccountStore accountStore, AccountCapsule account, long amount)
      throws BalanceInsufficientException {
    Commons.adjustBalance(accountStore, account, amount, this.disableJavaLangMath());
  }

  boolean disableJavaLangMath() {
    return chainBaseManager.getDynamicPropertiesStore().disableJavaLangMath();
  }
}
