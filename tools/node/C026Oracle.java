import io.grpc.ServiceDescriptor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Guarded runtime/reflection capture from the pinned java-tron classes. */
public final class C026Oracle {
  private C026Oracle() {}

  private static String hex(byte[] bytes) {
    StringBuilder out = new StringBuilder(bytes.length * 2);
    for (byte value : bytes) out.append(String.format("%02x", value & 255));
    return out.toString();
  }

  private static Class<?> load(String name) throws Exception {
    return Class.forName(name, false, C026Oracle.class.getClassLoader());
  }

  private static boolean hasMethod(Class<?> type, String name) {
    for (Method method : type.getMethods()) if (method.getName().equals(name)) return true;
    return false;
  }

  private static ServiceDescriptor descriptor(String grpcClass) throws Exception {
    return (ServiceDescriptor) load(grpcClass).getMethod("getServiceDescriptor").invoke(null);
  }

  public static void main(String[] args) throws Exception {
    Class<?> argsClass = load("org.tron.core.config.args.Args");
    Class<?> fullNodeClass = load("org.tron.program.FullNode");
    Class<?> rpcClass = load("org.tron.core.services.RpcApiService");
    Class<?> httpClass = load("org.tron.core.services.http.solidity.SolidityNodeHttpApiService");
    Class<?> nodeClass = load("org.tron.program.SolidityNode");
    Class<?> testClass = load("org.tron.program.SolidityNodeTest");
    String[] requiredArgs = {"getTrustNodeAddr", "getRpcPort", "getSolidityHttpPort", "isP2pDisable"};
    for (String method : requiredArgs) {
      if (!hasMethod(argsClass, method)) throw new IllegalStateException("missing Args method " + method);
    }
    if (!hasMethod(rpcClass, "start") || !hasMethod(httpClass, "start")
        || !hasMethod(fullNodeClass, "main") || !hasMethod(nodeClass, "run") || !hasMethod(nodeClass, "close")) {
      throw new IllegalStateException("missing production lifecycle method");
    }

    String[] grpcClasses = {
      "org.tron.api.DatabaseGrpc", "org.tron.api.WalletSolidityGrpc",
      "org.tron.api.WalletExtensionGrpc", "org.tron.api.MonitorGrpc",
      "org.tron.api.WalletGrpc", "org.tron.api.NetworkGrpc"
    };
    List<String> inventory = new ArrayList<String>();
    List<String> methodInventory = new ArrayList<String>();
    int methods = 0;
    for (String grpcClass : grpcClasses) {
      ServiceDescriptor service = descriptor(grpcClass);
      methods += service.getMethods().size();
      inventory.add(service.getName() + ":" + service.getMethods().size());
      service.getMethods().forEach(method -> methodInventory.add(method.getFullMethodName()));
    }
    Collections.sort(methodInventory);
    Collections.sort(inventory);
    argsClass.getMethod("setParam", String[].class, String.class)
        .invoke(null, new Object[] {new String[0], "config.conf"});
    Object config = argsClass.getMethod("getInstance").invoke(null);
    String trustNode = String.valueOf(argsClass.getMethod("getTrustNodeAddr").invoke(config));
    int rpcPort = ((Number) argsClass.getMethod("getRpcPort").invoke(config)).intValue();
    int solidityHttpPort = ((Number) argsClass.getMethod("getSolidityHttpPort").invoke(config)).intValue();
    boolean p2pDisabled = ((Boolean) argsClass.getMethod("isP2pDisable").invoke(config)).booleanValue();
    argsClass.getMethod("clearParam").invoke(null);

    List<String> tests = new ArrayList<String>();
    for (Method method : testClass.getDeclaredMethods()) {
      if (Modifier.isPublic(method.getModifiers()) && method.getParameterTypes().length == 0
          && method.getName().startsWith("test")) tests.add(method.getName());
    }
    Collections.sort(tests);
    if (tests.size() != 18) throw new IllegalStateException("SolidityNodeTest count " + tests.size());

    String canonical = String.join("\n", inventory) + "\n--methods--\n"
        + String.join("\n", methodInventory) + "\n--tests--\n" + String.join("\n", tests)
        + "\n--config--\n" + trustNode + ":" + rpcPort + ":" + solidityHttpPort + ":" + p2pDisabled + "\n";
    String digest = hex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
    System.out.println("C026_SERVICES=" + inventory.size());
    System.out.println("C026_METHODS=" + methods);
    System.out.println("C026_TESTS=" + tests.size());
    System.out.println("C026_INVENTORY=" + String.join(",", inventory));
    System.out.println("C026_METHOD_INVENTORY=" + String.join(",", methodInventory));
    System.out.println("C026_TEST_INVENTORY=" + String.join(",", tests));
    System.out.println("C026_CONFIG=" + trustNode + ":" + rpcPort + ":" + solidityHttpPort + ":" + p2pDisabled);
    System.out.println("C026_CANONICAL_SHA256=" + digest);
  }
}
