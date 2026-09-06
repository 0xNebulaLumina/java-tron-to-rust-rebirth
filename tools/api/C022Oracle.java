import io.grpc.MethodDescriptor;
import io.grpc.ServiceDescriptor;
import java.util.Arrays;
import java.util.List;
import org.tron.api.DatabaseGrpc;
import org.tron.api.MonitorGrpc;
import org.tron.api.NetworkGrpc;
import org.tron.api.TronZksnarkGrpc;
import org.tron.api.WalletExtensionGrpc;
import org.tron.api.WalletGrpc;
import org.tron.api.WalletSolidityGrpc;

public final class C022Oracle {
  private static final List<ServiceDescriptor> SERVICES = Arrays.asList(
      WalletGrpc.getServiceDescriptor(),
      WalletSolidityGrpc.getServiceDescriptor(),
      WalletExtensionGrpc.getServiceDescriptor(),
      DatabaseGrpc.getServiceDescriptor(),
      MonitorGrpc.getServiceDescriptor(),
      NetworkGrpc.getServiceDescriptor(),
      TronZksnarkGrpc.getServiceDescriptor());

  public static void main(String[] args) {
    int methods = 0;
    StringBuilder inventory = new StringBuilder();
    for (ServiceDescriptor service : SERVICES) {
      methods += service.getMethods().size();
      for (MethodDescriptor<?, ?> method : service.getMethods()) {
        if (inventory.length() != 0) inventory.append(',');
        inventory.append(method.getFullMethodName());
      }
    }
    System.out.println("C022_CAPTURE={\"schema\":\"c022-java-descriptor-v1\",\"services\":"
        + SERVICES.size() + ",\"methods\":" + methods + ",\"inventory\":\"" + inventory + "\"}");
  }
}
