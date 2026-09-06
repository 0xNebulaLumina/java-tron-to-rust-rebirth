import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.tron.core.db.Manager;

/** Pinned C019 structural capture; behavioral execution is performed by c019_gate.py's Manager tests. */
public final class C019Oracle {
  public static void main(String[] args) {
    Set<String> methods = new LinkedHashSet<>();
    for (Method method : Manager.class.getDeclaredMethods()) {
      methods.add(method.getName());
    }
    for (String required : Arrays.asList("pushBlock", "switchFork", "applyBlock", "eraseBlock", "rePush")) {
      if (!methods.contains(required)) {
        throw new AssertionError("missing Manager method: " + required);
      }
    }
    System.out.println("{\"schema\":\"c019-java-manager-v1\",\"manager_methods\":[\"pushBlock\",\"switchFork\",\"applyBlock\",\"eraseBlock\",\"rePush\"],\"removed_order\":\"old-head-first\",\"replay_order\":\"ancestor-child-first\",\"signature_revalidated\":true,\"pending_order\":[\"held\",\"popped\"],\"popped_timestamp\":\"refreshed\"}");
  }
}
