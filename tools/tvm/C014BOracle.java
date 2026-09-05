import java.util.ArrayList;
import java.util.List;

/** Deterministic C014.03B vectors derived from the pinned java-tron operation contract. */
public final class C014BOracle {
  private static long memoryCost(long bytes) {
    long words = (bytes + 31) / 32;
    return 3 * words + words * words / 512;
  }
  private static void row(List<String> out, int opcode, String name, int required, int resulting,
      String activation, String energy) {
    out.add(String.format("%02x\t%s\t%d\t%d\t%s\t%s", opcode, name, required, resulting,
        activation, energy));
  }
  public static void main(String[] args) {
    List<String> rows = new ArrayList<>();
    row(rows, 0x00, "STOP", 0, 0, "always", "0");
    String[][] fixed = {
      {"50","POP","1","0","always","2"},{"51","MLOAD","1","1","always","memory"},
      {"52","MSTORE","2","0","always","memory"},{"53","MSTORE8","2","0","always","memory"},
      {"54","SLOAD","1","1","always","50"},{"55","SSTORE","2","0","always","sstore"},
      {"56","JUMP","1","0","always","8"},{"57","JUMPI","2","0","always","10"},
      {"58","PC","0","1","always","2"},{"59","MSIZE","0","1","always","2"},
      {"5a","GAS","0","1","always","2"},{"5b","JUMPDEST","0","0","always","1"},
      {"5c","TLOAD","1","1","cancun","100"},{"5d","TSTORE","2","0","cancun","100"},
      {"5e","MCOPY","3","0","cancun","mcopy"},{"5f","PUSH0","0","1","shanghai","2"}};
    for (String[] f : fixed) row(rows, Integer.parseInt(f[0],16), f[1], Integer.parseInt(f[2]),
        Integer.parseInt(f[3]), f[4], f[5]);
    for (int n=1;n<=32;n++) row(rows,0x5f+n,"PUSH"+n,0,1,"always","3");
    for (int n=1;n<=16;n++) row(rows,0x7f+n,"DUP"+n,n,n+1,"always","3");
    for (int n=1;n<=16;n++) row(rows,0x8f+n,"SWAP"+n,n+1,n+1,"always","3");
    for (int n=0;n<=4;n++) row(rows,0xa0+n,"LOG"+n,n+2,0,"always","log");
    row(rows,0xf3,"RETURN",2,0,"always","memory");
    row(rows,0xfd,"REVERT",2,0,"always","memory");
    if (rows.size()!=88) throw new AssertionError(rows.size());
    for (String value : rows) System.out.println("ROW\t"+value);
    System.out.println("VECTOR\tmcopy\t"+(3 + memoryCost(65) + 3*((33+31)/32)));
    System.out.println("VECTOR\tlog4_32\t"+(375 + 4*375 + 8*32 + memoryCost(32)));
    System.out.println("VECTOR\tsstore_set\t20000");
    System.out.println("VECTOR\tsstore_delete\t5000");
    System.out.println("VECTOR\tpush2_truncated\taa00");
  }
}
