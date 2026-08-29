import com.google.protobuf.DescriptorProtos.FileDescriptorProto;
import com.google.protobuf.DescriptorProtos.FileDescriptorSet;
import com.google.protobuf.Descriptors.Descriptor;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Descriptors.FileDescriptor;
import com.google.protobuf.DynamicMessage;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Emits protobuf-java 3.25.8 DynamicMessage map serialization oracles. */
public final class MapSerializationOracle {
  private static final class Row {
    String field;
    String forward;
    String reverse;
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 1) {
      throw new IllegalArgumentException("usage: MapSerializationOracle <FileDescriptorSet>");
    }
    FileDescriptorSet set = FileDescriptorSet.parseFrom(Files.readAllBytes(Paths.get(args[0])));
    Map<String, FileDescriptor> built = new HashMap<>();
    List<FileDescriptorProto> pending = new ArrayList<>(set.getFileList());
    while (!pending.isEmpty()) {
      boolean progressed = false;
      for (int index = pending.size() - 1; index >= 0; index--) {
        FileDescriptorProto proto = pending.get(index);
        FileDescriptor[] dependencies = new FileDescriptor[proto.getDependencyCount()];
        boolean ready = true;
        for (int dependency = 0; dependency < dependencies.length; dependency++) {
          dependencies[dependency] = built.get(proto.getDependency(dependency));
          ready &= dependencies[dependency] != null;
        }
        if (ready) {
          built.put(proto.getName(), FileDescriptor.buildFrom(proto, dependencies));
          pending.remove(index);
          progressed = true;
        }
      }
      if (!progressed) {
        throw new IllegalStateException("descriptor dependencies cannot be resolved");
      }
    }

    List<Row> rows = new ArrayList<>();
    for (FileDescriptor file : built.values()) {
      for (Descriptor message : file.getMessageTypes()) {
        collect(message, rows);
      }
    }
    rows.sort(Comparator.comparing(row -> row.field));
    System.out.print("[");
    for (int index = 0; index < rows.size(); index++) {
      Row row = rows.get(index);
      if (index != 0) System.out.print(",");
      System.out.print("{\"field\":\"" + row.field + "\",\"forward_hex\":\""
          + row.forward + "\",\"reverse_hex\":\"" + row.reverse + "\"}");
    }
    System.out.println("]");
  }

  private static void collect(Descriptor message, List<Row> rows) {
    for (FieldDescriptor field : message.getFields()) {
      if (field.isMapField()) {
        Row row = new Row();
        row.field = message.getFullName() + "." + field.getName();
        row.forward = hex(serialize(message, field, false));
        row.reverse = hex(serialize(message, field, true));
        rows.add(row);
      }
    }
    for (Descriptor nested : message.getNestedTypes()) {
      if (!nested.getOptions().getMapEntry()) collect(nested, rows);
    }
  }

  private static byte[] serialize(Descriptor parent, FieldDescriptor map, boolean reverse) {
    Descriptor entry = map.getMessageType();
    FieldDescriptor key = entry.findFieldByName("key");
    FieldDescriptor value = entry.findFieldByName("value");
    DynamicMessage first = entry(key, value, false);
    DynamicMessage second = entry(key, value, true);
    DynamicMessage.Builder builder = DynamicMessage.newBuilder(parent);
    builder.addRepeatedField(map, reverse ? second : first);
    builder.addRepeatedField(map, reverse ? first : second);
    return builder.build().toByteArray();
  }

  private static DynamicMessage entry(FieldDescriptor key, FieldDescriptor value, boolean second) {
    DynamicMessage.Builder builder = DynamicMessage.newBuilder(key.getContainingType());
    builder.setField(key, scalar(key, second));
    builder.setField(value, scalar(value, second));
    return builder.build();
  }

  private static Object scalar(FieldDescriptor field, boolean second) {
    switch (field.getJavaType()) {
      case STRING: return second ? "Z" : "A";
      case LONG: return second ? 9L : 1L;
      case INT: return second ? 9 : 1;
      case BOOLEAN: return second;
      case BYTE_STRING: return com.google.protobuf.ByteString.copyFromUtf8(second ? "Z" : "A");
      case ENUM: return field.getEnumType().getValues().get(second && field.getEnumType().getValues().size() > 1 ? 1 : 0);
      case FLOAT: return second ? 9.0f : 1.0f;
      case DOUBLE: return second ? 9.0d : 1.0d;
      default: throw new IllegalArgumentException("unsupported map scalar " + field.getJavaType());
    }
  }

  private static String hex(byte[] bytes) {
    StringBuilder out = new StringBuilder(bytes.length * 2);
    for (byte value : bytes) out.append(String.format("%02x", value & 0xff));
    return out.toString();
  }
}
