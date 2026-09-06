import com.google.protobuf.ByteString;
import org.tron.common.crypto.ECKey;
import org.tron.common.utils.Sha256Hash;
import org.tron.protos.Discover;
import org.tron.protos.Protocol;

public final class C018Oracle {
  private static String hex(byte[] bytes) {
    StringBuilder out = new StringBuilder(bytes.length * 2);
    for (byte value : bytes) out.append(String.format("%02x", value & 0xff));
    return out.toString();
  }

  private static Protocol.PBFTMessage message(Protocol.PBFTMessage.Raw raw, byte[] key) {
    Protocol.PBFTMessage.Builder builder = Protocol.PBFTMessage.newBuilder().setRawData(raw);
    if (key != null) {
      byte[] hash = Sha256Hash.hash(true, raw.toByteArray());
      builder.setSignature(ByteString.copyFrom(ECKey.fromPrivate(key).sign(hash).toByteArray()));
    }
    return builder.build();
  }

  public static void main(String[] args) throws Exception {
    Protocol.PBFTMessage.Raw block = Protocol.PBFTMessage.Raw.newBuilder()
        .setMsgType(Protocol.PBFTMessage.MsgType.PREPREPARE)
        .setDataType(Protocol.PBFTMessage.DataType.BLOCK)
        .setViewN(7).setEpoch(42).setData(ByteString.copyFromUtf8("block-id")).build();
    byte[] privateKey = new byte[32]; privateKey[31] = 1;
    Protocol.PBFTMessage signed = message(block, privateKey);

    byte[] addressA = new byte[21]; java.util.Arrays.fill(addressA, (byte) 0x41);
    byte[] addressB = new byte[21]; java.util.Arrays.fill(addressB, (byte) 0x42);
    Protocol.SRL srl = Protocol.SRL.newBuilder()
        .addSrAddress(ByteString.copyFrom(addressA))
        .addSrAddress(ByteString.copyFrom(addressB)).build();
    Protocol.PBFTMessage.Raw srlRaw = Protocol.PBFTMessage.Raw.newBuilder()
        .setMsgType(Protocol.PBFTMessage.MsgType.PREPREPARE)
        .setDataType(Protocol.PBFTMessage.DataType.SRL)
        .setViewN(99).setEpoch(99).setData(srl.toByteString()).build();

    Discover.BackupMessage backupFalse = Discover.BackupMessage.newBuilder().setPriority(6).build();
    Discover.BackupMessage backupTrue = Discover.BackupMessage.newBuilder().setFlag(true).setPriority(10).build();
    System.out.println("{\"schema\":\"c018-java-capture.v3\"," 
        + "\"capture_contract\":\"pinned-input-output-error\"," 
        + "\"block_raw_hex\":\"" + hex(block.toByteArray()) + "\"," 
        + "\"block_unsigned_hex\":\"" + hex(message(block, null).toByteArray()) + "\"," 
        + "\"block_signed_hex\":\"" + hex(signed.toByteArray()) + "\"," 
        + "\"block_signature_hex\":\"" + hex(signed.getSignature().toByteArray()) + "\"," 
        + "\"block_view\":" + block.getViewN() + "," 
        + "\"block_epoch\":" + block.getEpoch() + "," 
        + "\"block_no\":\"" + block.getViewN() + "_" + block.getDataTypeValue() + "\"," 
        + "\"block_data_type\":\"" + block.getDataType().name() + "\"," 
        + "\"srl_raw_hex\":\"" + hex(srlRaw.toByteArray()) + "\"," 
        + "\"srl_no\":\"" + srlRaw.getViewN() + "_" + srlRaw.getDataTypeValue() + "\"," 
        + "\"srl_members\":" + srl.getSrAddressCount() + "," 
        + "\"backup_false_hex\":\"05" + hex(backupFalse.toByteArray()) + "\"," 
        + "\"backup_false_flag\":" + backupFalse.getFlag() + "," 
        + "\"backup_false_priority\":" + backupFalse.getPriority() + "," 
        + "\"backup_true_hex\":\"05" + hex(backupTrue.toByteArray()) + "\"," 
        + "\"backup_true_flag\":" + backupTrue.getFlag() + "," 
        + "\"backup_true_priority\":" + backupTrue.getPriority() + "," 
        + "\"backup_type\":5}");
  }
}
