import com.google.protobuf.ByteString;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.protobuf.ProtobufVarint32LengthFieldPrepender;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.tron.p2p.connection.message.Message;
import org.tron.p2p.connection.message.base.P2pDisconnectMessage;
import org.tron.p2p.connection.business.upgrade.UpgradeController;
import org.tron.p2p.connection.message.handshake.HelloMessage;
import org.tron.p2p.connection.socket.P2pProtobufVarint32FrameDecoder;
import org.tron.p2p.discover.message.kad.PingMessage;
import org.tron.p2p.discover.message.kad.NeighborsMessage;
import org.tron.p2p.discover.message.kad.PongMessage;
import org.tron.p2p.discover.socket.P2pPacketDecoder;
import org.tron.p2p.discover.socket.UdpEvent;
import org.tron.p2p.protos.Connect;
import org.tron.p2p.protos.Discover;
import org.xerial.snappy.Snappy;

/** Executable oracle backed only by authenticated libp2p 2.2.9 codecs and messages. */
public final class C020Oracle {
  private static byte[] nodeId() {
    String hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        + "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    byte[] out = new byte[64]; for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(hex.substring(i*2,i*2+2),16);
    return out;
  }

  private static Discover.Endpoint endpoint(int port) {
    return Discover.Endpoint.newBuilder().setAddress(ByteString.copyFromUtf8("127.0.0.1"))
        .setPort(port).setNodeId(ByteString.copyFrom(nodeId())).build();
  }

  private static byte[] tcpMessage() throws Exception {
    Connect.HelloMessage proto = Connect.HelloMessage.newBuilder().setFrom(endpoint(18888))
        .setNetworkId(728126428).setVersion(1).setCode(0).setTimestamp(9).build();
    HelloMessage hello = new HelloMessage(proto.toByteArray());
    if (!hello.valid() || hello.getNetworkId() != 728126428) throw new IllegalStateException("invalid HelloMessage");
    return hello.getSendData();
  }

  private static byte[] ping(int fromPort, int toPort) throws Exception {
    Discover.PingMessage proto = Discover.PingMessage.newBuilder().setFrom(endpoint(fromPort))
        .setTo(endpoint(toPort)).setVersion(4).setTimestamp(9).build();
    PingMessage message = new PingMessage(proto.toByteArray());
    if (!message.valid()) throw new IllegalStateException("invalid PingMessage");
    return message.getSendData();
  }

  private static byte[] pong(int port) throws Exception {
    Discover.PongMessage proto = Discover.PongMessage.newBuilder().setFrom(endpoint(port)).setEcho(7).setTimestamp(9).build();
    PongMessage message = new PongMessage(proto.toByteArray());
    if (!message.valid()) throw new IllegalStateException("invalid PongMessage");
    return message.getSendData();
  }

  private static byte[] neighbours(int port) throws Exception {
    Discover.Neighbours proto = Discover.Neighbours.newBuilder().setFrom(endpoint(port))
        .addNeighbours(endpoint(port + 1)).setTimestamp(9).build();
    NeighborsMessage message = new NeighborsMessage(proto.toByteArray());
    if (!message.valid()) throw new IllegalStateException("invalid NeighborsMessage");
    return message.getSendData();
  }

  private static byte[] typed(int type, byte[] body) {
    byte[] out = new byte[body.length + 1]; out[0] = (byte) type; System.arraycopy(body, 0, out, 1, body.length); return out;
  }

  private static byte[] status() {
    return typed(0xfc, Connect.StatusMessage.newBuilder().setFrom(endpoint(18888)).setVersion(1)
        .setNetworkId(728126428).setMaxConnections(30).setCurrentConnections(1).setTimestamp(9).build().toByteArray());
  }

  private static byte[] compressedHello() throws Exception {
    Connect.CompressMessage message = Connect.CompressMessage.newBuilder()
        .setType(Connect.CompressMessage.CompressType.snappy)
        .setData(ByteString.copyFrom(Snappy.compress(tcpMessage()))).build();
    return message.toByteArray();
  }

  private static ChannelInitializer<SocketChannel> peer(final CountDownLatch done, final boolean server) {
    return new ChannelInitializer<SocketChannel>() {
      protected void initChannel(SocketChannel socket) {
        org.tron.p2p.connection.Channel libp2pChannel = new org.tron.p2p.connection.Channel();
        socket.pipeline().addLast("protoPrepend", new ProtobufVarint32LengthFieldPrepender());
        socket.pipeline().addLast("protoDecode", new P2pProtobufVarint32FrameDecoder(libp2pChannel));
        socket.pipeline().addLast("oracle", new ChannelInboundHandlerAdapter() {
          int stage = 0;
          public void channelActive(ChannelHandlerContext ctx) throws Exception { if (!server) ctx.writeAndFlush(Unpooled.wrappedBuffer(tcpMessage())); }
          public void channelRead(ChannelHandlerContext ctx, Object value) throws Exception {
            ByteBuf frame = (ByteBuf) value;
            try {
              byte[] body = new byte[frame.readableBytes()]; frame.readBytes(body);
              if (stage == 0) {
                Message decoded = Message.parse(body);
                if (!(decoded instanceof HelloMessage) || !decoded.valid()) throw new IllegalStateException("expected hello");
                if (server) ctx.writeAndFlush(Unpooled.wrappedBuffer(tcpMessage()));
                ctx.writeAndFlush(Unpooled.wrappedBuffer(status())); stage = 1;
              } else if (stage == 1) {
                if (body.length < 2 || (body[0] & 0xff) != 0xfc) throw new IllegalStateException("expected status");
                Connect.StatusMessage.parseFrom(Arrays.copyOfRange(body, 1, body.length));
                ctx.writeAndFlush(Unpooled.wrappedBuffer(new byte[]{(byte)0xfa,1})); stage = 2;
              } else if (stage == 2) {
                if (!Arrays.equals(body, new byte[]{(byte)0xfa,1})) throw new IllegalStateException("expected snappy upgrade");
                ctx.writeAndFlush(Unpooled.wrappedBuffer(compressedHello())); stage = 3;
              } else if (stage == 3) {
                if (body.length < 2 || (body[0] & 0xff) != 0xff) throw new IllegalStateException("expected keepalive ping");
                Connect.KeepAliveMessage ping = Connect.KeepAliveMessage.parseFrom(Arrays.copyOfRange(body,1,body.length));
                ctx.writeAndFlush(Unpooled.wrappedBuffer(typed(0xfe,ping.toByteArray())));
                ctx.writeAndFlush(Unpooled.wrappedBuffer(new P2pDisconnectMessage(Connect.DisconnectReason.PEER_QUITING).getSendData()));
                System.out.println(server ? "TCP_SERVER_SESSION_OK" : "TCP_CLIENT_SESSION_OK"); System.out.flush(); done.countDown(); stage = 4;
              }
            } finally { frame.release(); }
          }
          public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) { cause.printStackTrace(); done.countDown(); ctx.close(); }
        });
      }
    };
  }

  private static void tcpServer(int port) throws Exception {
    EventLoopGroup boss = new NioEventLoopGroup(1), worker = new NioEventLoopGroup(1); CountDownLatch done = new CountDownLatch(1);
    try {
      Channel channel = new ServerBootstrap().group(boss, worker).channel(NioServerSocketChannel.class)
          .childHandler(peer(done, true)).bind("127.0.0.1", port).sync().channel();
      System.out.println("READY " + ((InetSocketAddress) channel.localAddress()).getPort()); System.out.flush();
      if (!done.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("TCP server timeout"); channel.close().sync();
    } finally { boss.shutdownGracefully().sync(); worker.shutdownGracefully().sync(); }
  }

  private static void tcpClient(int port) throws Exception {
    EventLoopGroup group = new NioEventLoopGroup(1); CountDownLatch done = new CountDownLatch(1);
    try { new Bootstrap().group(group).channel(NioSocketChannel.class).option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 3000)
        .handler(peer(done, false)).connect("127.0.0.1", port).sync();
      if (!done.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("TCP client timeout");
    } finally { group.shutdownGracefully().sync(); }
  }

  private static UdpEvent decodeUdp(byte[] bytes, InetSocketAddress sender, InetSocketAddress recipient) {
    EmbeddedChannel channel = new EmbeddedChannel(new P2pPacketDecoder());
    try {
      channel.writeInbound(new io.netty.channel.socket.DatagramPacket(Unpooled.wrappedBuffer(bytes), recipient, sender));
      return channel.readInbound();
    } finally { channel.finishAndReleaseAll(); }
  }

  private static void udpServer(int port) throws Exception {
    try (DatagramSocket socket = new DatagramSocket(port, InetAddress.getByName("127.0.0.1"))) {
      System.out.println("READY " + socket.getLocalPort()); System.out.flush(); byte[] buf = new byte[2048];
      DatagramPacket packet = new DatagramPacket(buf, buf.length); socket.setSoTimeout(10000); socket.receive(packet);
      byte[] wire = Arrays.copyOf(buf, packet.getLength());
      UdpEvent event = decodeUdp(wire, (InetSocketAddress) packet.getSocketAddress(), new InetSocketAddress("127.0.0.1", port));
      if (event == null || !(event.getMessage() instanceof PingMessage)) throw new IllegalStateException("P2pPacketDecoder rejected ping");
      byte[] reply = pong(socket.getLocalPort()); socket.send(new DatagramPacket(reply, reply.length, packet.getSocketAddress()));
      System.out.println("UDP_SERVER_OK");
    }
  }

  private static void udpClient(int port) throws Exception {
    try (DatagramSocket socket = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"))) {
      byte[] request = ping(socket.getLocalPort(), port); socket.setSoTimeout(10000);
      socket.send(new DatagramPacket(request, request.length, InetAddress.getByName("127.0.0.1"), port));
      byte[] buf = new byte[2048]; DatagramPacket packet = new DatagramPacket(buf, buf.length); socket.receive(packet);
      UdpEvent event = decodeUdp(Arrays.copyOf(buf, packet.getLength()), (InetSocketAddress) packet.getSocketAddress(),
          new InetSocketAddress("127.0.0.1", socket.getLocalPort()));
      if (event == null || !(event.getMessage() instanceof PongMessage)) throw new IllegalStateException("P2pPacketDecoder rejected pong");
      System.out.println("UDP_CLIENT_OK");
    }
  }

  private static void evidence() throws Exception {
    byte[] hello = tcpMessage();
    Connect.CompressMessage compress = Connect.CompressMessage.newBuilder().setType(Connect.CompressMessage.CompressType.uncompress)
        .setData(ByteString.copyFrom(hello)).build();
    if (!Arrays.equals(Connect.CompressMessage.parseFrom(compress.toByteArray()).getData().toByteArray(), hello))
      throw new IllegalStateException("CompressMessage roundtrip");
    P2pDisconnectMessage disconnect = new P2pDisconnectMessage(Connect.DisconnectReason.PEER_QUITING);
    if (!(Message.parse(disconnect.getSendData()) instanceof P2pDisconnectMessage)) throw new IllegalStateException("disconnect roundtrip");
    EmbeddedChannel encoder = new EmbeddedChannel(new ProtobufVarint32LengthFieldPrepender());
    encoder.writeOutbound(Unpooled.wrappedBuffer(hello)); ByteBuf framed = encoder.readOutbound(); byte[] wire = new byte[framed.readableBytes()]; framed.readBytes(wire); framed.release(); encoder.finishAndReleaseAll();
    EmbeddedChannel decoder = new EmbeddedChannel(new P2pProtobufVarint32FrameDecoder(new org.tron.p2p.connection.Channel()));
    decoder.writeInbound(Unpooled.wrappedBuffer(wire)); ByteBuf decoded = decoder.readInbound();
    if (decoded == null || !Arrays.equals(hello, io.netty.buffer.ByteBufUtil.getBytes(decoded))) throw new IllegalStateException("frame codec roundtrip"); decoded.release(); decoder.finishAndReleaseAll();
    boolean malformed = false;
    EmbeddedChannel bad = new EmbeddedChannel(new P2pProtobufVarint32FrameDecoder(new org.tron.p2p.connection.Channel()));
    try { bad.writeInbound(Unpooled.wrappedBuffer(new byte[]{(byte)0x80,(byte)0x80,(byte)0x80,(byte)0x80,(byte)0x80,0})); }
    catch (CorruptedFrameException expected) { malformed = true; } finally { try { bad.finishAndReleaseAll(); } catch (Exception ignored) {} }
    if (!malformed) throw new IllegalStateException("high-bit varint was accepted");
    byte[] pingWire = ping(18888,18888);
    UdpEvent captured = decodeUdp(pingWire, new InetSocketAddress("203.0.113.9",40000), new InetSocketAddress("127.0.0.1",18888));
    if (captured == null || !(captured.getMessage() instanceof PingMessage)
        || !"127.0.0.1".equals(((PingMessage) captured.getMessage()).getFrom().getHostV4()))
      throw new IllegalStateException("UDP source overrode declared endpoint");
    byte[] neighboursWire = neighbours(18888);
    UdpEvent decodedNeighbours = decodeUdp(neighboursWire, new InetSocketAddress("127.0.0.1",40000), new InetSocketAddress("127.0.0.1",18888));
    if (decodedNeighbours == null || !(decodedNeighbours.getMessage() instanceof NeighborsMessage)
        || !((NeighborsMessage) decodedNeighbours.getMessage()).valid())
      throw new IllegalStateException("P2pPacketDecoder rejected neighbours");
    byte[] disabledUpgrade = UpgradeController.codeSendData(0, hello);
    byte[] enabledUpgrade = UpgradeController.codeSendData(1, hello);
    if (!Arrays.equals(disabledUpgrade, hello)) throw new IllegalStateException("disabled UpgradeController must skip compression envelope");
    if (Arrays.equals(enabledUpgrade, hello) || !Arrays.equals(UpgradeController.decodeReceiveData(1, enabledUpgrade), hello))
      throw new IllegalStateException("enabled UpgradeController envelope mismatch");
    System.out.println("TCP_MESSAGE_HEX=" + org.tron.p2p.utils.ByteArray.toHexString(hello));
    System.out.println("TCP_WIRE_HEX=" + org.tron.p2p.utils.ByteArray.toHexString(wire));
    System.out.println("UDP_PING_HEX=" + org.tron.p2p.utils.ByteArray.toHexString(pingWire));
    System.out.println("UDP_PONG_HEX=" + org.tron.p2p.utils.ByteArray.toHexString(pong(18888)));
    System.out.println("UDP_NEIGHBOURS_HEX=" + org.tron.p2p.utils.ByteArray.toHexString(neighboursWire));
    System.out.println("JAR_CODEC_EVIDENCE_OK");
    System.out.println("UPGRADE_DISABLED_HEX=" + org.tron.p2p.utils.ByteArray.toHexString(disabledUpgrade));
    System.out.println("UPGRADE_ENABLED_HEX=" + org.tron.p2p.utils.ByteArray.toHexString(enabledUpgrade));
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 1 || args.length > 2) throw new IllegalArgumentException("MODE [PORT]");
    int port = args.length == 2 ? Integer.parseInt(args[1]) : 0;
    switch (args[0]) {
      case "tcp-server": tcpServer(port); break; case "tcp-client": tcpClient(port); break;
      case "udp-server": udpServer(port); break; case "udp-client": udpClient(port); break;
      case "evidence": evidence(); break; default: throw new IllegalArgumentException(args[0]);
    }
  }
}
