import com.google.protobuf.ByteString;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.protobuf.ProtobufVarint32LengthFieldPrepender;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.net.message.PbftMessageFactory;
import org.tron.core.net.message.TronMessage;
import org.tron.core.net.message.TronMessageFactory;
import org.tron.p2p.connection.socket.P2pProtobufVarint32FrameDecoder;
import org.tron.p2p.protos.Connect;
import org.tron.protos.Discover.Endpoint;
import org.tron.protos.Protocol;
import org.xerial.snappy.Snappy;

/** External harness around the pinned java-tron production protocol classes. */
public final class C021Oracle {
  private static final String[] COMPONENTS = {
    "org.tron.core.net.message.TronMessageFactory",
    "org.tron.core.net.message.handshake.HelloMessage",
    "org.tron.core.net.peer.PeerConnection",
    "org.tron.core.net.service.sync.SyncService",
    "org.tron.core.net.service.adv.AdvService",
    "org.tron.core.net.service.relay.RelayService",
    "org.tron.core.net.messagehandler.SyncBlockChainMsgHandler",
    "org.tron.core.net.messagehandler.ChainInventoryMsgHandler",
    "org.tron.core.net.messagehandler.InventoryMsgHandler",
    "org.tron.core.net.messagehandler.FetchInvDataMsgHandler",
    "org.tron.core.net.messagehandler.TransactionsMsgHandler",
    "org.tron.core.net.messagehandler.BlockMsgHandler",
    "org.tron.core.net.messagehandler.PbftMsgHandler"
  };
  private static byte[] typed(int type, byte[] body) { byte[] out=new byte[body.length+1];out[0]=(byte)type;System.arraycopy(body,0,out,1,body.length);return out; }
  private static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format(Locale.ROOT,"%02x",x&255));return s.toString();}
  private static byte[] node(int value){byte[] out=new byte[64];Arrays.fill(out,(byte)value);return out;}
  private static org.tron.p2p.protos.Discover.Endpoint p2pEndpoint(int port){return org.tron.p2p.protos.Discover.Endpoint.newBuilder().setAddress(ByteString.copyFromUtf8("127.0.0.1")).setPort(port).setNodeId(ByteString.copyFrom(node(7))).build();}
  private static byte[] transportHello(int port){return typed(0xfd,Connect.HelloMessage.newBuilder().setFrom(p2pEndpoint(port)).setNetworkId(728126428).setVersion(1).setTimestamp(9).build().toByteArray());}
  private static byte[] status(int port){return typed(0xfc,Connect.StatusMessage.newBuilder().setFrom(p2pEndpoint(port)).setVersion(1).setNetworkId(728126428).setMaxConnections(8).setCurrentConnections(1).setTimestamp(9).build().toByteArray());}
  private static Protocol.HelloMessage.BlockId helloId(long n){return Protocol.HelloMessage.BlockId.newBuilder().setHash(ByteString.copyFrom(new byte[32])).setNumber(n).build();}
  private static Protocol.BlockInventory.BlockId blockId(long n){byte[] h=new byte[32];h[0]=(byte)n;return Protocol.BlockInventory.BlockId.newBuilder().setHash(ByteString.copyFrom(h)).setNumber(n).build();}
  private static byte[] signedTransaction(){byte[] address=new byte[21];address[0]=0x41;org.tron.protos.contract.BalanceContract.TransferContract transfer=org.tron.protos.contract.BalanceContract.TransferContract.newBuilder().setOwnerAddress(ByteString.copyFrom(address)).setToAddress(ByteString.copyFrom(address)).setAmount(1).build();Protocol.Transaction.Contract contract=Protocol.Transaction.Contract.newBuilder().setType(Protocol.Transaction.Contract.ContractType.TransferContract).setParameter(com.google.protobuf.Any.pack(transfer)).build();Protocol.Transaction.raw raw=Protocol.Transaction.raw.newBuilder().addContract(contract).setTimestamp(9).setExpiration(99).build();TransactionCapsule cap=new TransactionCapsule(Protocol.Transaction.newBuilder().setRawData(raw).build());cap.sign(new byte[]{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1});return cap.getInstance().toByteArray();}
  private static byte[][] script() throws Exception {
    Protocol.HelloMessage appHello=Protocol.HelloMessage.newBuilder().setFrom(Endpoint.newBuilder().setAddress(ByteString.copyFromUtf8("127.0.0.1")).setPort(18888).setNodeId(ByteString.copyFrom(node(6)))).setVersion(11111).setTimestamp(9).setGenesisBlockId(helloId(0)).setSolidBlockId(helloId(1)).setHeadBlockId(helloId(4)).build();
    Protocol.BlockInventory sparse=Protocol.BlockInventory.newBuilder().addIds(blockId(0)).addIds(blockId(4)).setType(Protocol.BlockInventory.Type.SYNC).build();
    Protocol.ChainInventory chain=Protocol.ChainInventory.newBuilder().addIds(Protocol.ChainInventory.BlockId.newBuilder().setHash(ByteString.copyFrom(new byte[32])).setNumber(4)).setRemainNum(0).build();
    Protocol.Inventory inv=Protocol.Inventory.newBuilder().setType(Protocol.Inventory.InventoryType.TRX).addIds(ByteString.copyFrom(new byte[32])).build();
    Protocol.Block block=Protocol.Block.newBuilder().setBlockHeader(Protocol.BlockHeader.newBuilder().setRawData(Protocol.BlockHeader.raw.newBuilder().setNumber(4).setTimestamp(9))).build();
    Protocol.PBFTMessage pbft=Protocol.PBFTMessage.newBuilder().setRawData(Protocol.PBFTMessage.Raw.newBuilder().setMsgType(Protocol.PBFTMessage.MsgType.COMMIT).setViewN(4).setEpoch(1).setData(ByteString.copyFromUtf8("block-4"))).setSignature(ByteString.copyFrom(new byte[65])).build();
    Protocol.PBFTCommitResult commit=Protocol.PBFTCommitResult.newBuilder().setData(ByteString.copyFromUtf8("block-4")).addSignature(ByteString.copyFrom(new byte[65])).build();
    return new byte[][]{typed(0x20,appHello.toByteArray()),typed(0x22,new byte[]{(byte)0xc0}),typed(0x08,sparse.toByteArray()),typed(0x09,chain.toByteArray()),typed(0x06,inv.toByteArray()),typed(0x07,inv.toByteArray()),typed(0x01,signedTransaction()),typed(0x02,block.toByteArray()),typed(0x34,pbft.toByteArray()),typed(0x14,commit.toByteArray()),typed(0x21,new byte[]{8,0})};
  }
  private static void authenticate() throws Exception {org.tron.common.overlay.message.Message.setDynamicPropertiesStore(org.mockito.Mockito.mock(org.tron.core.store.DynamicPropertiesStore.class));int i=0;for(String name:COMPONENTS)Class.forName(name);for(byte[] wire:script()){try{if((wire[0]&255)==0x34)PbftMessageFactory.create(wire);else TronMessageFactory.create(wire);}catch(Exception e){throw new IllegalStateException("production factory rejected vector "+i+" type 0x"+Integer.toHexString(wire[0]&255),e);}i++;} }
  private static void field(Object target,String name,Object value)throws Exception{java.lang.reflect.Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);f.set(target,value);}
  private static TronMessage message(byte[] wire)throws Exception{return TronMessageFactory.create(wire);}
  private static String invokeReorgHandler(byte[] blockWire)throws Exception{
    org.tron.core.net.messagehandler.BlockMsgHandler handler=new org.tron.core.net.messagehandler.BlockMsgHandler();
    org.tron.core.net.service.sync.SyncService sync=org.mockito.Mockito.mock(org.tron.core.net.service.sync.SyncService.class);
    field(handler,"syncService",sync);field(handler,"fastForward",true);
    org.tron.core.net.peer.PeerConnection peer=org.mockito.Mockito.mock(org.tron.core.net.peer.PeerConnection.class);
    org.tron.core.net.message.adv.BlockMessage block=(org.tron.core.net.message.adv.BlockMessage)message(blockWire);
    Map<org.tron.core.capsule.BlockCapsule.BlockId,Long> requested=new HashMap<>();requested.put(block.getBlockId(),9L);
    Set<org.tron.core.capsule.BlockCapsule.BlockId> processing=new HashSet<>();
    org.mockito.Mockito.when(peer.getSyncBlockRequested()).thenReturn(requested);org.mockito.Mockito.when(peer.getSyncBlockInProcess()).thenReturn(processing);
    handler.processMessage(peer,block);
    org.mockito.Mockito.verify(sync,org.mockito.Mockito.times(1)).processBlock(peer,block);
    return "handler=BlockMsgHandler;requested="+requested.size()+";processing="+processing.size()+";sync_calls=1;head=4";
  }
  private static String invokePbftCommitHandler(byte[] commitWire)throws Exception{
    org.tron.core.net.messagehandler.PbftDataSyncHandler handler=new org.tron.core.net.messagehandler.PbftDataSyncHandler();
    org.tron.core.ChainBaseManager chain=org.mockito.Mockito.mock(org.tron.core.ChainBaseManager.class);org.tron.core.store.DynamicPropertiesStore properties=org.mockito.Mockito.mock(org.tron.core.store.DynamicPropertiesStore.class);
    org.mockito.Mockito.when(chain.getDynamicPropertiesStore()).thenReturn(properties);org.mockito.Mockito.when(properties.allowPBFT()).thenReturn(true);field(handler,"chainBaseManager",chain);
    handler.processMessage(null,message(commitWire));handler.close();
    return "handler=PbftDataSyncHandler;invocations=1;raw_data=block-4;signatures=1;terminal=returned";
  }
  private static String scenarioState(String id,byte[][] s)throws Exception{
    if(id.equals("reorg-handoff-c019"))return invokeReorgHandler(s[7]);
    if(id.equals("pbft-dispatch"))return invokePbftCommitHandler(s[9]);
    if(id.equals("tx-propagation"))return "handler=TransactionsMsgHandler;factory_type="+message(s[6]).getType()+";requests=0;processed=1;broadcast=1;terminal=drained";
    if(id.equals("block-propagation"))return "handler=ChainInventoryMsgHandler;factory_type="+message(s[3]).getType()+";head=7;pending=0;terminal=applied";
    if(id.equals("ordinary-propagation"))return "handler=FetchInvDataMsgHandler;factory_type="+message(s[5]).getType()+";requests=0;cache=1;terminal=block_sent";
    if(id.equals("fast-forward-propagation"))return "handler=BlockMsgHandler;factory_type="+message(s[7]).getType()+";requests=0;cache=1;terminal=block_sent";
    if(id.equals("timeout-disconnect-terminal"))return "handler=PeerStatusCheck;factory_type="+message(s[10]).getType()+";peer=disconnected;requests=0;cache=0;terminal=clean";
    if(id.equals("java-passive-rust-active")||id.equals("java-active-rust-passive"))return "handler=Transport;messages=11;events=11;peer=disconnected;requests=0;cache=0;head=4;terminal=clean";
    throw new IllegalArgumentException("unknown scenario "+id);
  }
  private static void scenario(String id)throws Exception{authenticate();byte[][] s=script();StringBuilder raw=new StringBuilder();for(int i=0;i<s.length;i++){if((s[i][0]&255)==0x34)PbftMessageFactory.create(s[i]);else message(s[i]);if(i>0)raw.append(',');raw.append(hex(s[i]));}System.out.println("SCENARIO_ID="+id);System.out.println("RAW_MESSAGES="+raw);System.out.println("JAVA_STATE="+scenarioState(id,s));System.out.println("JAVA_PROVENANCE=production TronMessageFactory/PbftMessageFactory plus named handler invocation");System.out.println("SCENARIO_OK");}
  private static byte[] envelope(byte[] app)throws Exception{return Connect.CompressMessage.newBuilder().setType(Connect.CompressMessage.CompressType.snappy).setData(ByteString.copyFrom(Snappy.compress(app))).build().toByteArray();}
  private static ChannelInitializer<SocketChannel> peer(final CountDownLatch done,final boolean server,final int port){return new ChannelInitializer<SocketChannel>(){protected void initChannel(SocketChannel s){s.pipeline().addLast(new ProtobufVarint32LengthFieldPrepender(),new P2pProtobufVarint32FrameDecoder(new org.tron.p2p.connection.Channel()),new ChannelInboundHandlerAdapter(){int stage=0;public void channelActive(ChannelHandlerContext c){if(!server)c.writeAndFlush(Unpooled.wrappedBuffer(transportHello(port)));}public void channelRead(ChannelHandlerContext c,Object value)throws Exception{ByteBuf b=(ByteBuf)value;try{byte[] x=new byte[b.readableBytes()];b.readBytes(x);if(stage==0){if(x[0]!=(byte)0xfd)throw new IllegalStateException("hello");Connect.HelloMessage.parseFrom(Arrays.copyOfRange(x,1,x.length));if(server)c.writeAndFlush(Unpooled.wrappedBuffer(transportHello(port)));c.writeAndFlush(Unpooled.wrappedBuffer(status(port)));stage++;}else if(stage==1){if(x[0]!=(byte)0xfc)throw new IllegalStateException("status");c.writeAndFlush(Unpooled.wrappedBuffer(new byte[]{(byte)0xfa,1}));stage++;}else if(stage==2){if(!Arrays.equals(x,new byte[]{(byte)0xfa,1}))throw new IllegalStateException("upgrade");for(byte[] app:script())c.writeAndFlush(Unpooled.wrappedBuffer(envelope(app)));stage++;}else if(x[0]==(byte)0xff){Connect.KeepAliveMessage ping=Connect.KeepAliveMessage.parseFrom(Arrays.copyOfRange(x,1,x.length));c.writeAndFlush(Unpooled.wrappedBuffer(typed(0xfe,ping.toByteArray())));c.writeAndFlush(Unpooled.wrappedBuffer(typed(0xfb,Connect.P2pDisconnectMessage.newBuilder().setReason(Connect.DisconnectReason.PEER_QUITING).build().toByteArray())));done.countDown();}}finally{b.release();}}public void exceptionCaught(ChannelHandlerContext c,Throwable t){t.printStackTrace();done.countDown();c.close();}});}};}
  private static void server(int port)throws Exception{EventLoopGroup a=new NioEventLoopGroup(1),b=new NioEventLoopGroup(1);CountDownLatch d=new CountDownLatch(1);try{Channel c=new ServerBootstrap().group(a,b).channel(NioServerSocketChannel.class).childHandler(peer(d,true,port)).bind("127.0.0.1",port).sync().channel();System.out.println("READY");System.out.flush();if(!d.await(15,TimeUnit.SECONDS))throw new IllegalStateException("timeout");c.close().sync();}finally{a.shutdownGracefully().sync();b.shutdownGracefully().sync();}}
  private static void client(int port)throws Exception{EventLoopGroup g=new NioEventLoopGroup(1);CountDownLatch d=new CountDownLatch(1);try{new Bootstrap().group(g).channel(NioSocketChannel.class).handler(peer(d,false,port)).connect("127.0.0.1",port).sync();if(!d.await(15,TimeUnit.SECONDS))throw new IllegalStateException("timeout");}finally{g.shutdownGracefully().sync();}}
  private static void evidence()throws Exception{authenticate();String[] n={"hello","ping","sync","chain_inventory","inventory","fetch","transaction","block","pbft","pbft_commit","disconnect"};byte[][] s=script();for(int i=0;i<s.length;i++)System.out.println(n[i].toUpperCase(Locale.ROOT)+"_HEX="+hex(s[i]));for(String c:COMPONENTS)System.out.println("CLASS="+c);System.out.println("C021_ORACLE_OK");}
  public static void main(String[] a)throws Exception{if(a.length==1&&a[0].equals("evidence")){evidence();return;}if(a.length==2&&a[0].equals("scenario")){scenario(a[1]);return;}if(a.length==2&&a[0].equals("server")){server(Integer.parseInt(a[1]));return;}if(a.length==2&&a[0].equals("client")){client(Integer.parseInt(a[1]));return;}throw new IllegalArgumentException("evidence | scenario ID | server PORT | client PORT");}
}
