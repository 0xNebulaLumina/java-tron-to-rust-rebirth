import java.io.*;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Stream;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;

/** Records real Picocli execute argv, writers and immediate fixture trees. */
public final class C027CommandAgent {
  public static void premain(String ignored,Instrumentation instrumentation){new AgentBuilder.Default().disableClassFormatChanges().type(ElementMatchers.named("picocli.CommandLine")).transform((builder,type,loader,module,protectionDomain)->builder.visit(Advice.to(ExecuteAdvice.class).on(ElementMatchers.named("execute").and(ElementMatchers.takesArguments(String[].class))))).installOn(instrumentation);}
  public static final class Tee extends Writer {public final Writer original;public final StringWriter capture=new StringWriter();public Tee(Writer original){this.original=original;}public void write(char[]v,int o,int n)throws IOException{original.write(v,o,n);capture.write(v,o,n);}public void flush()throws IOException{original.flush();capture.flush();}public void close()throws IOException{flush();}}
  public static final class State {public final Object command;public final Method setOut,setErr;public final PrintWriter out,err;public final Tee outTee,errTee;public final String beforeTree;public State(Object command)throws Exception{this.command=command;Class<?>t=command.getClass();Method getOut=t.getMethod("getOut"),getErr=t.getMethod("getErr");setOut=t.getMethod("setOut",PrintWriter.class);setErr=t.getMethod("setErr",PrintWriter.class);out=(PrintWriter)getOut.invoke(command);err=(PrintWriter)getErr.invoke(command);outTee=new Tee(out);errTee=new Tee(err);setOut.invoke(command,new PrintWriter(outTee,true));setErr.invoke(command,new PrintWriter(errTee,true));beforeTree=snapshot();}public void restore()throws Exception{setOut.invoke(command,out);setErr.invoke(command,err);}}
  public static final class ExecuteAdvice {
    @Advice.OnMethodEnter public static void enter(@Advice.This Object command,@Advice.Local("capture") State state)throws Exception{state=new State(command);}
    @Advice.OnMethodExit(onThrowable=Throwable.class) public static void exit(@Advice.Argument(0)String[]args,@Advice.Return int returned,@Advice.Thrown Throwable thrown,@Advice.Local("capture")State state)throws Exception{String afterTree=snapshot();state.restore();String path=System.getProperty("c027.command.capture");if(path==null)return;StringBuilder argv=new StringBuilder();for(String arg:args){if(argv.length()!=0)argv.append(',');argv.append(b64(arg));}String error=thrown==null?"":b64(thrown.toString());String row="C027_COMMAND|"+argv+"|"+returned+"|"+error+"|"+b64(state.outTee.capture.toString())+"|"+b64(state.errTee.capture.toString())+"|"+b64(state.beforeTree)+"|"+b64(afterTree)+"\n";try(FileOutputStream stream=new FileOutputStream(path,true)){stream.write(row.getBytes(StandardCharsets.UTF_8));}}
  }
  public static String snapshot()throws Exception{String raw=System.getProperty("c027.fixture.root");if(raw==null)return"";Path root=Paths.get(raw);if(!Files.exists(root))return"";StringBuilder out=new StringBuilder();try(Stream<Path> stream=Files.walk(root)){for(Path p:(Iterable<Path>)stream.sorted(Comparator.comparing(x->root.relativize(x).toString())).filter(x->!x.equals(root)&&!root.relativize(x).startsWith("logs"))::iterator){Path rel=root.relativize(p);String type=Files.isSymbolicLink(p)?"L":Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS)?"D":"F";long size=type.equals("F")?Files.size(p):0;String value=type.equals("F")?shaFile(p):type.equals("L")?b64(Files.readSymbolicLink(p).toString()):"";out.append(b64(rel.toString())).append('\t').append(type).append('\t').append(mode(p)).append('\t').append(size).append('\t').append(value).append('\n');}}return out.toString();}
  public static String mode(Path p){try{Set<PosixFilePermission>s=Files.getPosixFilePermissions(p,LinkOption.NOFOLLOW_LINKS);int m=0;PosixFilePermission[]a=PosixFilePermission.values();int[]b={0400,0200,0100,0040,0020,0010,0004,0002,0001};for(int i=0;i<a.length;i++)if(s.contains(a[i]))m|=b[i];return Integer.toOctalString(m);}catch(Exception e){return"0";}}
  public static String b64(String value){return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));}public static String hex(byte[]v){StringBuilder s=new StringBuilder();for(byte b:v)s.append(String.format("%02x",b&255));return s.toString();}
  public static String shaFile(Path path)throws Exception{MessageDigest digest=MessageDigest.getInstance("SHA-256");try(InputStream in=Files.newInputStream(path)){byte[] buffer=new byte[65536];for(int read;(read=in.read(buffer))>=0;)if(read!=0)digest.update(buffer,0,read);}return hex(digest.digest());}
}
