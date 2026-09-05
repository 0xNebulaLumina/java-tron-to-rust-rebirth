package org.tron.tools.c012;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Reflection-only runtime hooks injected by C012Transformer. All hooks are observational. */
public final class C012Capture {
  private static final Object LOCK = new Object();
  private static final ThreadLocal<Boolean> GUARD = new ThreadLocal<Boolean>();
  private static final ThreadLocal<ArrayDeque<Invocation>> STACK = new ThreadLocal<ArrayDeque<Invocation>>() {
    protected ArrayDeque<Invocation> initialValue() { return new ArrayDeque<Invocation>(); }
  };
  private static final IdentityHashMap<Object,Ctor> CTORS = new IdentityHashMap<Object,Ctor>();
  private static final IdentityHashMap<Object,Integer> INSTANCES = new IdentityHashMap<Object,Integer>();
  private static final ThreadLocal<String> LOGICAL_STORE = new ThreadLocal<String>();
  private static final ArrayList<Invocation> INVOCATIONS = new ArrayList<Invocation>();
  private static final ArrayList<Map<String,Object>> AUDIT = new ArrayList<Map<String,Object>>();
  private static long nextToken, nextMutation; private static int nextInstance, completion;
  private static int testEntries, testExits; private static long testThread;
  private static String fatal; private static Object manager;
  private static final Set<String> STORES = new LinkedHashSet<String>(Arrays.asList(
    "account","accountid-index","account-index","account-asset","asset-issue","asset-issue-v2","block","block-index","trans","trans-cache","transactionRetStore","transactionHistoryStore","recent-block","recent-transaction","contract","abi","code","contract-state","storage-row","witness","witness_schedule","votes","proposal","exchange","exchange-v2","market_account","market_order","market_pair_to_price","market_pair_price_to_order","DelegatedResource","DelegatedResourceAccountIndex","properties","IncrementalMerkleTree","nullifier","zkProof","tree-block-index","section-bloom","account-trace","balance-trace","delegation","pbft-sign-data","reward-vi","common","checkpoint","tmp"));
  private static final HashMap<String,Integer> STORE_ORDER = new HashMap<String,Integer>();
  static { int i=0; for(String s:STORES) STORE_ORDER.put(s,i++); }
  private C012Capture() {}

  public static void audit(String name,String sha,String methods,boolean expectedLoader) { safe(new Op(){public void run(){ Map<String,Object> m=new LinkedHashMap<String,Object>(); m.put("class",name);m.put("original_sha256",sha);m.put("methods",methods);m.put("expected_application_loader",expectedLoader); synchronized(LOCK){AUDIT.add(m);} }}); }
  public static void captureFailure(Throwable t) { synchronized(LOCK){ if(fatal==null) fatal=t.getClass().getName()+": "+String.valueOf(t.getMessage()); } }
  private interface Op { void run() throws Exception; }
  private static void safe(Op op){ if(Boolean.TRUE.equals(GUARD.get()))return; try{GUARD.set(Boolean.TRUE);op.run();}catch(Throwable t){captureFailure(t);}finally{GUARD.remove();} }
  public static void enterTestBody(){ safe(new Op(){public void run(){ synchronized(LOCK){testEntries++; testThread=Thread.currentThread().getId();} }}); }
  public static void exitTestBody(final Throwable t){ safe(new Op(){public void run(){ synchronized(LOCK){testExits++; if(t!=null && fatal==null){} } }}); }
  public static void actuatorConstructed(final Object actuator,final Object type,final Class<?> messageClass){ safe(new Op(){public void run(){ synchronized(LOCK){CTORS.put(actuator,new Ctor(type,messageClass));} }}); }
  public static void managerInitialized(final Object value){ safe(new Op(){public void run(){manager=value;}}); }

  public static long enterInvocation(final Object actuator,final String phase,final Object argument){
    if(Boolean.TRUE.equals(GUARD.get()) || testEntries!=1 || testExits!=0) return 0;
    final long[] result={0}; safe(new Op(){public void run() throws Exception {
      if(Thread.currentThread().getId()!=testThread) throw new IllegalStateException("cross-thread actuator invocation");
      Invocation x=new Invocation(); synchronized(LOCK){x.token=++nextToken;x.ordinal=INVOCATIONS.size()+1;x.instance=instance(actuator);INVOCATIONS.add(x);} result[0]=x.token;
      x.actuator=actuator; x.actuatorClass=actuator.getClass().getName(); x.phase=phase; x.contract=contract(actuator); x.resultBefore=result(argument); x.argumentClass=argument==null?null:argument.getClass().getName();
      STACK.get().push(x);
    }}); return result[0];
  }
  public static void exitInvocationSuccess(final long token,final boolean value){ exit(token,Boolean.valueOf(value),null); }
  public static void exitInvocationFailure(final long token,final Throwable error){ exit(token,null,error); }
  private static void exit(final long token,final Boolean value,final Throwable error){ if(token==0)return; safe(new Op(){public void run() throws Exception{
    ArrayDeque<Invocation> stack=STACK.get(); Invocation x=stack.isEmpty()?null:stack.pop(); if(x==null||x.token!=token)throw new IllegalStateException("invocation stack mismatch");
    x.returnValue=value; x.error=throwable(error); x.resultAfter=resultByClass(x.resultBefore,x.argumentClass,x); for(Delta d:x.deltas.values()) d.after=read(d.store,d.key); synchronized(LOCK){x.completion=++completion;}
  }}); }
  private static int instance(Object a){Integer n=INSTANCES.get(a);if(n==null){n=++nextInstance;INSTANCES.put(a,n);}return n;}

  public static Object storeWriteEnter(final Object store,final byte[] key,final byte[] requested,final boolean delete){
    if(Boolean.TRUE.equals(GUARD.get())||STACK.get().isEmpty())return null; final Write w=new Write(); safe(new Op(){public void run() throws Exception{
      requireThread(); w.store=store;w.key=copy(key);w.requested=copy(requested);w.delete=delete;w.name=dbName(store);w.logical=store.getClass().getName().equals("org.tron.core.db2.core.Chainbase");
      if(!w.logical && w.name.equals(LOGICAL_STORE.get()))return;
      if(w.logical)LOGICAL_STORE.set(w.name);w.before=read(store,key);if(!STORE_ORDER.containsKey(w.name))throw new IllegalStateException("unknown logical store: "+w.name);
    }}); return w.before==null&&w.name==null?null:(!w.logical && w.name.equals(LOGICAL_STORE.get())?null:w);
  }
  public static void storeWriteExit(final Object token){ if(!(token instanceof Write))return; final Write w=(Write)token; safe(new Op(){public void run() throws Exception{
    w.after=read(w.store,w.key); ArrayList<Invocation> active=new ArrayList<Invocation>(STACK.get()); Collections.reverse(active);
    for(Invocation x:active){ DeltaKey k=new DeltaKey(w.name,w.key); Delta d=x.deltas.get(k); if(d==null){d=new Delta(w.store,w.name,w.key,w.before);x.deltas.put(k,d);} d.after=w.after;
      Mutation m=new Mutation(); synchronized(LOCK){m.ordinal=++nextMutation;} m.store=w.name;m.key=w.key;m.before=w.before;m.requested=w.requested;m.after=w.after;m.delete=w.delete;x.mutations.add(m); }
    if(w.logical)LOGICAL_STORE.remove();
  }}); }
  public static void storeRead(final Object store,final byte[] key,final byte[] value){ if(Boolean.TRUE.equals(GUARD.get())||STACK.get().isEmpty())return; safe(new Op(){public void run() throws Exception{
    requireThread();String name=dbName(store);if(!STORE_ORDER.containsKey(name))throw new IllegalStateException("unknown logical store: "+name);for(Invocation x:STACK.get()){DeltaKey k=new DeltaKey(name,key);if(!x.reads.containsKey(k))x.reads.put(k,copy(value));}
  }}); }
  private static void requireThread(){if(Thread.currentThread().getId()!=testThread)throw new IllegalStateException("unattributed cross-thread store access");}
  private static String dbName(Object o)throws Exception{return String.valueOf(invoke(o,o.getClass().getName().endsWith("Chainbase")?"getDbName":"getDBName"));}
  private static byte[] read(Object store,byte[] key)throws Exception{GUARD.set(Boolean.TRUE);try{Object v=invoke(store,store.getClass().getName().endsWith("Chainbase")?"getUnchecked":"getData",key);return copy((byte[])v);}finally{GUARD.remove();}}
  private static byte[] copy(byte[] b){return b==null?null:b.clone();}

  private static Map<String,Object> contract(Object actuator)throws Exception{
    Object any=field(actuator,"any"), full=field(actuator,"contract"); Ctor ctor=CTORS.get(actuator); if(full==null && any!=null && ctor!=null){Object builder=invokeStatic(Class.forName("org.tron.protos.Protocol$Transaction$Contract"),"newBuilder");invoke(builder,"setType",ctor.type);invoke(builder,"setParameter",any);full=invoke(builder,"build");}
    LinkedHashMap<String,Object> m=new LinkedHashMap<String,Object>();m.put("contract_source",field(actuator,"contract")!=null?"actual_contract":"synthesized_from_constructor_type_and_actual_any");m.put("contract_hex",hex(bytes(full)));m.put("contract_sha256",sha(bytes(full)));m.put("any_hex",hex(bytes(any)));m.put("any_sha256",sha(bytes(any)));m.put("any_type_url",any==null?null:invoke(any,"getTypeUrl"));m.put("any_value_hex",any==null?null:hex(bytes(invoke(any,"getValue"))));if(ctor!=null){m.put("type_number",invoke(ctor.type,"getNumber"));m.put("type_name",String.valueOf(ctor.type));m.put("message_class",ctor.messageClass==null?null:ctor.messageClass.getName());}return m;
  }
  private static Map<String,Object> result(Object arg)throws Exception{if(arg==null)return null; if(!arg.getClass().getName().equals("org.tron.core.capsule.TransactionResultCapsule"))return null;Object inst=invoke(arg,"getInstance");LinkedHashMap<String,Object> m=new LinkedHashMap<String,Object>();m.put("data_hex",hex((byte[])invoke(arg,"getData")));Object ret=invoke(inst,"getRet");m.put("ret_number",invoke(ret,"getNumber"));m.put("ret_name",String.valueOf(ret));m.put("fee",invoke(inst,"getFee"));m.put("asset_issue_id_hex",hex(bytes(invoke(inst,"getAssetIssueIDBytes"))));m.put("_object",arg);return m;}
  private static Map<String,Object> resultByClass(Map<String,Object> before,String cls,Invocation x)throws Exception{return before==null?null:result(before.get("_object"));}
  private static Map<String,Object> throwable(Throwable t){if(t==null)return null;LinkedHashMap<String,Object> m=new LinkedHashMap<String,Object>();m.put("class",t.getClass().getName());m.put("message_is_null",t.getMessage()==null);m.put("message_utf8_hex",hex(t.getMessage()==null?null:t.getMessage().getBytes(StandardCharsets.UTF_8)));ArrayList<Object> causes=new ArrayList<Object>();Throwable c=t.getCause();for(int i=0;c!=null&&i<8;i++,c=c.getCause())causes.add(throwable(c));m.put("causes",causes);return m;}

  public static String finishJson(Map<String,Object> junit){ synchronized(LOCK){LinkedHashMap<String,Object> root=new LinkedHashMap<String,Object>();root.put("schema","c012-java-invocation-observation-v1");root.putAll(junit);root.put("test_body_enter_count",testEntries);root.put("test_body_exit_count",testExits);root.put("invocation_count",INVOCATIONS.size());ArrayList<Object> rows=new ArrayList<Object>();for(Invocation x:INVOCATIONS)rows.add(x.json());root.put("invocations",rows);LinkedHashMap<String,Object>a=new LinkedHashMap<String,Object>();a.put("fatal",fatal);a.put("transforms",AUDIT);a.put("manager_registered",manager!=null);root.put("capture_audit",a);return json(root);} }
  public static void verify(){if(fatal!=null)throw new IllegalStateException("capture fatal: "+fatal);if(testEntries!=1||testExits!=1)throw new IllegalStateException("selected body count "+testEntries+"/"+testExits);boolean test=false,base=false;for(Map<String,Object>a:AUDIT){String n=(String)a.get("class");if(n.equals(System.getProperty("c012.test.class").replace('.','/')))test=true;if(n.equals("org/tron/core/actuator/AbstractActuator"))base=true;}if(!test||!base)throw new IllegalStateException("transform audit incomplete test="+test+" base="+base);}

  private static final class Ctor{final Object type;final Class<?>messageClass;Ctor(Object t,Class<?>c){type=t;messageClass=c;}}
  private static final class Write{Object store;String name;byte[]key,requested,before,after;boolean delete,logical;}
  private static final class DeltaKey{final String store;final byte[]key;DeltaKey(String s,byte[]k){store=s;key=copy(k);}public int hashCode(){return 31*store.hashCode()+Arrays.hashCode(key);}public boolean equals(Object o){return o instanceof DeltaKey&&store.equals(((DeltaKey)o).store)&&Arrays.equals(key,((DeltaKey)o).key);}}
  private static final class Delta{Object store;String name;byte[]key,before,after;Delta(Object s,String n,byte[]k,byte[]b){store=s;name=n;key=copy(k);before=copy(b);}Map<String,Object>json(){LinkedHashMap<String,Object>m=new LinkedHashMap<String,Object>();m.put("store",name);m.put("store_ordinal",STORE_ORDER.get(name));m.put("key_hex",hex(key));m.put("before_hex",hex(before));m.put("after_hex",hex(after));return m;}}
  private static final class Mutation{long ordinal;String store;byte[]key,before,requested,after;boolean delete;Map<String,Object>json(){LinkedHashMap<String,Object>m=new LinkedHashMap<String,Object>();m.put("mutation_ordinal",ordinal);m.put("store",store);m.put("key_hex",hex(key));m.put("operation",delete?"delete":"put");m.put("before_hex",hex(before));m.put("requested_hex",hex(requested));m.put("actual_after_hex",hex(after));return m;}}
  private static final class Invocation{long token;int ordinal,completion,instance;Object actuator;String actuatorClass,phase,argumentClass;Map<String,Object>contract,resultBefore,resultAfter,error;Boolean returnValue;LinkedHashMap<DeltaKey,byte[]>reads=new LinkedHashMap<DeltaKey,byte[]>();LinkedHashMap<DeltaKey,Delta>deltas=new LinkedHashMap<DeltaKey,Delta>();ArrayList<Mutation>mutations=new ArrayList<Mutation>();Map<String,Object>json(){LinkedHashMap<String,Object>m=new LinkedHashMap<String,Object>();m.put("invocation_id",System.getProperty("c012.stable.id")+"/invocation/"+String.format("%03d",ordinal));m.put("ordinal",ordinal);m.put("completion_ordinal",completion);m.put("actuator_instance_ordinal",instance);m.put("actuator_class",actuatorClass);m.put("phase",phase);m.put("contract",contract);m.put("argument_class",argumentClass);m.put("return",returnValue);m.put("error",error);strip(resultBefore);strip(resultAfter);m.put("result_before",resultBefore);m.put("result_after",resultAfter);ArrayList<Object>r=new ArrayList<Object>();for(Map.Entry<DeltaKey,byte[]>e:reads.entrySet()){LinkedHashMap<String,Object>q=new LinkedHashMap<String,Object>();q.put("store",e.getKey().store);q.put("key_hex",hex(e.getKey().key));q.put("value_hex",hex(e.getValue()));r.add(q);}m.put("read_dependencies",r);ArrayList<Object>mt=new ArrayList<Object>();for(Mutation q:mutations)mt.add(q.json());m.put("mutation_trace",mt);ArrayList<Delta>ds=new ArrayList<Delta>(deltas.values());Collections.sort(ds,new Comparator<Delta>(){public int compare(Delta a,Delta b){int c=STORE_ORDER.get(a.name)-STORE_ORDER.get(b.name);if(c!=0)return c;int n=Math.min(a.key.length,b.key.length);for(int i=0;i<n;i++){c=(a.key[i]&255)-(b.key[i]&255);if(c!=0)return c;}return a.key.length-b.key.length;}});ArrayList<Object>dj=new ArrayList<Object>();for(Delta d:ds)dj.add(d.json());m.put("ordered_store_deltas",dj);m.put("lifecycle_reference",Collections.singletonMap("status",ds.isEmpty()?"no_state_change":"baseline_only"));return m;}}
  private static void strip(Map<String,Object>m){if(m!=null)m.remove("_object");}
  private static Object field(Object o,String name)throws Exception{for(Class<?>c=o.getClass();c!=null;c=c.getSuperclass())try{Field f=c.getDeclaredField(name);f.setAccessible(true);return f.get(o);}catch(NoSuchFieldException e){}throw new NoSuchFieldException(name);}
  private static Object invokeStatic(Class<?>c,String n,Object...a)throws Exception{return invoke0(null,c,n,a);}
  private static Object invoke(Object o,String n,Object...a)throws Exception{return invoke0(o,o.getClass(),n,a);}
  private static Object invoke0(Object o,Class<?>c,String n,Object[]a)throws Exception{for(Method m:c.getMethods())if(m.getName().equals(n)&&m.getParameterTypes().length==a.length){try{return m.invoke(o,a);}catch(IllegalArgumentException e){}}throw new NoSuchMethodException(c.getName()+"."+n);}
  private static byte[] bytes(Object o)throws Exception{if(o==null)return null;if(o instanceof byte[])return(byte[])o;return(byte[])invoke(o,"toByteArray");}
  private static String sha(byte[]b)throws Exception{return b==null?null:hex(MessageDigest.getInstance("SHA-256").digest(b));}
  private static String hex(byte[]b){if(b==null)return null;char[]d="0123456789abcdef".toCharArray(),o=new char[b.length*2];for(int i=0;i<b.length;i++){o[2*i]=d[(b[i]>>>4)&15];o[2*i+1]=d[b[i]&15];}return new String(o);}
  @SuppressWarnings("unchecked") private static String json(Object v){if(v==null)return"null";if(v instanceof String){String s=(String)v;StringBuilder b=new StringBuilder("\"");for(int i=0;i<s.length();i++){char c=s.charAt(i);if(c=='\"'||c=='\\')b.append('\\').append(c);else if(c=='\n')b.append("\\n");else if(c=='\r')b.append("\\r");else if(c=='\t')b.append("\\t");else if(c<32)b.append(String.format("\\u%04x",(int)c));else b.append(c);}return b.append('\"').toString();}if(v instanceof Number||v instanceof Boolean)return String.valueOf(v);if(v instanceof Map){StringBuilder b=new StringBuilder("{");boolean first=true;for(Map.Entry<Object,Object>e:((Map<Object,Object>)v).entrySet()){if(!first)b.append(',');first=false;b.append(json(String.valueOf(e.getKey()))).append(':').append(json(e.getValue()));}return b.append('}').toString();}if(v instanceof Iterable){StringBuilder b=new StringBuilder("[");boolean first=true;for(Object x:(Iterable<?>)v){if(!first)b.append(',');first=false;b.append(json(x));}return b.append(']').toString();}return json(String.valueOf(v));}
}
