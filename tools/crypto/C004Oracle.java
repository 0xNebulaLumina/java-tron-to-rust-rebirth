// Java 8-compatible, mechanically-derived C004 compatibility oracle.
// Compiled only with authenticated Bouncy Castle 1.84; no java-tron source is copied.
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.math.ec.ECPoint;

public final class C004Oracle {
  private static final byte[] PRIVATE_ONE = scalar(BigInteger.ONE);
  private static final byte[] PREHASH = sha256(bytes("C004 deterministic signature input"));
  private static final String REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3";
  private static final String BC_SHA256 = "64d6c5a6121fcd927152dd182cbed39afe0fda641a970d9bcc0c9cb1858b2731";
  private static final String POM_SHA256 = "ce7abb4a91ba5d2a73fdf17a3df4762e3605a0392cc7983ef2f1ae16cd384cc3";

  private static final class Curve {
    final X9ECParameters p; final BigInteger n; final ECPoint g; final ECPoint q;
    Curve(X9ECParameters p) { this.p=p; n=p.getN(); g=p.getG(); q=g.multiply(BigInteger.ONE).normalize(); }
  }
  private static final class Sig { final BigInteger r,s; final int recid; Sig(BigInteger r, BigInteger s, int recid){this.r=r;this.s=s;this.recid=recid;} }

  public static void main(String[] args) throws Exception {
    Curve secp = new Curve(SECNamedCurves.getByName("secp256k1"));
    Curve sm2 = new Curve(GMNamedCurves.getByName("sm2p256v1"));
    byte[] input = bytes("C004 fixed hash input");
    byte[] secpPub = uncompressed(secp.q), sm2Pub = uncompressed(sm2.q);
    byte[] secpAddress = address(secpPub), sm2Address = address(sm2Pub);
    Sig secpSig = ecdsa(secp, PREHASH, BigInteger.valueOf(2));
    Sig sm2Sig = sm2(sm2, PREHASH, BigInteger.valueOf(2));
    byte[] generic = hex("41000102030405060708090a0b0c0d0e0f10111213");
    StringBuilder j = new StringBuilder(16384);
    j.append("{\n  \"schema_version\": 1,\n  \"id\": \"c004-crypto-fixture-manifest-v1\",\n");
    j.append("  \"generator\": {\"path\":\"tools/crypto/C004Oracle.java\",\"java_source_revision\":\"").append(REVISION)
      .append("\",\"bcprov\":\"org.bouncycastle:bcprov-jdk18on:1.84\",\"bcprov_sha256\":\"").append(BC_SHA256)
      .append("\",\"gradle_pom_sha256\":\"").append(POM_SHA256).append("\"},\n  \"vectors\": [\n");
    boolean first=true;
    first=vec(j,first,"C004.HASH.SHA256", "\"input_utf8\":\"C004 fixed hash input\",\"output_hex\":\""+hx(sha256(input))+"\"");
    first=vec(j,first,"C004.HASH.SM3", "\"input_utf8\":\"C004 fixed hash input\",\"output_hex\":\""+hx(sm3(input))+"\"");
    first=vec(j,first,"C004.HASH.KECCAK256", "\"input_utf8\":\"C004 fixed hash input\",\"output_hex\":\""+hx(keccak(input,256))+"\"");
    first=vec(j,first,"C004.HASH.KECCAK512", "\"input_utf8\":\"C004 fixed hash input\",\"output_hex\":\""+hx(keccak(input,512))+"\"");
    first=vec(j,first,"C004.HASH.RIPEMD160", "\"input_utf8\":\"C004 fixed hash input\",\"output_hex\":\""+hx(ripemd(input))+"\"");
    first=vec(j,first,"C004.KEY.SECP256K1", "\"private_key_hex\":\""+hx(PRIVATE_ONE)+"\",\"public_key_uncompressed_hex\":\""+hx(secpPub)+"\",\"address_hex\":\""+hx(secpAddress)+"\",\"address_base58check\":\""+base58check(secpAddress,false)+"\"");
    first=vec(j,first,"C004.KEY.SM2", "\"private_key_hex\":\""+hx(PRIVATE_ONE)+"\",\"public_key_uncompressed_hex\":\""+hx(sm2Pub)+"\",\"address_hex\":\""+hx(sm2Address)+"\",\"address_base58check\":\""+base58check(sm2Address,true)+"\"");
    first=vec(j,first,"C004.SIG.SECP256K1", sigFields(secp,secpSig,"low_s",true));
    first=vec(j,first,"C004.SIG.SECP256K1.HIGH_S", sigFields(secp,new Sig(secpSig.r,secp.n.subtract(secpSig.s),secpSig.recid^1),"recover_and_verify",true));
    first=vec(j,first,"C004.SIG.SM2", sigFields(sm2,sm2Sig,"verify_and_recover_compatibility",verifySm2(sm2,PREHASH,sm2Sig)));
    first=vec(j,first,"C004.BASE58.SECP256K1", "\"payload_hex\":\""+hx(generic)+"\",\"encoded\":\""+base58check(generic,false)+"\"");
    first=vec(j,first,"C004.BASE58.SM2", "\"payload_hex\":\""+hx(generic)+"\",\"encoded\":\""+base58check(generic,true)+"\"");
    first=vec(j,first,"C004.ADDRESS.INVALID_PREFIX", "\"input_hex\":\"420000000000000000000000000000000000000000\",\"error\":\"invalid_prefix\"");
    first=policy(j,first,"C004.WIRE.INGRESS_64","signature_format"); first=policy(j,first,"C004.WIRE.INGRESS_65","accepted");
    first=policy(j,first,"C004.WIRE.INGRESS_68","accepted"); first=policy(j,first,"C004.WIRE.INGRESS_69","signature_format");
    first=policy(j,first,"C004.WIRE.CONSENSUS_69","accepted_ignore_trailing");
    first=policy(j,first,"C004.PERMISSION.TOO_MANY","too_many_signatures"); first=policy(j,first,"C004.PERMISSION.NONMEMBER","signer_not_in_permission");
    first=policy(j,first,"C004.PERMISSION.DUPLICATE_PRE_471","canonical_signature_identity"); first=policy(j,first,"C004.PERMISSION.DUPLICATE_POST_471","recovered_address_identity");
    byte[] txid=sequence(32,0), owner=hex("41000102030405060708090a0b0c0d0e0f10111213"), salt=sequence(32,32), code=bytes("C004 init code");
    first=vec(j,first,"C004.FORMULA.TOP_LEVEL", "\"txid_hex\":\""+hx(txid)+"\",\"owner_hex\":\""+hx(owner)+"\",\"address_hex\":\""+hx(tronAddress(concat(txid,owner)))+"\"");
    first=vec(j,first,"C004.FORMULA.CREATE.POSITIVE", "\"root_txid_hex\":\""+hx(txid)+"\",\"nonce\":1,\"address_hex\":\""+hx(tronAddress(concat(txid,i64(1))))+"\"");
    first=vec(j,first,"C004.FORMULA.CREATE.NEGATIVE", "\"root_txid_hex\":\""+hx(txid)+"\",\"nonce\":-1,\"address_hex\":\""+hx(tronAddress(concat(txid,i64(-1))))+"\"");
    first=vec(j,first,"C004.FORMULA.CREATE2", "\"creator_hex\":\""+hx(owner)+"\",\"salt_hex\":\""+hx(salt)+"\",\"init_code_hex\":\""+hx(code)+"\",\"address_hex\":\""+hx(tronAddress(concat(owner,salt,keccak(code,256))))+"\"");
    j.append("\n  ]\n}\n"); System.out.print(j.toString());
  }
  static boolean vec(StringBuilder j,boolean first,String id,String fields){if(!first)j.append(",\n");j.append("    {\"id\":\"").append(id).append("\",").append(fields).append("}");return false;}
  static boolean policy(StringBuilder j,boolean first,String id,String expected){return vec(j,first,id,"\"expected\":\""+expected+"\"");}
  static String sigFields(Curve c,Sig s,String policy,boolean verified){return "\"prehash_hex\":\""+hx(PREHASH)+"\",\"nonce_hex\":\""+hx(scalar(BigInteger.valueOf(2)))+"\",\"r_hex\":\""+hx(scalar(s.r))+"\",\"s_hex\":\""+hx(scalar(s.s))+"\",\"recovery_id\":"+s.recid+",\"wire_hex\":\""+hx(wire(s))+"\",\"policy\":\""+policy+"\",\"verified\":"+verified;}
  static Sig ecdsa(Curve c,byte[] h,BigInteger k){BigInteger z=new BigInteger(1,h),r=c.g.multiply(k).normalize().getAffineXCoord().toBigInteger().mod(c.n),s=k.modInverse(c.n).multiply(z.add(r)).mod(c.n);int rec=c.g.multiply(k).normalize().getAffineYCoord().toBigInteger().testBit(0)?1:0;if(s.compareTo(c.n.shiftRight(1))>0){s=c.n.subtract(s);rec^=1;}return new Sig(r,s,rec);}
  static Sig sm2(Curve c,byte[] h,BigInteger k){BigInteger e=new BigInteger(1,h),r=e.add(c.g.multiply(k).normalize().getAffineXCoord().toBigInteger()).mod(c.n),s=BigInteger.ONE.add(BigInteger.ONE).modInverse(c.n).multiply(k.subtract(r)).mod(c.n);int rec=c.g.multiply(k).normalize().getAffineYCoord().toBigInteger().testBit(0)?1:0;return new Sig(r,s,rec);}
  static boolean verifySm2(Curve c,byte[] h,Sig s){BigInteger t=s.r.add(s.s).mod(c.n);ECPoint p=c.g.multiply(s.s).add(c.q.multiply(t)).normalize();return new BigInteger(1,h).add(p.getAffineXCoord().toBigInteger()).mod(c.n).equals(s.r);}
  static byte[] wire(Sig s){return concat(scalar(s.r),scalar(s.s),new byte[]{(byte)s.recid});}
  static byte[] address(byte[] pub){byte[] k=keccak(Arrays.copyOfRange(pub,1,pub.length),256),out=new byte[21];out[0]=0x41;System.arraycopy(k,12,out,1,20);return out;}
  static byte[] tronAddress(byte[] in){byte[] k=keccak(in,256),out=new byte[21];out[0]=0x41;System.arraycopy(k,12,out,1,20);return out;}
  static String base58check(byte[] p,boolean useSm3){byte[] a=useSm3?sm3(p):sha256(p),b=useSm3?sm3(a):sha256(a);return base58(concat(p,Arrays.copyOf(b,4)));}
  static String base58(byte[] in){String alphabet="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";BigInteger n=new BigInteger(1,in);StringBuilder s=new StringBuilder();while(n.signum()!=0){BigInteger[] q=n.divideAndRemainder(BigInteger.valueOf(58));s.append(alphabet.charAt(q[1].intValue()));n=q[0];}for(int i=0;i<in.length&&in[i]==0;i++)s.append('1');return s.reverse().toString();}
  static byte[] sha256(byte[] b){try{return MessageDigest.getInstance("SHA-256").digest(b);}catch(Exception e){throw new RuntimeException(e);}}
  static byte[] sm3(byte[] b){SM3Digest d=new SM3Digest();d.update(b,0,b.length);byte[] o=new byte[d.getDigestSize()];d.doFinal(o,0);return o;}
  static byte[] keccak(byte[] b,int bits){KeccakDigest d=new KeccakDigest(bits);d.update(b,0,b.length);byte[] o=new byte[d.getDigestSize()];d.doFinal(o,0);return o;}
  static byte[] ripemd(byte[] b){RIPEMD160Digest d=new RIPEMD160Digest();d.update(b,0,b.length);byte[] o=new byte[20];d.doFinal(o,0);return o;}
  static byte[] uncompressed(ECPoint p){return p.normalize().getEncoded(false);}
  static byte[] scalar(BigInteger n){byte[] x=n.toByteArray(),o=new byte[32];System.arraycopy(x,Math.max(0,x.length-32),o,Math.max(0,32-x.length),Math.min(32,x.length));return o;}
  static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);} static byte[] sequence(int n,int start){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(start+i);return b;}
  static byte[] i64(long n){byte[] b=new byte[8];for(int i=7;i>=0;i--){b[i]=(byte)n;n>>=8;}return b;}
  static byte[] concat(byte[]...xs){int n=0;for(byte[]x:xs)n+=x.length;byte[]o=new byte[n];int p=0;for(byte[]x:xs){System.arraycopy(x,0,o,p,x.length);p+=x.length;}return o;}
  static byte[] hex(String s){byte[]o=new byte[s.length()/2];for(int i=0;i<o.length;i++)o[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16);return o;}
  static String hx(byte[]b){StringBuilder s=new StringBuilder(b.length*2);for(byte x:b)s.append(String.format("%02x",x&255));return s.toString();}
}
