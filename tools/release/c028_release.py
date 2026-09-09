#!/usr/bin/env python3
"""C028 deterministic, offline release assembler.

The production path builds in two unrelated temporary roots and refuses drift. Fixture
mode exercises the same archive, OCI, SBOM, provenance, and manifest pipeline without Cargo.
No path below java-tron is ever opened; Sapling parameters are operator inputs only.
"""
from __future__ import annotations
import argparse, base64, gzip, hashlib, io, json, os, re, shutil, stat, struct, subprocess, tarfile, tempfile
from pathlib import Path

PLATFORM="P-LINUX-X64"; TARGET="x86_64-unknown-linux-gnu"
BINS=("tron-fullnode","tron-solidity","tron-toolkit","tron-release-verify")
SAPLING_NAMES={"sapling-spend.params","sapling-output.params","sapling-spend.bin","sapling-output.bin"}
AUTHORITATIVE_TRUST_NAMES={"release-trust-store.json","snapshot-trust-store.json","root.json","trusted-root.json"}
SAPLING_POLICY=(
 {"kind":"sapling-spend","size":48013340,"blake2b_512":"25fd9a0d1c1be0526c14662947ae95b758fe9f3d7fb7f55e9b4437830dcc6215a7ce3ea465914b157715b7a4d681389ea4aa84438190e185d5e4c93574d3a19a","included":False,"redistribution_rights":"not_asserted"},
 {"kind":"sapling-output","size":3647804,"blake2b_512":"a1cb23b93256adce5bce2cb09cefbc96a1d16572675ceb691e9a3626ec15b5b546926ff1c536cfe3a9df07d796b32fdfc3e5d99d65567257bf286cd2858d71a6","included":False,"redistribution_rights":"not_asserted"},
)
BUSYBOX_POLICY=Path(__file__).resolve().parents[2]/"docs/oracles/c028-busybox-material.v1.json"

def canonical(v): return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sha(data): return hashlib.sha256(data).hexdigest()
def file_sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
 return h.hexdigest()

def canonical_source_revision(value:str)->str:
 if not isinstance(value,str) or len(value)!=40 or any(c not in "0123456789abcdef" for c in value): raise RuntimeError("source_revision must be a canonical lowercase 40-hex Git SHA-1")
 return value

def git_output(repo:Path,*args:str)->str:
 completed=subprocess.run(["git","-C",str(repo),*args],text=True,capture_output=True,check=False)
 if completed.returncode!=0: raise RuntimeError("release tag is not an exact repository tag")
 return completed.stdout.strip()

def resolve_release_tag(repo:Path,release_tag:str)->tuple[str,str]:
 if not release_tag or release_tag.startswith("refs/") or any(c.isspace() for c in release_tag): raise RuntimeError("release tag name is not canonical")
 ref=f"refs/tags/{release_tag}"
 git_output(repo,"check-ref-format",ref)
 tag_commit=canonical_source_revision(git_output(repo,"rev-parse","--verify",ref+"^{commit}"))
 checkout_commit=canonical_source_revision(git_output(repo,"rev-parse","--verify","HEAD^{commit}"))
 return tag_commit,checkout_commit

def _busybox_policy(fixture:bool)->dict:
 path=Path(os.environ["TRON_BUSYBOX_POLICY"]) if fixture and os.environ.get("TRON_BUSYBOX_POLICY") else BUSYBOX_POLICY
 value=json.loads(path.read_text())
 if value.get("schema")!="c028-busybox-material-v1": raise RuntimeError("invalid BusyBox material policy")
 return value

def _validate_static_elf(data:bytes,policy:dict):
 if len(data)<64 or data[:4]!=b"\x7fELF": raise RuntimeError("TRON_BUSYBOX must be an ELF executable")
 if data[4]!=2 or data[5]!=1: raise RuntimeError("TRON_BUSYBOX must be little-endian ELF64")
 e_type,e_machine=struct.unpack_from("<HH",data,16)
 if e_type not in (2,3) or e_machine!=62: raise RuntimeError("TRON_BUSYBOX must be an x86-64 executable")
 e_phoff=struct.unpack_from("<Q",data,32)[0]; e_phentsize,e_phnum=struct.unpack_from("<HH",data,54)
 if e_phentsize<56 or e_phoff+e_phentsize*e_phnum>len(data): raise RuntimeError("TRON_BUSYBOX has invalid ELF program headers")
 types={struct.unpack_from("<I",data,e_phoff+i*e_phentsize)[0] for i in range(e_phnum)}
 if 2 in types or 3 in types: raise RuntimeError("TRON_BUSYBOX must be statically linked")
 if policy["material"]["version_marker"].encode() not in data: raise RuntimeError("TRON_BUSYBOX version marker mismatch")

def busybox_material(fixture:bool=False):
 path_value=os.environ.get("TRON_BUSYBOX","")
 if not path_value: raise RuntimeError("TRON_BUSYBOX is required; PATH discovery is forbidden")
 path=Path(path_value)
 if not path.is_absolute(): raise RuntimeError("TRON_BUSYBOX must be an absolute path")
 if not path.is_file() or path.is_symlink() or not os.access(path,os.X_OK): raise RuntimeError("TRON_BUSYBOX must be a regular executable file")
 policy=_busybox_policy(fixture); material=policy["material"]; actual=file_sha(path)
 if actual!=material["sha256"]: raise RuntimeError("TRON_BUSYBOX SHA-256 mismatch")
 if not fixture: _validate_static_elf(path.read_bytes(),policy)
 return {"name":"busybox","path":str(path),"sha256":actual,"version":material["version"],"license":material["license"],"provenance":material["provenance"]}
def safe_source(root:Path,p:Path):
 r=root.resolve(); q=p.resolve()
 if q==r/"java-tron" or (r/"java-tron") in q.parents: raise RuntimeError("java-tron is forbidden release input")
 return q

def scan_forbidden_sapling(root:Path):
 for p in sorted(root.rglob("*")):
  if p.is_symlink() or p.name.lower() in SAPLING_NAMES: raise RuntimeError(f"forbidden release member: {p}")
  if p.is_file() and p.name.lower() in AUTHORITATIVE_TRUST_NAMES: raise RuntimeError(f"authoritative trust root is not a release subject: {p}")
  if p.is_file() and p.stat().st_size in {x["size"] for x in SAPLING_POLICY}: raise RuntimeError(f"possible Sapling parameter bytes: {p}")

def normalized_tar(source:Path,epoch:int)->bytes:
 scan_forbidden_sapling(source); raw=io.BytesIO()
 with tarfile.open(fileobj=raw,mode="w",format=tarfile.USTAR_FORMAT) as tf:
  for p in sorted(source.rglob("*"),key=lambda x:x.relative_to(source).as_posix()):
   rel=p.relative_to(source).as_posix(); info=tarfile.TarInfo(rel+("/" if p.is_dir() else "")); volume_root=rel in {"opt/tron","etc/tron","var/lib/tron"}; info.uid=info.gid=65532 if volume_root else 0; info.uname=info.gname=""; info.mtime=epoch
   if p.is_dir(): info.type=tarfile.DIRTYPE; info.mode=0o755; tf.addfile(info)
   elif p.is_file():
    info.size=p.stat().st_size; info.mode=0o755 if p.stat().st_mode & 0o111 else 0o644
    with p.open("rb") as f: tf.addfile(info,f)
   else: raise RuntimeError(f"nonregular release member: {p}")
 return raw.getvalue()

def deterministic_gzip(raw:bytes)->bytes:
 compressed=io.BytesIO()
 with gzip.GzipFile(filename="",mode="wb",fileobj=compressed,mtime=0,compresslevel=9) as gz: gz.write(raw)
 return compressed.getvalue()

def normalize_archive(source:Path,out:Path,epoch:int):
 out.parent.mkdir(parents=True,exist_ok=True); out.write_bytes(deterministic_gzip(normalized_tar(source,epoch))); return out

def run(cmd,cwd,env): subprocess.run(cmd,cwd=cwd,env=env,check=True)
def build_one(repo:Path,work:Path,identity:dict,fixture:bool):
 stage=work/"stage"; (stage/"bin").mkdir(parents=True); (stage/"config").mkdir()
 if fixture:
  for name in BINS: (stage/"bin"/name).write_bytes(("#!/bin/sh\nprintf '%s\\n' "+name+"\n").encode()); (stage/"bin"/name).chmod(0o755)
 else:
  checkout=work/"checkout"; shutil.copytree(repo,checkout,ignore=shutil.ignore_patterns("java-tron","target",".git"),symlinks=False)
  cargo=Path(os.environ.get("CARGO_HOME",Path.home()/".cargo")).resolve(); target=work/"target"; env=os.environ.copy(); env.update({"CARGO_HOME":str(cargo),"CARGO_TARGET_DIR":str(target),"CARGO_INCREMENTAL":"0","CARGO_NET_OFFLINE":"true","LANG":"C.UTF-8","LC_ALL":"C.UTF-8","TZ":"UTC","SOURCE_DATE_EPOCH":str(identity["source_date_epoch"]),"TRON_RELEASE_ID":identity["release_id"],"TRON_RELEASE_VERSION":identity["version"],"TRON_RELEASE_SEQUENCE":str(identity["release_sequence"]),"TRON_RELEASE_CHANNEL":identity["channel"],"TRON_SOURCE_REVISION":identity["source_revision"],"TRON_PLATFORM_ID":PLATFORM,"TRON_BUILD_TARGET":TARGET,"RUSTFLAGS":f"--remap-path-prefix={checkout}=/usr/src/tron --remap-path-prefix={cargo}=/usr/local/cargo --remap-path-prefix={target}=/usr/src/target -C target-feature=+crt-static -C link-arg=-Wl,--build-id=none"})
  run(["cargo","build","--release","--locked","--offline","--target",TARGET,"--package","tron-node","--package","tron-toolkit","--bins"],checkout/"rust-tron",env)
  for name in BINS: shutil.copy2(target/TARGET/"release"/name,stage/"bin"/name)
 for p in sorted((repo/"rust-tron"/"packaging"/"config").glob("*")) if (repo/"rust-tron"/"packaging"/"config").exists() else []:
  if p.is_file():
   destination=stage/"config"/p.name
   if p.name.endswith(".deployment.json"):
    value=json.loads(p.read_text()); value["expected_release"]={"release_id":identity["release_id"],"minimum_release_sequence":identity["release_sequence"]}; destination.write_bytes(canonical(value))
   else: shutil.copyfile(p,destination)
 entrypoint=repo/"rust-tron"/"packaging"/"container"/"entrypoint.sh"
 if entrypoint.is_file(): shutil.copyfile(entrypoint,stage/"entrypoint.sh"); (stage/"entrypoint.sh").chmod(0o755)
 (stage/"BUILD-IDENTITY.json").write_bytes(canonical(identity)); scan_forbidden_sapling(stage); return stage

def build_oci(stage:Path,out:Path,epoch:int,busybox:dict):
 rootfs=out.parent/(out.name+"-rootfs"); (rootfs/"usr/local/bin").mkdir(parents=True); (rootfs/"etc/tron").mkdir(parents=True); (rootfs/"var/lib/tron").mkdir(parents=True); (rootfs/"opt/tron").mkdir(parents=True); (rootfs/"bin").mkdir(parents=True)
 shutil.copyfile(stage/"entrypoint.sh",rootfs/"usr/local/bin/entrypoint.sh"); (rootfs/"usr/local/bin/entrypoint.sh").chmod(0o755)
 shutil.copyfile(stage/"bin/tron-release-verify",rootfs/"usr/local/bin/tron-release-verify"); (rootfs/"usr/local/bin/tron-release-verify").chmod(0o755)
 source=Path(busybox["path"])
 if file_sha(source)!=busybox["sha256"]: raise RuntimeError("TRON_BUSYBOX changed after verification")
 shutil.copyfile(source,rootfs/"bin/busybox"); shutil.copyfile(source,rootfs/"bin/sh"); (rootfs/"bin/busybox").chmod(0o755); (rootfs/"bin/sh").chmod(0o755)
 raw=normalized_tar(rootfs,epoch); compressed=deterministic_gzip(raw); blobs=out/"blobs/sha256"; blobs.mkdir(parents=True,exist_ok=True); layer_digest=sha(compressed); diff_id=sha(raw); (blobs/layer_digest).write_bytes(compressed)
 cfg=canonical({"architecture":"amd64","os":"linux","config":{"User":"65532:65532","Entrypoint":["/usr/local/bin/entrypoint.sh"],"Cmd":["fullnode"],"Env":["PATH=/usr/local/bin:/usr/bin:/bin"],"Volumes":{"/opt/tron":{},"/etc/tron":{},"/var/lib/tron":{}}},"rootfs":{"type":"layers","diff_ids":["sha256:"+diff_id]},"created":None}); config_digest=sha(cfg); (blobs/config_digest).write_bytes(cfg)
 manifest=canonical({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:"+config_digest,"size":len(cfg)},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:"+layer_digest,"size":len(compressed)}]}); manifest_digest=sha(manifest); (blobs/manifest_digest).write_bytes(manifest)
 (out/"oci-layout").write_bytes(canonical({"imageLayoutVersion":"1.0.0"})); (out/"index.json").write_bytes(canonical({"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:"+manifest_digest,"size":len(manifest),"annotations":{"org.opencontainers.image.ref.name":"tron"}}]})); shutil.rmtree(rootfs)
 validate_oci_layout(out); return manifest_digest

def validate_oci_layout(layout:Path):
 def descriptor_blob(descriptor:dict,kind:str)->bytes:
  digest=descriptor.get("digest","");
  if not isinstance(digest,str) or not digest.startswith("sha256:") or len(digest)!=71: raise RuntimeError(f"invalid OCI {kind} digest")
  path=layout/"blobs/sha256"/digest[7:]
  if not path.is_file(): raise RuntimeError(f"missing OCI {kind} blob")
  data=path.read_bytes()
  if len(data)!=descriptor.get("size") or sha(data)!=digest[7:]: raise RuntimeError(f"OCI {kind} size or digest mismatch")
  return data
 if json.loads((layout/"oci-layout").read_text())!={"imageLayoutVersion":"1.0.0"}: raise RuntimeError("invalid OCI layout marker")
 index=json.loads((layout/"index.json").read_text()); manifests=index.get("manifests",[])
 if index.get("schemaVersion")!=2 or len(manifests)!=1: raise RuntimeError("OCI index must select exactly one manifest")
 manifest=json.loads(descriptor_blob(manifests[0],"manifest")); layers=manifest.get("layers",[])
 if manifest.get("schemaVersion")!=2 or len(layers)!=1: raise RuntimeError("OCI manifest must contain exactly one layer")
 config=json.loads(descriptor_blob(manifest["config"],"config")); compressed=descriptor_blob(layers[0],"layer")
 try: raw=gzip.decompress(compressed)
 except Exception as error: raise RuntimeError("OCI layer is not valid gzip") from error
 diff_ids=config.get("rootfs",{}).get("diff_ids",[])
 if diff_ids!=["sha256:"+sha(raw)]: raise RuntimeError("OCI config diff_id does not match uncompressed layer")
 entrypoint=config.get("config",{}).get("Entrypoint")
 if config.get("config",{}).get("Volumes")!={"/opt/tron":{},"/etc/tron":{},"/var/lib/tron":{}}: raise RuntimeError("OCI writable mountpoint declaration drift")
 if entrypoint!=["/usr/local/bin/entrypoint.sh"]: raise RuntimeError("OCI entrypoint declaration drift")
 with tarfile.open(fileobj=io.BytesIO(raw),mode="r:") as tf:
  names={member.name.rstrip("/"):member for member in tf.getmembers()}
  required=("usr/local/bin/entrypoint.sh","usr/local/bin/tron-release-verify","bin/sh")
  if any(name=="opt/tron/current" or name.startswith("opt/tron/current/") or name=="etc/tron/current" or name.startswith("etc/tron/current/") for name in names): raise RuntimeError("OCI rootfs must not preload a mutable current installation")
  for name in required:
   member=names.get(name)
   if member is None or not member.isfile() or not member.mode&0o111: raise RuntimeError(f"OCI rootfs lacks executable /{name}")
 return {"manifest":manifests[0]["digest"],"diff_id":diff_ids[0],"entrypoint":entrypoint[0]}

def generate_sbom(subjects,identity,busybox):
 return {"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":identity["release_id"],"documentNamespace":"https://tron.invalid/spdx/"+identity["release_id"],"creationInfo":{"created":"1970-01-01T00:00:00Z","creators":["Tool: c028_release.py"]},"files":[{"SPDXID":"SPDXRef-File-"+sha(name.encode())[:16],"fileName":name,"checksums":[{"algorithm":"SHA256","checksumValue":digest}]} for name,digest in subjects],"packages":[{"SPDXID":"SPDXRef-Package-BusyBox","name":"BusyBox","versionInfo":busybox["version"],"licenseConcluded":busybox["license"],"downloadLocation":"NOASSERTION","checksums":[{"algorithm":"SHA256","checksumValue":busybox["sha256"]}],"externalRefs":[{"referenceCategory":"OTHER","referenceType":"tron-provenance","referenceLocator":busybox["provenance"]}]}],"annotations":[{"annotationType":"OTHER","annotator":"Tool: c028_release.py","annotationDate":"1970-01-01T00:00:00Z","comment":"Sapling spend/output are operator-provided policy inputs and are not shipped components."}]}
def generate_provenance(subjects,identity,busybox): return {"_type":"https://in-toto.io/Statement/v1","subject":subjects,"predicateType":"https://slsa.dev/provenance/v1","predicate":{"materials":[{"uri":"git+urn:tron:source","digest":{"gitCommit":canonical_source_revision(identity["source_revision"])}},{"uri":busybox["provenance"],"digest":{"sha256":busybox["sha256"]}}],"buildDefinition":{"buildType":"https://tron.invalid/c028/offline-cargo-v1","externalParameters":{**identity,"busybox":{"sha256":busybox["sha256"],"version":busybox["version"],"license":busybox["license"],"provenance":busybox["provenance"]}},"internalParameters":{},"resolvedDependencies":[]},"runDetails":{"builder":{"id":"c028-release-builder"},"metadata":{"invocationId":identity["release_id"]}}}}
def assemble_dsse(payload_type,payload): return {"payloadType":payload_type,"payload":base64.b64encode(payload).decode(),"signatures":[]}
def sign_ed25519(payload_type:str,payload:bytes,key:Path):
 pae=b"DSSEv1 "+str(len(payload_type)).encode()+b" "+payload_type.encode()+b" "+str(len(payload)).encode()+b" "+payload
 public=subprocess.check_output(["openssl","pkey","-in",str(key),"-pubout","-outform","DER"])
 if len(public)<32: raise RuntimeError("invalid Ed25519 public key")
 raw_public=public[-32:]; key_id=sha(b"ed25519-v1\0"+raw_public)
 with tempfile.NamedTemporaryFile(prefix="c028-dsse-") as message:
  message.write(pae); message.flush()
  signature=subprocess.check_output(["openssl","pkeyutl","-sign","-rawin","-inkey",str(key),"-in",message.name])
 return {"key_id":key_id,"algorithm":"ed25519-v1","signature":base64.b64encode(signature).decode()}

def authenticate_candidate(out:Path,keys:list[Path]):
 if len(keys)<2: raise RuntimeError("authenticated production candidate requires at least two independently provisioned signing keys")
 provenance_path=out/"bundle/provenance.dsse.json"; penv=json.loads(provenance_path.read_text()); ptype=penv.get("payloadType",penv.get("payload_type")); payload=base64.b64decode(penv["payload"],validate=True)
 signatures=[sign_ed25519(ptype,payload,key) for key in keys]
 if len({item["key_id"] for item in signatures})<2: raise RuntimeError("production candidate signing keys are not independent")
 penv={"payload_type":ptype,"payload":base64.b64encode(payload).decode(),"signatures":signatures}; provenance_path.write_bytes(canonical(penv))
 manifest_path=out/"release-manifest.json"; manifest=json.loads(manifest_path.read_text()); artifact=next((item for item in manifest["artifacts"] if item["path"]=="provenance.dsse.json"),None)
 if artifact is None: raise RuntimeError("release manifest lacks provenance subject")
 artifact["sha256"]=file_sha(provenance_path); artifact["size"]=provenance_path.stat().st_size; raw=canonical(manifest); manifest_path.write_bytes(raw)
 payload_type="application/vnd.tron.release-manifest.v1+json"; signatures=[sign_ed25519(payload_type,raw,key) for key in keys]; envelope={"payload_type":payload_type,"payload":base64.b64encode(raw).decode(),"signatures":signatures}; (out/"release-manifest.dsse.json").write_bytes(canonical(envelope))
 inventory={"schema":"tron-candidate-inventory-v1","release_id":manifest["release_id"],"channel":manifest["channel"],"release_sequence":manifest["release_sequence"],"source_revision":canonical_source_revision(manifest["source_revision"]),"manifest_sha256":sha(raw)}; (out/"candidate-inventory.json").write_bytes(canonical(inventory)); scan_forbidden_sapling(out)
 return inventory
WORKFLOW_METADATA_FIELDS=("schema","repository","candidate_run_id","signing_run_id","signing_workflow","signing_workflow_sha","unsigned_artifact_name","unsigned_artifact_sha256","signed_artifact_name","signed_archive_name","candidate_sha256","release_id","channel","source_revision")
def validate_workflow_metadata(metadata:object,artifact_name:str,candidate_sha256:str,release_id:str,channel:str,source_revision:str,expected_repository:str,expected_candidate_run_id:int,expected_signing_run_id:int,expected_signing_workflow_sha:str)->dict:
 if not isinstance(metadata,dict) or set(metadata)!=set(WORKFLOW_METADATA_FIELDS): raise RuntimeError("workflow metadata fields do not match c028-workflow-metadata-v1")
 expected={"schema":"c028-workflow-metadata-v1","repository":expected_repository,"candidate_run_id":expected_candidate_run_id,"signing_run_id":expected_signing_run_id,"signing_workflow":".github/workflows/c028-release-sign.yml","signing_workflow_sha":expected_signing_workflow_sha,"signed_artifact_name":artifact_name,"signed_archive_name":"c028-candidate.tar.gz","candidate_sha256":candidate_sha256,"release_id":release_id,"channel":channel,"source_revision":source_revision}
 for field,value in expected.items():
  if metadata[field]!=value: raise RuntimeError(f"workflow metadata {field} does not match authenticated identity")
 if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",metadata["repository"]): raise RuntimeError("workflow metadata repository is not canonical")
 if type(metadata["candidate_run_id"]) is not int or metadata["candidate_run_id"]<1 or type(metadata["signing_run_id"]) is not int or metadata["signing_run_id"]<1: raise RuntimeError("workflow metadata run ID is not a positive integer")
 unsigned_sha=metadata["unsigned_artifact_sha256"]
 if not isinstance(unsigned_sha,str) or not re.fullmatch(r"[0-9a-f]{64}",unsigned_sha): raise RuntimeError("workflow metadata unsigned artifact digest is not canonical")
 if metadata["unsigned_artifact_name"]!=f"c028-unsigned-{release_id}-{unsigned_sha}": raise RuntimeError("workflow metadata unsigned artifact name does not match its digest and release")
 canonical_source_revision(metadata["signing_workflow_sha"]); canonical_source_revision(metadata["source_revision"])
 return metadata
def validate_publish_identity(inventory_path:Path,workflow_metadata_path:Path,artifact_name:str,candidate_sha256:str,expected_release_id:str,expected_channel:str,release_tag:str,repo:Path,expected_repository:str,expected_candidate_run_id:int,expected_signing_run_id:int,expected_signing_workflow_sha:str):
 if len(candidate_sha256)!=64 or any(c not in "0123456789abcdef" for c in candidate_sha256): raise RuntimeError("candidate SHA-256 is not canonical")
 expected_artifact=f"c028-candidate-{expected_release_id}-{candidate_sha256}"
 if artifact_name!=expected_artifact: raise RuntimeError("workflow artifact identity does not match independently approved digest and release")
 inventory=json.loads(inventory_path.read_text()); release_id=inventory.get("release_id"); channel=inventory.get("channel"); source_revision=canonical_source_revision(inventory.get("source_revision"))
 metadata=json.loads(workflow_metadata_path.read_text(),object_pairs_hook=dict)
 validate_workflow_metadata(metadata,artifact_name,candidate_sha256,release_id,channel,source_revision,expected_repository,expected_candidate_run_id,expected_signing_run_id,expected_signing_workflow_sha)
 if release_id!=expected_release_id: raise RuntimeError("authenticated release ID does not match workflow input")
 if channel!=expected_channel: raise RuntimeError("authenticated channel does not match workflow input")
 if release_tag!=release_id: raise RuntimeError("GitHub release tag does not match authenticated release ID")
 tag_commit,checkout_commit=resolve_release_tag(repo,release_tag)
 if tag_commit!=source_revision: raise RuntimeError("release tag commit does not match authenticated source_revision")
 if checkout_commit!=source_revision: raise RuntimeError("publish checkout does not match authenticated source_revision")
 return {"release_id":release_id,"channel":channel,"source_revision":source_revision,"tag_commit":tag_commit,"checkout_commit":checkout_commit,"artifact":artifact_name,"sha256":candidate_sha256}

def generate_snapshot_manifest(identity): return {"schema":"tron-snapshot-manifest-v1","release_id":identity["release_id"],"operator_input_policy":list(SAPLING_POLICY),"snapshots":[]}

def assemble(repo,out,identity,fixture):
 canonical_source_revision(identity["source_revision"])
 busybox=busybox_material(fixture)
 out.mkdir(parents=True,exist_ok=False); builds=[]
 with tempfile.TemporaryDirectory(prefix="c028-a-") as a, tempfile.TemporaryDirectory(prefix="c028-b-") as b:
  for root in (Path(a),Path(b)):
   stage=build_one(repo,root,identity,fixture); native=normalize_archive(stage,root/"native.tar.gz",identity["source_date_epoch"]); config=normalize_archive(stage/"config",root/"config.tar.gz",identity["source_date_epoch"]); oci=root/"oci"; md=build_oci(stage,oci,identity["source_date_epoch"],busybox); builds.append((stage,native,config,oci,md))
  fingerprints=[]
  for stage,native,config,oci,md in builds: fingerprints.append({**{n:file_sha(stage/"bin"/n) for n in BINS},"native":file_sha(native),"config":file_sha(config),"oci":md,"oci_index":file_sha(oci/"index.json")})
  if fingerprints[0]!=fingerprints[1]: raise RuntimeError("double build is not byte-identical: "+json.dumps(fingerprints,sort_keys=True))
  stage,native,config,oci,md=builds[0]; bundle=out/"bundle"; bundle.mkdir()
  for name in BINS:
   destination=bundle/"bin"/name; destination.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(stage/"bin"/name,destination); destination.chmod(0o755)
  shutil.copyfile(native,bundle/"tron-binaries.tar.gz"); shutil.copyfile(config,bundle/"tron-config.tar.gz"); shutil.copyfile(oci/"index.json",bundle/"index.json"); shutil.copyfile(oci/"oci-layout",bundle/"oci-layout")
  logical={**{n:(f"bin/{n}","binary") for n in BINS},"native-archive":("tron-binaries.tar.gz","archive"),"config-archive":("tron-config.tar.gz","archive"),"oci-image":("index.json","oci-manifest"),"oci-layout":("oci-layout","oci-blob")}
  for config_file in sorted((stage/"config").iterdir()):
   if config_file.is_file():
    relative=f"config/{config_file.name}"; (bundle/"config").mkdir(parents=True,exist_ok=True); shutil.copyfile(config_file,bundle/relative); logical[f"config-{config_file.name}"]=(relative,"configuration")
  for blob in sorted((oci/"blobs"/"sha256").iterdir()):
   rel="blobs/sha256/"+blob.name; (bundle/"blobs"/"sha256").mkdir(parents=True,exist_ok=True); shutil.copyfile(blob,bundle/rel); logical["oci-blob-"+blob.name[:16]]=(rel,"oci-blob")
  validate_oci_layout(bundle)
  preliminary=[(rel,file_sha(bundle/rel)) for rel,_ in logical.values()]; (bundle/"sbom.spdx.json").write_bytes(canonical(generate_sbom(preliminary,identity,busybox))); logical["sbom"]=("sbom.spdx.json","sbom")
  subjects=[{"name":rel,"digest":{"sha256":file_sha(bundle/rel)}} for rel,_ in logical.values()]; (bundle/"provenance.dsse.json").write_bytes(canonical(assemble_dsse("application/vnd.in-toto+json",canonical(generate_provenance(subjects,identity,busybox))))); logical["provenance"]=("provenance.dsse.json","provenance")
  artifacts=[]
  for name,(rel,kind) in logical.items(): p=bundle/rel; artifacts.append({"logical_name":name,"path":rel,"kind":kind,"platform_id":PLATFORM,"sha256":file_sha(p),"size":p.stat().st_size,"mode":493 if p.stat().st_mode&0o111 else 420,"media_type":"application/octet-stream","release_id":identity["release_id"]})
  manifest={"schema":"tron-release-manifest-v1",**identity,"production_materials":[{key:busybox[key] for key in ("name","sha256","version","license","provenance")}],"install_prefix":"/opt/tron","current_target":"/opt/tron/current","config_root":"/etc/tron","receipt_path":"/var/lib/tron/install-receipt.json","platforms":[{"platform_id":PLATFORM,"os":"linux","architecture":"x86_64","target":TARGET,"backend":"rustlog","backend_format":"rustlog-v1","features":["rustlog-v1"],"enabled":True}],"artifacts":artifacts,"operator_inputs":list(SAPLING_POLICY),"compatibility":{"minimum_sequence":identity["release_sequence"],"native_resources":[]}}
  raw=canonical(manifest); (out/"release-manifest.json").write_bytes(raw); (out/"release-manifest.dsse.json").write_bytes(canonical(assemble_dsse("application/vnd.tron.release-manifest.v1+json",raw))); (out/"snapshot-manifest.json").write_bytes(canonical(generate_snapshot_manifest(identity))); scan_forbidden_sapling(out)
  return {"schema":"c028-release-result-v2","platform_id":PLATFORM,"release_id":identity["release_id"],"double_build":fingerprints,"release_manifest_sha256":sha(raw),"oci_digest":"sha256:"+md,"publication":{"schema":"tron-publication-inventory-v1","candidate_objects":["release-manifest.dsse.json","bundle"],"optional_objects":["release-trust-update.dsse.json"],"staged_by":"tron-release-verify stage-publish"}}

def main():
 ap=argparse.ArgumentParser(); ap.add_argument("command",choices=("build","check","authenticate","validate-publish-identity","self-check")); ap.add_argument("--out",type=Path); ap.add_argument("--repo",type=Path,default=Path(__file__).resolve().parents[2]); ap.add_argument("--fixture",action="store_true"); ap.add_argument("--release-id",default="c028-fixture"); ap.add_argument("--version",default="0.0.0-c028"); ap.add_argument("--release-sequence",type=int,default=1); ap.add_argument("--channel",default="fixture"); ap.add_argument("--source-revision",default="0"*40); ap.add_argument("--source-date-epoch",type=int,default=0); ap.add_argument("--signing-key",type=Path,action="append",default=[]); ap.add_argument("--inventory",type=Path); ap.add_argument("--workflow-metadata",type=Path); ap.add_argument("--artifact-name"); ap.add_argument("--candidate-sha256"); ap.add_argument("--expected-release-id"); ap.add_argument("--expected-channel"); ap.add_argument("--release-tag"); ap.add_argument("--expected-repository"); ap.add_argument("--expected-candidate-run-id",type=int); ap.add_argument("--expected-signing-run-id",type=int); ap.add_argument("--expected-signing-workflow-sha"); a=ap.parse_args()
 identity={"release_id":a.release_id,"version":a.version,"release_sequence":a.release_sequence,"channel":a.channel,"source_revision":a.source_revision,"source_date_epoch":a.source_date_epoch}
 if a.command=="self-check":
  with tempfile.TemporaryDirectory() as t:
   fixture_busybox=Path(t)/"busybox"; fixture_busybox.write_bytes(b"#!/bin/sh\necho 'BusyBox v1.36.1 fixture'\n"); fixture_busybox.chmod(0o755)
   fixture_policy=Path(t)/"busybox-policy.json"; fixture_policy.write_bytes(canonical({"schema":"c028-busybox-material-v1","source":{"url":"fixture","sha256":"0"*64,"member":"busybox"},"material":{"sha256":file_sha(fixture_busybox),"version":"1.36.1","version_marker":"BusyBox v1.36.1","license":"GPL-2.0-only","provenance":"fixture:c028/busybox"},"elf":{"class":64,"endianness":"little","machine":"x86_64","static":True}}))
   os.environ.update({"TRON_BUSYBOX":str(fixture_busybox.resolve()),"TRON_BUSYBOX_POLICY":str(fixture_policy)})
   accepted=dict(os.environ)
   try:
    del os.environ["TRON_BUSYBOX"]
    try: busybox_material(True)
    except RuntimeError as error:
     if "required" not in str(error): raise
    else: raise RuntimeError("missing TRON_BUSYBOX was accepted")
   finally:
    os.environ.clear(); os.environ.update(accepted)
   policy=json.loads(fixture_policy.read_text()); policy["material"]["sha256"]="0"*64; fixture_policy.write_bytes(canonical(policy))
   try: busybox_material(True)
   except RuntimeError as error:
    if "mismatch" not in str(error): raise
   else: raise RuntimeError("mismatched TRON_BUSYBOX was accepted")
   policy["material"]["sha256"]=file_sha(fixture_busybox); fixture_policy.write_bytes(canonical(policy))
   x=Path(t)/"a"; y=Path(t)/"b"; r1=assemble(a.repo,x,identity,True); r2=assemble(a.repo,y,identity,True)
   if {p.relative_to(x):file_sha(p) for p in x.rglob("*") if p.is_file()}!={p.relative_to(y):file_sha(p) for p in y.rglob("*") if p.is_file()}: raise RuntimeError("fixture outputs differ")
   malicious=Path(t)/"malicious"; malicious.mkdir(); (malicious/"release-trust-store.json").write_text("{}")
   try: scan_forbidden_sapling(malicious)
   except RuntimeError as error:
    if "authoritative trust root" not in str(error): raise
   else: raise RuntimeError("candidate-controlled authoritative trust root was accepted")
   digest="a"*64; identity_repo=Path(t)/"identity-repo"; identity_repo.mkdir()
   subprocess.run(["git","init","-q",str(identity_repo)],check=True); subprocess.run(["git","-C",str(identity_repo),"config","user.name","C028"],check=True); subprocess.run(["git","-C",str(identity_repo),"config","user.email","c028@example.invalid"],check=True)
   (identity_repo/"source").write_text("authenticated\n"); subprocess.run(["git","-C",str(identity_repo),"add","source"],check=True); subprocess.run(["git","-C",str(identity_repo),"commit","-q","-m","source"],check=True)
   revision=git_output(identity_repo,"rev-parse","HEAD"); subprocess.run(["git","-C",str(identity_repo),"tag","release-1"],check=True)
   inventory=Path(t)/"publication-inventory.json"; inventory.write_bytes(canonical({"release_id":"release-1","channel":"stable","source_revision":revision})); artifact=f"c028-candidate-release-1-{digest}"; workflow_metadata=Path(t)/"workflow-metadata.json"
   repository="owner/repository"; signing_run_id=1002; workflow_sha="1"*40
   workflow_metadata.write_bytes(canonical({"schema":"c028-workflow-metadata-v1","repository":repository,"candidate_run_id":1001,"signing_run_id":signing_run_id,"signing_workflow":".github/workflows/c028-release-sign.yml","signing_workflow_sha":workflow_sha,"unsigned_artifact_name":f"c028-unsigned-release-1-{'b'*64}","unsigned_artifact_sha256":"b"*64,"signed_artifact_name":artifact,"signed_archive_name":"c028-candidate.tar.gz","candidate_sha256":digest,"release_id":"release-1","channel":"stable","source_revision":revision})); validate_publish_identity(inventory,workflow_metadata,artifact,digest,"release-1","stable","release-1",identity_repo,repository,1001,signing_run_id,workflow_sha)
   rejected=[]
   for label,values in (("wrong-artifact",(inventory,workflow_metadata,"other",digest,"release-1","stable","release-1",identity_repo,repository,1001,signing_run_id,workflow_sha)),("wrong-release",(inventory,workflow_metadata,artifact,digest,"release-2","stable","release-2",identity_repo,repository,1001,signing_run_id,workflow_sha))):
    try: validate_publish_identity(*values)
    except RuntimeError: rejected.append(label)
    else: raise RuntimeError(f"{label} publish identity was accepted")
   inventory.write_bytes(canonical({"release_id":"substituted","channel":"stable","source_revision":revision}))
   try: validate_publish_identity(inventory,workflow_metadata,artifact,digest,"release-1","stable","release-1",identity_repo,repository,1001,signing_run_id,workflow_sha)
   except RuntimeError: rejected.append("substitution")
   else: raise RuntimeError("authenticated inventory substitution was accepted")
   if rejected!=["wrong-artifact","wrong-release","substitution"]: raise RuntimeError("publish rejection self-check incomplete")
   layout=x/"bundle"
   index=json.loads((layout/"index.json").read_text()); manifest_descriptor=index["manifests"][0]; manifest=json.loads((layout/"blobs/sha256"/manifest_descriptor["digest"][7:]).read_text()); config_descriptor=manifest["config"]
   config_path=layout/"blobs/sha256"/config_descriptor["digest"][7:]; original=config_path.read_bytes(); mutated=json.loads(original); mutated["rootfs"]["diff_ids"]=["sha256:"+"0"*64]; changed=canonical(mutated); changed_path=layout/"blobs/sha256"/sha(changed); changed_path.write_bytes(changed); config_descriptor["digest"]="sha256:"+sha(changed); config_descriptor["size"]=len(changed)
   manifest_bytes=canonical(manifest); new_manifest=layout/"blobs/sha256"/sha(manifest_bytes); new_manifest.write_bytes(manifest_bytes); manifest_descriptor["digest"]="sha256:"+sha(manifest_bytes); manifest_descriptor["size"]=len(manifest_bytes); (layout/"index.json").write_bytes(canonical(index))
   try: validate_oci_layout(layout)
   except RuntimeError as error:
    if "diff_id" not in str(error): raise
   else: raise RuntimeError("malformed OCI diff_id mutation was accepted")
   mutated=json.loads(original); mutated["config"]["Entrypoint"]=["/wrong/entrypoint.sh"]; changed=canonical(mutated); changed_path=layout/"blobs/sha256"/sha(changed); changed_path.write_bytes(changed); config_descriptor["digest"]="sha256:"+sha(changed); config_descriptor["size"]=len(changed); manifest_bytes=canonical(manifest); new_manifest=layout/"blobs/sha256"/sha(manifest_bytes); new_manifest.write_bytes(manifest_bytes); manifest_descriptor["digest"]="sha256:"+sha(manifest_bytes); manifest_descriptor["size"]=len(manifest_bytes); (layout/"index.json").write_bytes(canonical(index))
   try: validate_oci_layout(layout)
   except RuntimeError as error:
    if "entrypoint" not in str(error): raise
   else: raise RuntimeError("malformed OCI entrypoint path mutation was accepted")
   with tarfile.open(fileobj=io.BytesIO(gzip.decompress((layout/"blobs/sha256"/manifest["layers"][0]["digest"][7:]).read_bytes())),mode="r:") as tf:
    if "usr/local/bin/entrypoint.sh" not in {m.name.rstrip("/") for m in tf.getmembers()}: raise RuntimeError("OCI entrypoint path proof failed")
   print(json.dumps(r1,sort_keys=True)); return
 if a.command=="authenticate":
  if not a.out or not a.out.is_dir(): raise RuntimeError("authenticate requires an existing --out")
  print(json.dumps(authenticate_candidate(a.out,a.signing_key),sort_keys=True)); return
 if a.command=="validate-publish-identity":
  required=(a.inventory,a.workflow_metadata,a.artifact_name,a.candidate_sha256,a.expected_release_id,a.expected_channel,a.release_tag,a.repo,a.expected_repository,a.expected_candidate_run_id,a.expected_signing_run_id,a.expected_signing_workflow_sha)
  if any(value is None for value in required): raise RuntimeError("validate-publish-identity requires inventory, workflow metadata, artifact, digest, expected identity/channel, tag, repository, candidate/signing runs, and signing workflow SHA")
  print(json.dumps(validate_publish_identity(*required),sort_keys=True)); return
 if not a.out: ap.error("--out is required")
 if a.command=="build": print(json.dumps(assemble(a.repo,a.out,identity,a.fixture),sort_keys=True))
 else:
  if not a.out.is_dir(): raise RuntimeError("--check requires an existing --out")
  with tempfile.TemporaryDirectory() as t:
   q=Path(t)/"reproduced"; assemble(a.repo,q,identity,a.fixture); left={p.relative_to(a.out):file_sha(p) for p in a.out.rglob("*") if p.is_file()}; right={p.relative_to(q):file_sha(p) for p in q.rglob("*") if p.is_file()}
   if left!=right: raise RuntimeError("release output drift")
   print(json.dumps({"status":"identical","files":len(left)},sort_keys=True))
if __name__=="__main__": main()
