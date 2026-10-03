#!/usr/bin/env python3
"""Real HTTP + PostgreSQL + isolated RSA OIDC fixture + two CLI profiles.

Requires TEST_DATABASE_URL and compiled debug binaries. Generates only synthetic secrets.
The test identity provider never runs in the product or deployment configuration.
"""
import base64
import concurrent.futures
import hashlib
import http.server
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).resolve().parents[1]

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

class Identity:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.codes = {}
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def send_json(self, data, status=200):
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def do_GET(self):
                target = urllib.parse.urlsplit(self.path)
                if target.path == "/.well-known/openid-configuration":
                    self.send_json({"issuer": owner.issuer, "authorization_endpoint": owner.issuer+"/authorize", "token_endpoint": owner.issuer+"/token", "jwks_uri": owner.issuer+"/jwks", "response_types_supported":["code"], "subject_types_supported":["public"], "id_token_signing_alg_values_supported":["RS256"], "token_endpoint_auth_methods_supported":["none"], "code_challenge_methods_supported":["S256"]})
                elif target.path == "/jwks":
                    n = owner.key.public_key().public_numbers()
                    self.send_json({"keys":[{"kty":"RSA","kid":"fixture","use":"sig","alg":"RS256","n":b64(n.n.to_bytes((n.n.bit_length()+7)//8,"big")),"e":b64(n.e.to_bytes(3,"big"))}]})
                elif target.path == "/authorize":
                    p = dict(urllib.parse.parse_qsl(target.query))
                    if p.get("client_id") != "niceotp-cli" or p.get("redirect_uri") != "http://127.0.0.1:43673/callback" or p.get("code_challenge_method") != "S256":
                        self.send_json({"error":"invalid_request"},400); return
                    code = secrets.token_urlsafe(32)
                    owner.codes[code] = p
                    self.send_response(302)
                    self.send_header("Location", p["redirect_uri"]+"?"+urllib.parse.urlencode({"code":code,"state":p["state"]}))
                    self.end_headers()
                else:
                    self.send_json({},404)
            def do_POST(self):
                p = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
                saved = owner.codes.pop(p.get("code"), None)
                if not saved or b64(hashlib.sha256(p.get("code_verifier", "").encode()).digest()) != saved["code_challenge"] or p.get("redirect_uri") != saved["redirect_uri"] or p.get("client_id") != "niceotp-cli":
                    self.send_json({"error":"invalid_grant"},400); return
                self.send_json({"access_token":secrets.token_urlsafe(32),"token_type":"Bearer","expires_in":300,"id_token":owner.token(saved.get("login_hint","browser-user"), nonce=saved["nonce"])})
        self.http = http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
        self.issuer = f"http://127.0.0.1:{self.http.server_port}"
        self.thread = threading.Thread(target=self.http.serve_forever,daemon=True)
        self.thread.start()
    def token(self, sub, **overrides):
        payload = {"iss":self.issuer,"sub":sub,"aud":"niceotp-cli","iat":int(time.time()),"exp":int(time.time())+300, **overrides}
        message = b64(json.dumps({"alg":"RS256","kid":"fixture"}).encode())+"."+b64(json.dumps(payload).encode())
        return message+"."+b64(self.key.sign(message.encode(),padding.PKCS1v15(),hashes.SHA256()))
    def close(self):
        self.http.shutdown(); self.http.server_close()

def request(base,path,data=None,token=None,method=None):
    headers={"Content-Type":"application/json"}
    if token: headers["Authorization"]="Bearer "+token
    req=urllib.request.Request(base+path,data=json.dumps(data).encode() if data is not None else None,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,timeout=20) as r:
            body=r.read();return r.status,json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        body=e.read()
        try: body=json.loads(body)
        except ValueError: body=body.decode()
        return e.code,body

def private(path,content):
    path.write_text(content);path.chmod(0o600);return path

def main():
    db=os.environ.get("TEST_DATABASE_URL")
    if not db: raise SystemExit("TEST_DATABASE_URL is required (use a dedicated test database)")
    schema="niceotp_e2e_"+uuid.uuid4().hex
    psql=os.environ.get("PSQL","psql")
    def sql(query,url=db):
        return subprocess.check_output([psql,url,"-X","-A","-t","-v","ON_ERROR_STOP=1","-c",query],stderr=subprocess.PIPE,text=True).strip()
    sql(f'CREATE SCHEMA "{schema}"')
    split=urllib.parse.urlsplit(db);params=dict(urllib.parse.parse_qsl(split.query));params["options"]="-csearch_path="+schema
    isolated=urllib.parse.urlunsplit(split._replace(query=urllib.parse.urlencode(params)))
    identity=Identity();server=None
    try:
        with tempfile.TemporaryDirectory(prefix="niceotp-e2e-") as temp:
            temp=Path(temp);password=private(temp/"password","correct horse river amber clock");newpass=private(temp/"newpass","another long independent vault phrase")
            with socket.socket() as sock: sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
            base=f"http://127.0.0.1:{port}";log=temp/"server.log"
            env={**os.environ,"DATABASE_URL":isolated,"OIDC_ISSUER":identity.issuer,"OIDC_CLIENT_ID":"niceotp-cli","LISTEN_ADDR":f"127.0.0.1:{port}"}
            with log.open("w") as out: server=subprocess.Popen([str(ROOT/"target/debug/niceotp-server")],env=env,stdout=out,stderr=out)
            for _ in range(100):
                try:
                    if request(base,"/health")[0]==200:break
                except OSError:pass
                if server.poll() is not None: raise AssertionError("server startup failed: "+log.read_text())
                time.sleep(.1)
            else: raise AssertionError("server startup timeout")
            def cli(profile,*args,input=None,pw=password,ok=True):
                cmd=[str(ROOT/"target/debug/niceotp"),"--data-dir",str(temp/profile),"--server",base,"--password-file",str(pw),"--json",*map(str,args)]
                r=subprocess.run(cmd,input=input,capture_output=True,text=True,timeout=40)
                if ok and r.returncode: raise AssertionError(f"CLI {args[0]} failed: {r.stderr}")
                if not ok: assert r.returncode!=0;return r
                return json.loads(r.stdout)
            def login(profile,user):
                token=private(temp/f"{profile}.token",identity.token(user));return cli(profile,"login","--id-token-file",token)
            def session(profile):return json.loads((temp/profile/"state.json").read_text())["session"]
            def state(profile):return json.loads((temp/profile/"state.json").read_text())
            def report(name):print("PASS",name,flush=True)
            assert request(base,"/health")[1]["version"]=="0.1.0"
            assert request(base,"/v1/vault")[0]==401
            for token in [identity.token("alice",aud="other-client"),identity.token("alice",exp=int(time.time())-120),identity.token("alice")+"x",identity.token("alice",azp="other-client")]:
                assert request(base,"/v1/sessions",{"id_token":token})[0]==401
            report("OIDC signature, issuer/audience/expiry boundary and unauthorized HTTP")
            # Exercise the actual browser flow, callback state, PKCE, nonce and token validation.
            cmd=[str(ROOT/"target/debug/niceotp"),"--data-dir",str(temp/"browser"),"--server",base,"--json","login","--no-browser"]
            proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            lines=queue.Queue()
            threading.Thread(target=lambda:[lines.put(line) for line in proc.stderr],daemon=True).start()
            auth_url=None
            while auth_url is None:
                line=lines.get(timeout=10).strip()
                if line.startswith(identity.issuer):auth_url=line
            with urllib.request.urlopen(auth_url,timeout=10) as response:response.read()
            stdout,_=proc.communicate(timeout=15);assert proc.returncode==0,stdout
            report("CLI browser authorization code + PKCE + nonce login")
            login("a","alice");recovery=temp/"recovery";cli("a","init","--recovery-output",recovery)
            login("b","alice");cli("b","sync")
            # RFC6238 public test secret, with canary names for plaintext leakage tests.
            uri="otpauth://totp/CanaryIssuer:canary-account?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=CanaryIssuer&digits=8"
            created=cli("a","add",input=uri);item=created["id"]
            assert cli("a","code",item,"--at","59")["code"]=="94287082"
            backup=temp/"unsynced.backup";cli("a","backup",backup)
            cli("a","sync");cli("b","sync")
            assert cli("b","list")["items"][0]["id"]==item
            report("independent clients, encrypted pending backup, RFC6238 OTP and sync")
            cli("a","edit",item,"--name","Alice offline edit");cli("b","edit",item,"--name","Bob offline edit")
            cli("a","sync");assert cli("b","sync")["conflicts"]==1
            assert len(cli("b","conflicts")["conflicts"])==1
            cli("b","resolve",item,"--use-version","local");cli("b","sync");cli("a","sync")
            assert cli("a","show",item)["name"]=="Bob offline edit"
            report("offline concurrent edits and explicit conflict resolution")
            # Permanent tombstone must defeat a stale offline edit.
            cli("b","edit",item,"--name","stale resurrection")
            cli("a","delete",item);cli("a","sync");assert len(cli("a","list","--trash")["items"])==1
            cli("a","restore",item);cli("a","sync");cli("a","delete",item);cli("a","sync");cli("a","purge",item,"--yes");cli("a","sync")
            assert cli("b","sync")["conflicts"]==1
            cli("b","resolve",item,"--use-version","local",ok=False)
            cli("b","resolve",item,"--use-version","remote");assert cli("b","list")["items"]==[]
            assert sql("SELECT count(*) FROM information_schema.columns WHERE table_schema='"+schema+"' AND table_name='mutations' AND column_name='request'",isolated)=="0"
            report("trash, restore, permanent tombstone and stale-client resurrection prevention")
            # Keep one live record for recovery/backup tests.
            item2=cli("a","add",input=uri)["id"];cli("a","sync")
            tok=session("a");record=state("a")["items"][item2]
            m={"mutation_id":str(uuid.uuid4()),"id":item2,"base_revision":record["revision"],"payload":record["payload"]}
            req={"cursor":state("a")["cursor"],"mutations":[m]}
            status,first=request(base,"/v1/sync",req,tok);assert status==200
            status,retry=request(base,"/v1/sync",req,tok);assert status==200 and retry["applied"]==first["applied"]
            # Model a committed response lost before the client's atomic state save.
            uncertain=state("a");uncertain["pending"]=[m];uncertain["inflight"]=req
            private(temp/"a"/"state.json",json.dumps(uncertain))
            cli("a","edit",item2,"--name","blocked-until-retry",ok=False)
            assert cli("a","sync")["cursor"]==first["cursor"]
            assert state("a")["pending"]==[] and state("a")["inflight"] is None
            known_cursor=state("a")["cursor"]
            invalid=state("a");invalid["cursor"]=9999999;private(temp/"a"/"state.json",json.dumps(invalid))
            cli("a","sync",ok=False);assert state("a")["inflight"] is None
            invalid=state("a");invalid["cursor"]=known_cursor;private(temp/"a"/"state.json",json.dumps(invalid))
            report("durable uncertain-response retry and definitive-rejection recovery")
            # A changed reused mutation ID rolls back an earlier mutation in the same batch.
            fresh={**m,"id":str(uuid.uuid4()),"mutation_id":str(uuid.uuid4()),"base_revision":0}
            changed={**m,"base_revision":0}
            status,_=request(base,"/v1/sync",{"cursor":0,"mutations":[fresh,changed]},tok);assert status==409
            assert sql(f"SELECT count(*) FROM items WHERE id='{fresh['id']}'",isolated)=="0"
            # Conflicted requests also reserve their mutation IDs.
            conflict={**m,"mutation_id":str(uuid.uuid4()),"base_revision":0}
            assert request(base,"/v1/sync",{"cursor":0,"mutations":[conflict]},tok)[1]["conflicts"]
            conflict["base_revision"]=first["applied"][0]["revision"]
            assert request(base,"/v1/sync",{"cursor":0,"mutations":[conflict]},tok)[0]==409
            assert request(base,"/v1/sync",{"cursor":9999999,"mutations":[]},tok)[0]==400
            report("idempotent retries, conflict ID reservation, atomic rollback and cursor validation")
            # Concurrent base-revision writers: exactly one commits, the other conflicts.
            current=request(base,"/v1/sync",{"cursor":0,"mutations":[]},tok)[1]
            current_item=next(i for i in current["changes"] if i["id"]==item2)
            writes=[{"cursor":current["cursor"],"mutations":[{**m,"mutation_id":str(uuid.uuid4()),"base_revision":current_item["revision"]}]} for _ in range(2)]
            with concurrent.futures.ThreadPoolExecutor() as ex:
                responses=list(ex.map(lambda body:request(base,"/v1/sync",body,tok),writes))
            assert sum(len(body["applied"]) for status,body in responses)==1
            assert sum(len(body["conflicts"]) for status,body in responses)==1
            report("concurrent PostgreSQL transactions serialize revision assignment")
            login("other","bob");assert request(base,"/v1/vault",token=session("other"))[0]==404
            cli("other","init","--recovery-output",temp/"bob-recovery");assert cli("other","sync")["cursor"]==0
            forged={**m,"mutation_id":str(uuid.uuid4()),"base_revision":1}
            assert request(base,"/v1/sync",{"cursor":0,"mutations":[forged]},session("other"))[1]["conflicts"]
            report("account isolation for vaults, item IDs and synchronization")
            cli("a","sync")
            imported=cli("a","import",input="\n".join([uri]*130))
            assert len(imported["items"])==130
            assert cli("a","sync")["applied"]==130
            portable=temp/"portable.backup";cli("a","backup",portable)
            report("more than 128 pending mutations split into bounded batches")
            cli("a","recover","--recovery-file",recovery,"--new-password-file",newpass)
            cli("a","list",pw=password,ok=False);assert cli("a","list",pw=newpass)["items"]
            # Server unavailable: backup must still decrypt and generate correct OTP.
            server.terminate();server.wait(timeout=10);server=None
            cli("restored","restore-backup",portable,"--recovery-file",recovery)
            restored_id=cli("restored","list")["items"][0]["id"];assert restored_id!=item2
            assert cli("restored","code",restored_id,"--at","59")["code"]=="94287082"
            damaged=temp/"damaged.backup";content=json.loads(portable.read_text())
            # Alter the complete envelope without knowing a key.
            content["header"]["vault_id"]=str(uuid.uuid4());private(damaged,json.dumps(content))
            cli("tampered","restore-backup",damaged,ok=False)
            report("recovery-key password reset and offline authenticated portable restore")
            with log.open("a") as out:server=subprocess.Popen([str(ROOT/"target/debug/niceotp-server")],env=env,stdout=out,stderr=out)
            for _ in range(100):
                try:
                    if request(base,"/health")[0]==200:break
                except OSError:pass
                time.sleep(.1)
            login("restored","carol");assert cli("restored","sync")["applied"]==131;assert len(cli("restored","list")["items"])==131
            old=session("restored");cli("restored","logout");assert request(base,"/v1/vault",token=old)[0]==401
            report("restore into another account and revoke session")
            # Secret canaries must be absent from persistent server and client state.
            dump="\n".join(sql(f"SELECT row_to_json(t)::text FROM {table} t",isolated) for table in ["accounts","sessions","vaults","items","mutations"])
            for canary in ["CanaryIssuer","canary-account","GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",password.read_text(),recovery.read_text()]:
                assert canary not in dump and canary not in log.read_text()
                for path in temp.glob("*/state.json"):assert canary not in path.read_text()
            report("database, server logs and local state contain no plaintext canaries")
            print("All v0.1 end-to-end checks passed.")
    finally:
        if server is not None:server.terminate();server.wait(timeout=10)
        identity.close();sql(f'DROP SCHEMA "{schema}" CASCADE')

if __name__=="__main__":main()
