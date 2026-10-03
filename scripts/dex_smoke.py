#!/usr/bin/env python3
"""Smoke the documented local Dex login with real authorization-code/PKCE.

Only the public loopback demo identity is used. Start deploy/compose.local.yml dex
first. TEST_DATABASE_URL must point to a disposable PostgreSQL database.
"""
import html.parser
import http.cookiejar
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[1]
class Forms(html.parser.HTMLParser):
    def __init__(self):super().__init__();self.forms=[];self.current=None
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=="form":self.current={"action":a.get("action",""),"fields":{}};self.forms.append(self.current)
        if tag in ("input","button") and self.current is not None and a.get("name"):
            self.current["fields"][a["name"]]=a.get("value","")
    def handle_endtag(self,tag):
        if tag=="form":self.current=None

def main():
    db=os.environ["TEST_DATABASE_URL"];schema="niceotp_dex_"+uuid.uuid4().hex
    psql=os.environ.get("PSQL","psql")
    def sql(q):subprocess.run([psql,db,"-X","-q","-v","ON_ERROR_STOP=1","-c",q],check=True,capture_output=True)
    sql(f'CREATE SCHEMA "{schema}"')
    split=urllib.parse.urlsplit(db);params=dict(urllib.parse.parse_qsl(split.query));params["options"]="-csearch_path="+schema
    isolated=urllib.parse.urlunsplit(split._replace(query=urllib.parse.urlencode(params)))
    server=None;cli=None
    try:
        with tempfile.TemporaryDirectory(prefix="niceotp-dex-") as directory:
            d=Path(directory)
            with socket.socket() as s:s.bind(("127.0.0.1",0));port=s.getsockname()[1]
            env={**os.environ,"DATABASE_URL":isolated,"OIDC_ISSUER":"http://127.0.0.1:5556/dex","OIDC_CLIENT_ID":"niceotp-cli","LISTEN_ADDR":f"127.0.0.1:{port}"}
            with (d/"server.log").open("w") as out:server=subprocess.Popen([str(ROOT/"target/debug/niceotp-server")],env=env,stdout=out,stderr=out)
            base=f"http://127.0.0.1:{port}"
            for _ in range(100):
                try:
                    with urllib.request.urlopen(base+"/health",timeout=2):break
                except OSError:
                    if server.poll() is not None:raise AssertionError("Server failed to start against Dex")
                    time.sleep(.1)
            cli=subprocess.Popen([str(ROOT/"target/debug/niceotp"),"--data-dir",str(d/"profile"),"--server",base,"--json","login","--no-browser"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            lines=queue.Queue();threading.Thread(target=lambda:[lines.put(line) for line in cli.stderr],daemon=True).start()
            auth_url=None
            while auth_url is None:
                line=lines.get(timeout=20).strip()
                if line.startswith("http://127.0.0.1:5556/"):auth_url=line
            opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
            response=opener.open(auth_url,timeout=10)
            for _ in range(6):
                page=response.read().decode();url=response.url
                if url.startswith("http://127.0.0.1:43673/callback"):break
                parser=Forms();parser.feed(page)
                if not parser.forms:raise AssertionError("Unexpected Dex login page without form")
                form=parser.forms[0];fields=form["fields"]
                if "login" in fields:fields["login"]="demo@example.test"
                if "password" in fields:fields["password"]="local-development-only"
                if "approval" in fields:fields["approval"]="approve"
                action=urllib.parse.urljoin(url,form["action"])
                assert action.startswith("http://127.0.0.1:5556/")
                response=opener.open(action,data=urllib.parse.urlencode(fields).encode(),timeout=10)
            else:raise AssertionError("Dex login did not reach callback")
            output,_=cli.communicate(timeout=20)
            assert cli.returncode==0 and json.loads(output)["logged_in"],"CLI rejected Dex login"
            print("PASS real Dex browser login, PKCE, ID token verification and session creation")
    finally:
        if cli is not None and cli.poll() is None:cli.terminate();cli.wait(timeout=5)
        if server is not None:server.terminate();server.wait(timeout=10)
        sql(f'DROP SCHEMA "{schema}" CASCADE')

if __name__=="__main__":main()
