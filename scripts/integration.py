#!/usr/bin/env python3
"""Destructive only to ll-test-* resources on an explicitly isolated CI engine."""
import json,os,pathlib,subprocess,tempfile,time,shutil
ROOT=pathlib.Path(__file__).resolve().parents[1]
os.chdir(ROOT);(ROOT/'qa').mkdir(exist_ok=True)
PREFIX='ll-test-';N=PREFIX+'net';IMAGE='locklane-gateway:0.1.0';WORK='locklane-workspace:0.1.0'
proof={'checks':[],'complete':False,'scope':'Linux Docker engine; synthetic WireGuard and Shadowsocks servers; no Claude login or inference'}
def cmd(*args,check=True,input=None):
 p=subprocess.run(args,input=input,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if check and p.returncode:raise RuntimeError('Command failed: '+' '.join(args[:4])+'\n'+p.stderr[-2000:])
 return p

def d(*args,**kw):return cmd('docker',*args,**kw)
def record(name):proof['checks'].append({'name':name,'passed':True});print('PASS',name,flush=True)
def cleanup():
 for c in ['canary','gateway','server','ss','stream']:
  d('rm','-f',PREFIX+c,check=False)
 d('network','rm',N,check=False)

def wait_state(path, predicate, timeout=70):
 end=time.time()+timeout
 while time.time()<end:
  try:
   s=json.loads(path.read_text())
   if predicate(s):return s
  except (OSError,ValueError):pass
  time.sleep(1)
 logs=d('logs',PREFIX+'gateway',check=False)
 detail={}
 for label,args in [('state',['cat','/state/status.json']),('routes',['ip','route','show','table','all']),('rules',['ip','rule']),('filter',['iptables','-nvL','OUTPUT']),('probe',['setpriv','--reuid=1001','--regid=1001','--clear-groups','curl','-4','-v','--max-time','6','https://api.ipify.org']),('bridge',['curl','-4','--socks5-hostname','127.0.0.2:1080','-v','--max-time','6','https://api.ipify.org'])]:
  result=d('exec',PREFIX+'gateway',*args,check=False);detail[label]=result.stdout[-3500:]+result.stderr[-3500:]
 raise RuntimeError('Gateway not ready: '+logs.stderr[-2500:]+'\n'+logs.stdout[-1000:]+'\n'+json.dumps(detail))
def canary(root):
 d('rm','-f',PREFIX+'canary',check=False)
 d('run','-d','--name',PREFIX+'canary','--network','container:'+PREFIX+'gateway','--user','1000:1000','--cap-drop=ALL','--security-opt','no-new-privileges:true','--read-only','--tmpfs','/tmp:rw,nosuid,size=32m','-v',str(root/'status')+':/state:ro','-v',str(root/'resolv.conf')+':/etc/resolv.conf:ro',WORK)
def app(code,ok=True):
 p=d('exec',PREFIX+'canary','python3','-c',code,check=False)
 if (p.returncode==0)!=ok:raise RuntimeError('Canary outcome mismatch: '+p.stdout+p.stderr)
 return p.stdout
DENIED="import socket; s=socket.socket(); s.settimeout(2);\ntry: s.connect(('1.1.1.1',443))\nexcept OSError: pass\nelse: raise AssertionError('DIRECT ACCESS')"
def gateway(root,provider,expected):
 d('rm','-f',PREFIX+'gateway',check=False)
 (root/'status'/'status.json').unlink(missing_ok=True)
 args=['run','-d','--name',PREFIX+'gateway','--network',N,'--ip','172.28.0.3','--cap-drop=ALL','--cap-add=NET_ADMIN','--cap-add=NET_RAW','--cap-add=SETUID','--cap-add=SETGID','--cap-add=DAC_OVERRIDE','--device','/dev/net/tun','--security-opt','no-new-privileges:true','-e','LL_PROVIDER='+provider,'-e','LL_EXPECTED_IP='+expected,'-e','LL_ENDPOINT=172.28.0.2','-e','LL_ADDRESSES=10.77.0.2/32','-v',str(root/'status')+':/state','-v',str(root/'resolv.conf')+':/etc/resolv.conf:ro']
 if provider=='wireguard':args+=['-v',str(root/'client.conf')+':/secrets/wg.conf:ro']
 else:args+=['-v',str(root/'proxy.json')+':/secrets/proxy.json:ro']
 d(*args,IMAGE)
if os.environ.get('CI')!='true' and os.environ.get('LOCKLANE_ISOLATED_TEST_ENGINE')!='yes':raise RuntimeError('Refusing to use a non-test Docker engine')
try:
 cleanup()
 for dockerfile,tag in [('Dockerfile.gateway',IMAGE),('Dockerfile.workspace',WORK)]:
  print('Building',tag,flush=True);p=subprocess.run(['docker','build','-f','runtime/'+dockerfile,'-t',tag,'runtime']);assert p.returncode==0
 record('gateway and Claude workspace images built')
 env=os.environ.copy();fixtures=ROOT/'qa/core-fixtures';env['LOCKLANE_FIXTURES_DIR']=str(fixtures)
 subprocess.run(['go','test','-run','TestExportCoreFixtures','.'],env=env,check=True)
 for f in sorted(fixtures.glob('*.json')):
  d('run','--rm','-v',str(f)+':/secrets/proxy.json:ro','--entrypoint','locklane-gate',IMAGE,'check-profile')
 record('generated multi-protocol profiles accepted by real Xray and sing-box binaries')
 d('network','create','--subnet','172.28.0.0/24',N)
 with tempfile.TemporaryDirectory(prefix='ll-test-') as td:
  root=pathlib.Path(td);(root/'status').mkdir(mode=0o777);os.chmod(root/'status',0o777);(root/'resolv.conf').write_text('nameserver 1.1.1.1\n')
  def key():return d('run','--rm','--entrypoint','wg',IMAGE,'genkey').stdout.strip()
  def pub(k):return d('run','--rm','-i','--entrypoint','wg',IMAGE,'pubkey',input=k+'\n').stdout.strip()
  server,client=key(),key();spub,cpub=pub(server),pub(client)
  (root/'server.key').write_text(server+'\n');(root/'client.conf').write_text('[Interface]\nPrivateKey = '+client+'\n[Peer]\nPublicKey = '+spub+'\nAllowedIPs = 0.0.0.0/0\nEndpoint = 172.28.0.2:51820\nPersistentKeepalive = 25\n')
  os.chmod(root/'client.conf',0o600)
  script='wireguard-go -f wg0 >/tmp/wg.log 2>&1 &\nfor x in $(seq 1 50); do ip link show wg0 >/dev/null 2>&1 && break; sleep .1; done\nwg set wg0 private-key /test/server.key listen-port 51820 peer '+cpub+' allowed-ips 10.77.0.2/32\nip address add 10.77.0.1/24 dev wg0\nip link set wg0 up\niptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE\niptables -A FORWARD -i wg0 -j ACCEPT\niptables -A FORWARD -o wg0 -j ACCEPT\nsleep infinity'
  d('run','-d','--name',PREFIX+'server','--network',N,'--ip','172.28.0.2','--cap-add=NET_ADMIN','--device','/dev/net/tun','--sysctl','net.ipv4.ip_forward=1','-v',str(root)+':/test:ro','--entrypoint','bash',IMAGE,'-ec',script)
  expected=d('run','--rm','--entrypoint','curl',IMAGE,'-4','-fsS','--retry','3','https://api.ipify.org').stdout.strip()
  gateway(root,'wireguard',expected);wait_state(root/'status/status.json',lambda s:s.get('ready'));canary(root)
  actual=app("import subprocess; print(subprocess.check_output(['curl','-4','-fsS','--max-time','8','https://api.ipify.org'],text=True).strip())").strip();assert actual==expected;record('WireGuard positive route and exact exit IP')
  fresh=json.loads(d('exec',PREFIX+'gateway','locklane-gate','inspect-ip').stdout);assert fresh['ip']==expected and fresh['match'];record('manual IP check uses the same unprivileged tunnel probe')
  p=d('exec',PREFIX+'canary','locklane-run','--version');assert '2.1.326' in p.stdout;record('real Claude Code binary starts inside a verified namespace without account login')
  app("import os; s=open('/proc/self/status').read(); assert os.getuid()==1000 and 'NoNewPrivs:\\t1' in s and 'CapEff:\\t0000000000000000' in s; assert not os.path.exists('/var/run/docker.sock')")
  record('workspace is unprivileged and has no Docker socket')
  for target in ['169.254.169.254','192.168.1.1','127.0.0.11','127.0.0.2']:
   app(DENIED.replace('1.1.1.1',target))
  record('metadata, LAN, Docker DNS and gateway proxy listener denied')
  app("import subprocess; assert subprocess.run(['curl','-6','-fsS','--max-time','2','https://api64.ipify.org'],capture_output=True).returncode!=0")
  app("import subprocess; assert subprocess.run(['curl','-4','--interface','eth0','-fsS','--max-time','2','https://api.ipify.org'],capture_output=True).returncode!=0")
  record('IPv6 and physical-interface bypass denied')
  d('exec',PREFIX+'server','ip','address','add','203.0.113.50/32','dev','lo')
  stream_code="import socket,time; s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',9000));s.listen();c,a=s.accept();\nwhile True: c.sendall(b'TICK\\n');time.sleep(.05)"
  d('run','-d','--name',PREFIX+'stream','--network','container:'+PREFIX+'server','--entrypoint','python3',WORK,'-u','-c',stream_code)
  time.sleep(1)
  active="import socket,sys,time; s=socket.create_connection(('203.0.113.50',9000),5);assert s.recv(10);print('READY',flush=True);sys.stdin.readline();s.settimeout(.1);\ntry:\n while s.recv(8192): pass\nexcept OSError: pass\ns.settimeout(2);\ntry: data=s.recv(10)\nexcept OSError: data=b''\nassert not data;print('STREAM_CLOSED',flush=True)"
  proc=subprocess.Popen(['docker','exec','-i',PREFIX+'canary','python3','-u','-c',active],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  assert proc.stdout.readline().strip()=='READY'
  d('exec',PREFIX+'gateway','ip','link','del','wg0');d('exec',PREFIX+'gateway','ip','route','replace','default','via','172.28.0.1','dev','eth0')
  out,err=proc.communicate('\n',timeout=8);assert proc.returncode==0 and 'STREAM_CLOSED' in out,(out,err);record('an existing TCP stream cannot continue after the VPN interface is removed')
  app(DENIED);wait_state(root/'status/status.json',lambda s:not s.get('ready'));d('exec',PREFIX+'canary','locklane-run','--version',check=False)
  p=d('exec',PREFIX+'canary','locklane-run','--version',check=False);assert p.returncode!=0
  record('tunnel deletion with restored direct route remains closed; launcher refuses')
  d('rm','-f',PREFIX+'canary');gateway(root,'wireguard','1.1.1.1');wait_state(root/'status/status.json',lambda s:'does not match' in s.get('reason',''));canary(root);app(DENIED);record('wrong pinned IP blocks app despite a working VPN')
  d('rm','-f',PREFIX+'canary');gateway(root,'wireguard','');s=wait_state(root/'status/status.json',lambda s:s.get('reason')=='Pin this observed exit IP');assert s['ip']==expected and not s['ready'];canary(root);app(DENIED);record('IP discovery does not grant app egress')
  d('rm','-f',PREFIX+'canary',PREFIX+'gateway')
  password='synthetic-ss-test-password'
  ss={'log':{'loglevel':'warning'},'inbounds':[{'listen':'0.0.0.0','port':8388,'protocol':'shadowsocks','settings':{'method':'chacha20-ietf-poly1305','password':password,'network':'tcp,udp'}}],'outbounds':[{'protocol':'freedom'}]}
  (root/'ss.json').write_text(json.dumps(ss));d('run','-d','--name',PREFIX+'ss','--network',N,'--ip','172.28.0.4','-v',str(root/'ss.json')+':/ss.json:ro','--entrypoint','xray',IMAGE,'run','-config','/ss.json')
  proxy={'core':'xray','server_ip':'172.28.0.4','outbound':{'tag':'proxy','protocol':'shadowsocks','settings':{'servers':[{'address':'172.28.0.4','port':8388,'method':'chacha20-ietf-poly1305','password':password}]},'streamSettings':{'network':'raw','sockopt':{'interface':'eth0'}}}}
  (root/'proxy.json').write_text(json.dumps(proxy));gateway(root,'proxy',expected);wait_state(root/'status/status.json',lambda s:s.get('ready'));canary(root)
  actual=app("import subprocess; print(subprocess.check_output(['curl','-4','-fsS','--max-time','8','https://api.ipify.org'],text=True).strip())").strip();assert actual==expected;record('sing-box TUN plus Xray Shadowsocks positive route and exact IP')
  app(DENIED.replace('1.1.1.1','127.0.0.2'));record('workspace cannot bypass IP gate via internal SOCKS bridge')
  d('exec',PREFIX+'gateway','ip','link','del','ll0');d('exec',PREFIX+'gateway','ip','route','replace','default','via','172.28.0.1','dev','eth0');app(DENIED);record('proxy TUN deletion remains closed')
  proof['complete']=True
finally:
 cleanup();(ROOT/'qa/network-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2))
