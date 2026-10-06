import hashlib, hmac, ipaddress, json, math, os, re, secrets, socket, subprocess, time, unicodedata
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
import httpx, psycopg, pymysql
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

app=FastAPI(title="LVL - NetAtlas",version="0.2.0")
app.mount("/static",StaticFiles(directory="/opt/netatlas/static"),name="static")
NETBOX_URL=os.getenv("NETBOX_URL","").rstrip("/"); NETBOX_TOKEN=os.getenv("NETBOX_TOKEN","")
OSRM_URL=os.getenv("OSRM_URL","https://router.project-osrm.org").rstrip("/")
ZHOST=os.getenv("ZABBIX_DB_HOST",""); ZPORT=int(os.getenv("ZABBIX_DB_PORT","3306")); ZNAME=os.getenv("ZABBIX_DB_NAME","zabbix"); ZUSER=os.getenv("ZABBIX_DB_USER",""); ZPASS=os.getenv("ZABBIX_DB_PASSWORD",""); ZREAD_TIMEOUT=int(os.getenv("ZABBIX_DB_READ_TIMEOUT","60"))
DB_DSN=os.getenv("NETATLAS_DB_DSN","postgresql://netatlas_app@127.0.0.1/netatlas")
LICENSE_SERVER_URL=os.getenv("LICENSE_SERVER_URL","https://lvllicencas.lvltech.com.br").rstrip('/')
LICENSE_PRODUCT=os.getenv("LICENSE_PRODUCT","LVL - NetAtlas")
LICENSE_KEY=os.getenv("NETATLAS_LICENSE_KEY","").strip()
OLT_MANAGER_URL=os.getenv("OLT_MANAGER_URL","http://172.16.210.51:6000").rstrip('/')
OLT_MANAGER_TOKEN=os.getenv("OLT_MANAGER_TOKEN","")
GITHUB_REPOSITORY=os.getenv('NETATLAS_GITHUB_REPOSITORY','rafaelm1907-wq/lvl-netatlas').strip('/')
INSTALL_DIR='/opt/netatlas'

class NodeIn(BaseModel):
 name:str=Field(min_length=1,max_length=200); kind:str=Field(default="cto",pattern="^(cto|host|junction|cloud)$"); latitude:float=Field(ge=-90,le=90); longitude:float=Field(ge=-180,le=180); site_id:int|None=None; splitter_type:str|None=Field(default=None,pattern="^1x(2|4|8|16|32)$"); splitter_name:str|None=Field(default=None,max_length=120)
class PopIn(BaseModel):
 name:str=Field(min_length=1,max_length=200); latitude:float=Field(ge=-90,le=90); longitude:float=Field(ge=-180,le=180)
class PositionIn(BaseModel):
 latitude:float=Field(ge=-90,le=90); longitude:float=Field(ge=-180,le=180)
class Endpoint(BaseModel):
 kind:str=Field(pattern="^(device|node)$"); id:int; name:str; zabbix_hostid:int|None=None; interface_itemid:int|None=None; interface_name:str|None=None; interface_description:str|None=None; splitter_type:str|None=Field(default=None,pattern="^1x(2|4|8|16|32)$")
class LinkIn(BaseModel):
 name:str=Field(min_length=1,max_length=200); source:Endpoint; target:Endpoint; parent_link_id:int|None=None; coordinates:list[list[float]]=Field(min_length=2); route_mode:str=Field(default='manual',pattern='^(manual|straight|suggested)$'); trunk_group:str|None=Field(default=None,max_length=80); is_trunk:bool=False
class LinkBatchIn(BaseModel): links:list[LinkIn]=Field(min_length=1,max_length=32)
class LagMemberIn(BaseModel): source:Endpoint; target:Endpoint|None=None
class LinkLagsIn(BaseModel): members:list[LagMemberIn]=Field(min_length=1,max_length=32)
class LinkGeometry(BaseModel): coordinates:list[list[float]]=Field(min_length=2)
class LinkNameIn(BaseModel): name:str=Field(min_length=1,max_length=200)
class LinkInterfaceIn(BaseModel):
 interface_itemid:int|None=None; interface_name:str=Field(min_length=1,max_length=300); interface_description:str|None=None
class LinkCtoIn(BaseModel):
 name:str=Field(min_length=1,max_length=200); latitude:float=Field(ge=-90,le=90); longitude:float=Field(ge=-180,le=180); splitter_type:str|None=Field(default=None,pattern="^1x(2|4|8|16|32)$"); input_side:str|None=Field(default=None,pattern="^(source|target)$")
class ZabbixHostImportIn(BaseModel):
 hostid:int; site_id:int
class ZabbixHostsImportIn(BaseModel):
 hostids:list[int]=Field(min_length=1,max_length=100); site_id:int
class ValidateProvisionalHostIn(BaseModel): hostid:int
class RouteSuggestionIn(BaseModel):
 source:list[float]=Field(min_length=2,max_length=2); target:list[float]=Field(min_length=2,max_length=2)
class LoginIn(BaseModel): username:str=Field(min_length=1,max_length=80); password:str=Field(min_length=1,max_length=200)
class IssueIn(BaseModel):
 target_kind:str=Field(pattern='^(device|node|link)$'); target_id:int; target_name:str=Field(min_length=1,max_length=200); severity:str=Field(pattern='^(medium|severe|disaster)$'); description:str=Field(min_length=1,max_length=1000); latitude:float|None=Field(default=None,ge=-90,le=90); longitude:float|None=Field(default=None,ge=-180,le=180)
class UserIn(BaseModel):
 username:str=Field(min_length=3,max_length=80); display_name:str=Field(min_length=1,max_length=120); password:str=Field(min_length=8,max_length=200); role:str=Field(pattern='^(superadmin|admin|technician)$')
class LicenseActivateIn(BaseModel):
 license_key:str=Field(min_length=8,max_length=300)
class BgpFeatureIn(BaseModel):
 enabled:bool; zabbix_hostid:int
class OperatorInterfaceIn(BaseModel):
 zabbix_hostid:int; interface_itemid:int; interface_name:str=Field(min_length=1,max_length=300); interface_description:str|None=None; provider_name:str=Field(min_length=1,max_length=120); address_family:str=Field(pattern='^(ipv4|ipv6|dual)$'); subtitle:str|None=Field(default=None,max_length=160)
class CtoSplitterIn(BaseModel):
 name:str=Field(min_length=1,max_length=120); splitter_type:str=Field(pattern="^1x(2|4|8|16|32)$"); olt_id:str=Field(min_length=1,max_length=120); sfp:str=Field(pattern=r"^\d+/\d+/\d+$"); link_id:int|None=None
class CtoOutputIn(BaseModel):
 name:str=Field(min_length=1,max_length=120); output_kind:str=Field(pattern="^(customers|continuation|unused)$")
class CtoClientSelectionIn(BaseModel):
 ont_numbers:list[int]=Field(default_factory=list,max_length=512)
class AlertAckIn(BaseModel):
 alert_key:str=Field(min_length=3,max_length=200)
class AlertAckSyncIn(BaseModel):
 active_keys:list[str]=Field(default_factory=list,max_length=1000)

def pg(): return psycopg.connect(DB_DSN,row_factory=psycopg.rows.dict_row)
def zconn():
 last_error=None
 for attempt in range(4):
  try:
   connection=pymysql.connect(host=ZHOST,port=ZPORT,user=ZUSER,password=ZPASS,database=ZNAME,connect_timeout=4,read_timeout=min(10,ZREAD_TIMEOUT),write_timeout=10,cursorclass=pymysql.cursors.DictCursor)
   connection._read_timeout=ZREAD_TIMEOUT
   if connection._sock:connection._sock.settimeout(ZREAD_TIMEOUT)
   return connection
  except pymysql.err.OperationalError as error:
   last_error=error
   if not error.args or error.args[0] not in (2003,2013) or attempt==3:raise
   time.sleep(.25*(attempt+1))
 raise last_error
def password_hash(password,salt=None):
 salt=salt or secrets.token_bytes(16);digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,310000);return salt.hex(),digest.hex()
def verify_password(password,salt,digest):return hmac.compare_digest(password_hash(password,bytes.fromhex(salt))[1],digest)
def license_device_id():
 try:
  with open('/etc/machine-id',encoding='utf-8') as f: machine=f.read().strip()
 except OSError: machine=socket.gethostname()
 return hashlib.sha256(f'LVL-NetAtlas:{machine}:{socket.gethostname()}'.encode()).hexdigest()
def mask_license_key(key):
 return f'{key[:5]}••••{key[-4:]}' if len(key)>9 else '••••'
def check_license(key):
 try:
  with httpx.Client(timeout=12) as client:
   response=client.post(f'{LICENSE_SERVER_URL}/api/v1/validate',json={'license_key':key,'product':LICENSE_PRODUCT,'device_id':license_device_id()})
   data=response.json()
   return data,response.status_code
 except (httpx.HTTPError,ValueError) as error:
  return {'valid':False,'reason':'license_server_unreachable','message':str(error)},503
def license_active_host(action,host_id,host_name):
 """Conta somente equipamentos ativos associados ao Zabbix; nunca CTOs/passivos."""
 with pg() as c,c.cursor() as q:q.execute('SELECT license_key FROM license_config WHERE id=1 AND valid'); row=q.fetchone()
 if not row:return None
 try:
  with httpx.Client(timeout=12) as client:
   response=client.post(f'{LICENSE_SERVER_URL}/api/v1/hosts/{action}',json={'license_key':row['license_key'],'product':LICENSE_PRODUCT,'host_id':str(host_id),'host_name':host_name})
   data=response.json()
 except (httpx.HTTPError,ValueError) as error:raise HTTPException(503,f'Não foi possível atualizar a contagem da licença: {error}')
 if not data.get('valid'):raise HTTPException(response.status_code if response.status_code<500 else 503,data.get('reason') or 'A licença não permite adicionar este host')
 return data
def current_user(request:Request):
 token=request.cookies.get('netatlas_session')
 if not token:raise HTTPException(401,'Faça login para acessar o NetAtlas')
 th=hashlib.sha256(token.encode()).hexdigest()
 with pg() as c,c.cursor() as q:
  q.execute("""SELECT u.id,u.username,u.display_name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=%s AND s.expires_at>now() AND u.active""",(th,));u=q.fetchone()
 if not u:raise HTTPException(401,'Sessão expirada')
 return dict(u)
def roles(*allowed):
 def check(u=Depends(current_user)):
  if u['role'] not in allowed:raise HTTPException(403,'Seu perfil não permite esta ação')
  return u
 return check
viewer=roles('superadmin','admin','technician');operator=roles('superadmin','admin');superadmin=roles('superadmin')

@app.on_event("startup")
def startup():
 with pg() as c,c.cursor() as q:
  # Os workers do bootstrap em paralelo; o lock evita DDL concorrente e deadlocks.
  q.execute('SELECT pg_advisory_xact_lock(748215005)')
  q.execute("""CREATE TABLE IF NOT EXISTS nodes(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL DEFAULT 'cto',geom geometry(Point,4326) NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now());CREATE TABLE IF NOT EXISTS element_positions(element_kind TEXT NOT NULL,element_id BIGINT NOT NULL,geom geometry(Point,4326) NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),PRIMARY KEY(element_kind,element_id));CREATE TABLE IF NOT EXISTS links(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,source_kind TEXT NOT NULL,source_id BIGINT NOT NULL,source_name TEXT NOT NULL,source_zabbix_hostid BIGINT,source_interface_itemid BIGINT,source_interface_name TEXT,source_interface_description TEXT,target_kind TEXT NOT NULL,target_id BIGINT NOT NULL,target_name TEXT NOT NULL,target_zabbix_hostid BIGINT,target_interface_itemid BIGINT,target_interface_name TEXT,target_interface_description TEXT,parent_link_id BIGINT REFERENCES links(id) ON DELETE SET NULL,geom geometry(LineString,4326) NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now());CREATE INDEX IF NOT EXISTS links_geom_gix ON links USING GIST(geom);CREATE INDEX IF NOT EXISTS nodes_geom_gix ON nodes USING GIST(geom);
CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,username TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN('superadmin','admin','technician')),password_salt TEXT NOT NULL,password_hash TEXT NOT NULL,active BOOLEAN NOT NULL DEFAULT true,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS issues(id BIGSERIAL PRIMARY KEY,target_kind TEXT NOT NULL CHECK(target_kind IN('device','node','link')),target_id BIGINT NOT NULL,target_name TEXT NOT NULL,severity TEXT NOT NULL CHECK(severity IN('medium','severe','disaster')),description TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','validated','resolved')),reported_by BIGINT NOT NULL REFERENCES users(id),validated_by BIGINT REFERENCES users(id),created_at TIMESTAMPTZ NOT NULL DEFAULT now(),validated_at TIMESTAMPTZ,resolved_at TIMESTAMPTZ);CREATE INDEX IF NOT EXISTS issues_target_idx ON issues(target_kind,target_id,status);
CREATE TABLE IF NOT EXISTS audit_log(id BIGSERIAL PRIMARY KEY,actor_id BIGINT REFERENCES users(id) ON DELETE SET NULL,actor_username TEXT NOT NULL,actor_role TEXT NOT NULL,action TEXT NOT NULL,target_kind TEXT NOT NULL,target_id BIGINT,target_name TEXT,details JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ NOT NULL DEFAULT now());CREATE INDEX IF NOT EXISTS audit_log_created_idx ON audit_log(created_at DESC)""")
  q.execute("CREATE TABLE IF NOT EXISTS license_config(id SMALLINT PRIMARY KEY CHECK(id=1),license_key TEXT,valid BOOLEAN NOT NULL DEFAULT false,last_checked_at TIMESTAMPTZ,last_response JSONB NOT NULL DEFAULT '{}'::jsonb,updated_at TIMESTAMPTZ NOT NULL DEFAULT now())")
  if LICENSE_KEY:
   q.execute('SELECT license_key FROM license_config WHERE id=1');configured=q.fetchone()
   if not configured:
    data,_=check_license(LICENSE_KEY);q.execute("INSERT INTO license_config(id,license_key,valid,last_checked_at,last_response)VALUES(1,%s,%s,now(),%s)",(LICENSE_KEY,bool(data.get('valid')),json.dumps(data)))
  q.execute("CREATE TABLE IF NOT EXISTS bgp_devices(device_id BIGINT PRIMARY KEY,zabbix_hostid BIGINT NOT NULL,enabled BOOLEAN NOT NULL DEFAULT true,updated_at TIMESTAMPTZ NOT NULL DEFAULT now())")
  q.execute("CREATE TABLE IF NOT EXISTS notification_acknowledgements(user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,alert_key TEXT NOT NULL,acknowledged_at TIMESTAMPTZ NOT NULL DEFAULT now(),PRIMARY KEY(user_id,alert_key))")
  q.execute("CREATE TABLE IF NOT EXISTS bgp_operator_interfaces(id BIGSERIAL PRIMARY KEY,device_id BIGINT NOT NULL,zabbix_hostid BIGINT NOT NULL,interface_itemid BIGINT NOT NULL,interface_name TEXT NOT NULL,interface_description TEXT,provider_name TEXT NOT NULL,image_data BYTEA,image_content_type TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),UNIQUE(device_id,interface_itemid))")
  q.execute("ALTER TABLE bgp_operator_interfaces ADD COLUMN IF NOT EXISTS address_family TEXT NOT NULL DEFAULT 'ipv4'")
  q.execute("ALTER TABLE bgp_operator_interfaces ADD COLUMN IF NOT EXISTS subtitle TEXT")
  q.execute('ALTER TABLE nodes ADD COLUMN IF NOT EXISTS netbox_device_id BIGINT;ALTER TABLE nodes ADD COLUMN IF NOT EXISTS netbox_sync_error TEXT')
  q.execute('ALTER TABLE nodes ADD COLUMN IF NOT EXISTS splitter_type TEXT;ALTER TABLE nodes ADD COLUMN IF NOT EXISTS splitter_name TEXT')
  q.execute('ALTER TABLE issues ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION;ALTER TABLE issues ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION')
  q.execute("ALTER TABLE links ADD COLUMN IF NOT EXISTS route_mode TEXT NOT NULL DEFAULT 'manual'")
  q.execute("ALTER TABLE links ADD COLUMN IF NOT EXISTS source_splitter_type TEXT;ALTER TABLE links ADD COLUMN IF NOT EXISTS target_splitter_type TEXT")
  q.execute("ALTER TABLE links ADD COLUMN IF NOT EXISTS trunk_group TEXT;ALTER TABLE links ADD COLUMN IF NOT EXISTS is_trunk BOOLEAN NOT NULL DEFAULT false;CREATE INDEX IF NOT EXISTS links_trunk_group_idx ON links(trunk_group)")
  q.execute("CREATE TABLE IF NOT EXISTS link_passive_nodes(link_id BIGINT NOT NULL REFERENCES links(id) ON DELETE CASCADE,node_id BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,position_fraction DOUBLE PRECISION NOT NULL DEFAULT .5,splitter_type TEXT,input_side TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),PRIMARY KEY(link_id,node_id));ALTER TABLE link_passive_nodes ADD COLUMN IF NOT EXISTS splitter_type TEXT;ALTER TABLE link_passive_nodes ADD COLUMN IF NOT EXISTS input_side TEXT;CREATE INDEX IF NOT EXISTS link_passive_nodes_link_idx ON link_passive_nodes(link_id)")
  q.execute("""CREATE TABLE IF NOT EXISTS cto_splitters(id BIGSERIAL PRIMARY KEY,node_id BIGINT NOT NULL UNIQUE REFERENCES nodes(id) ON DELETE CASCADE,name TEXT NOT NULL,splitter_type TEXT NOT NULL,olt_id TEXT NOT NULL,sfp TEXT NOT NULL,link_id BIGINT REFERENCES links(id) ON DELETE SET NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS cto_splitter_outputs(id BIGSERIAL PRIMARY KEY,splitter_id BIGINT NOT NULL REFERENCES cto_splitters(id) ON DELETE CASCADE,output_number INTEGER NOT NULL,name TEXT NOT NULL,output_kind TEXT NOT NULL DEFAULT 'unused',created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),UNIQUE(splitter_id,output_number));
CREATE TABLE IF NOT EXISTS cto_ont_assignments(id BIGSERIAL PRIMARY KEY,output_id BIGINT NOT NULL REFERENCES cto_splitter_outputs(id) ON DELETE CASCADE,olt_id TEXT NOT NULL,sfp TEXT NOT NULL,ont_number INTEGER NOT NULL,ont_name TEXT,serial TEXT,status TEXT,rx_power DOUBLE PRECISION,vlans JSONB NOT NULL DEFAULT '[]'::jsonb,last_collected_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),UNIQUE(olt_id,sfp,ont_number));CREATE INDEX IF NOT EXISTS cto_ont_output_idx ON cto_ont_assignments(output_id)""")
  q.execute("ALTER TABLE cto_splitters ALTER COLUMN olt_id DROP NOT NULL;ALTER TABLE cto_splitters ALTER COLUMN sfp DROP NOT NULL;ALTER TABLE cto_ont_assignments ADD COLUMN IF NOT EXISTS geom geometry(Point,4326);CREATE INDEX IF NOT EXISTS cto_ont_geom_gix ON cto_ont_assignments USING GIST(geom)")
  q.execute("""INSERT INTO cto_splitters(node_id,name,splitter_type)
SELECT id,COALESCE(splitter_name,'Splitter '||name),splitter_type FROM nodes WHERE kind='cto' AND splitter_type IS NOT NULL ON CONFLICT(node_id)DO NOTHING""")
  q.execute("""INSERT INTO cto_splitter_outputs(splitter_id,output_number,name)
SELECT s.id,n,'Saída '||n FROM cto_splitters s CROSS JOIN LATERAL generate_series(1,split_part(s.splitter_type,'x',2)::integer) n ON CONFLICT(splitter_id,output_number)DO NOTHING""")
  # A consolidação dos registros antigos é deliberadamente opt-in: ela remove trechos filhos.
  # Habilite somente depois de criar backup: MIGRATE_LEGACY_SPLIT_LINKS=true.
  while os.getenv('MIGRATE_LEGACY_SPLIT_LINKS','false').lower()=='true':
   q.execute("""SELECT p.id parent_id,p.target_id node_id,c.id child_id FROM links p JOIN links c ON c.parent_link_id=p.id WHERE p.target_kind='node' AND c.source_kind='node' AND p.target_id=c.source_id LIMIT 1 FOR UPDATE""")
   split=q.fetchone()
   if not split:break
   q.execute('INSERT INTO link_passive_nodes(link_id,node_id)VALUES(%s,%s) ON CONFLICT DO NOTHING',(split['parent_id'],split['node_id']))
   q.execute("""UPDATE links p SET target_kind=c.target_kind,target_id=c.target_id,target_name=c.target_name,target_zabbix_hostid=c.target_zabbix_hostid,target_interface_itemid=c.target_interface_itemid,target_interface_name=c.target_interface_name,target_interface_description=c.target_interface_description,geom=ST_MakeLine(p.geom,c.geom),updated_at=now() FROM links c WHERE p.id=%s AND c.id=%s""",(split['parent_id'],split['child_id']))
   q.execute('UPDATE links SET parent_link_id=%s WHERE parent_link_id=%s',(split['parent_id'],split['child_id']))
   q.execute("UPDATE issues SET target_kind='link',target_id=%s,target_name=(SELECT name FROM links WHERE id=%s) WHERE target_kind='link' AND target_id=%s",(split['parent_id'],split['parent_id'],split['child_id']))
   q.execute('DELETE FROM links WHERE id=%s',(split['child_id'],))
  q.execute('SELECT count(*) n FROM users')
  if q.fetchone()['n']==0:
   pwd=os.getenv('NETATLAS_SUPERADMIN_PASSWORD')
   if not pwd:raise RuntimeError('NETATLAS_SUPERADMIN_PASSWORD precisa estar configurada no primeiro início')
   salt,digest=password_hash(pwd);q.execute("INSERT INTO users(username,display_name,role,password_salt,password_hash)VALUES('superadmin','Superadmin','superadmin',%s,%s)",(salt,digest))

def nbget(path):
 url=f"{NETBOX_URL}{path}"; out=[]
 with httpx.Client(timeout=20,headers={"Authorization":f"Token {NETBOX_TOKEN}"}) as c:
  while url:
   r=c.get(url);r.raise_for_status();p=r.json();out+=p.get("results",[]);url=p.get("next")
 return out
def audit(q,u,action,target_kind,target_id=None,target_name=None,details=None):
 q.execute('INSERT INTO audit_log(actor_id,actor_username,actor_role,action,target_kind,target_id,target_name,details)VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',(u['id'],u['username'],u['role'],action,target_kind,target_id,target_name,json.dumps(details or {})))
def nbrequest(method,path,payload=None):
 with httpx.Client(timeout=25,headers={"Authorization":f"Token {NETBOX_TOKEN}","Content-Type":"application/json"}) as c:
  r=c.request(method,f"{NETBOX_URL}{path}",json=payload);r.raise_for_status();return r.json() if r.content else None
def olt_manager_get(path,params=None):
 if not OLT_MANAGER_TOKEN:raise HTTPException(503,'A integração com o gerenciador de OLTs ainda não possui token configurado')
 try:
  with httpx.Client(timeout=20,headers={'Authorization':f'Bearer {OLT_MANAGER_TOKEN}'}) as c:
   r=c.get(f'{OLT_MANAGER_URL}{path}',params=params)
   try:data=r.json()
   except ValueError:data={}
   if r.status_code>=400:raise HTTPException(502,data.get('error') or f'O gerenciador de OLTs respondeu HTTP {r.status_code}')
   return data
 except HTTPException:raise
 except httpx.HTTPError as e:raise HTTPException(502,f'Não foi possível consultar o gerenciador de OLTs: {e}')
def pon_sfp(interface_name):
 match=re.search(r'(?:XGS?-?PON|GPON|PON)\s*[-:]?\s*(\d+/\d+/\d+)',interface_name or '',re.I)
 return match.group(1) if match else None
def cto_pon_contexts(node_id,manager_olts=None):
 with pg() as c,c.cursor() as q:
  q.execute("""SELECT DISTINCT l.id link_id,l.name link_name,l.source_zabbix_hostid,l.source_name,l.source_interface_name,l.target_zabbix_hostid,l.target_name,l.target_interface_name
FROM links l LEFT JOIN link_passive_nodes pn ON pn.link_id=l.id
WHERE (l.source_kind='node' AND l.source_id=%s) OR (l.target_kind='node' AND l.target_id=%s) OR pn.node_id=%s ORDER BY l.id""",(node_id,node_id,node_id));linked=q.fetchall()
 contexts=[]
 for link in linked:
  for side in ('source','target'):
   host_id=link[f'{side}_zabbix_hostid'];name=link[f'{side}_interface_name'];sfp=pon_sfp(name)
   if not host_id or not sfp:continue
   try:
    with closing(zconn()) as z,z.cursor() as cursor:
     cursor.execute("SELECT ip,dns FROM interface WHERE hostid=%s ORDER BY main DESC,interfaceid",(host_id,));addresses=[value for row in cursor.fetchall() for value in (row.get('ip'),row.get('dns')) if value]
   except Exception:addresses=[]
   contexts.append({'link_id':int(link['link_id']),'link_name':link['link_name'],'zabbix_hostid':int(host_id),'host_name':link[f'{side}_name'],'interface_name':name,'sfp':sfp,'host_addresses':list(dict.fromkeys(addresses))})
 unique=[];seen=set()
 for context in contexts:
  key=(context['link_id'],context['zabbix_hostid'],context['sfp'])
  if key in seen:continue
  seen.add(key);unique.append(context)
 if manager_olts is not None:
  for context in unique:
   matches=[olt['id'] for olt in manager_olts if olt.get('host') in context['host_addresses']]
   context['suggested_olt_id']=matches[0] if len(matches)==1 else None
 return unique
def sync_cto_distribution_to_netbox(q,node_id):
 q.execute('SELECT id,name,netbox_device_id FROM nodes WHERE id=%s AND kind=\'cto\'',(node_id,));node=q.fetchone()
 if not node or not node['netbox_device_id']:return
 q.execute("""SELECT s.name,s.splitter_type,s.olt_id,s.sfp,o.output_number,o.name output_name,o.output_kind,count(a.id) client_count,string_agg(concat(a.ont_number,':',COALESCE(a.serial,'')),', ' ORDER BY a.ont_number) clients
FROM cto_splitters s JOIN cto_splitter_outputs o ON o.splitter_id=s.id LEFT JOIN cto_ont_assignments a ON a.output_id=o.id
WHERE s.node_id=%s GROUP BY s.name,s.splitter_type,s.olt_id,s.sfp,o.output_number,o.name,o.output_kind ORDER BY o.output_number""",(node_id,));rows=q.fetchall()
 if not rows:return
 device=nbrequest('GET',f"/api/dcim/devices/{node['netbox_device_id']}/")
 comments=device.get('comments') or ''
 marker_start='<!-- NETATLAS-SPLITTER -->';marker_end='<!-- /NETATLAS-SPLITTER -->'
 block=[marker_start,f"Splitter: {rows[0]['name']} ({rows[0]['splitter_type']})",f"Origem: {rows[0]['olt_id']} · PON {rows[0]['sfp']}"]
 for row in rows:
  detail=f"Saída {row['output_number']}: {row['output_name']} [{row['output_kind']}] · {row['client_count']} cliente(s)"
  if row['clients']:detail+=f" · {row['clients']}"
  block.append(detail)
 block.append(marker_end);managed='\n'.join(block)
 if marker_start in comments and marker_end in comments:comments=re.sub(re.escape(marker_start)+r'.*?'+re.escape(marker_end),managed,comments,flags=re.S)
 else:comments=f"{comments.rstrip()}\n\n{managed}".strip()
 nbrequest('PATCH',f"/api/dcim/devices/{node['netbox_device_id']}/",{'comments':comments})
def slugify(value):
 value=unicodedata.normalize('NFKD',value).encode('ascii','ignore').decode().lower();return re.sub(r'[^a-z0-9]+','-',value).strip('-')[:100]
def nbensure(path,slug,payload):
 found=nbget(f'{path}?slug={slug}&limit=1');return found[0] if found else nbrequest('POST',path,payload)
def netbox_site(site_id):
 try:site=nbrequest('GET',f'/api/dcim/sites/{int(site_id)}/')
 except httpx.HTTPStatusError as e:
  if e.response.status_code==404:raise RuntimeError('POP não encontrado no NetBox')
  raise
 if site.get('latitude') is None or site.get('longitude') is None:raise RuntimeError('O POP selecionado não possui coordenadas')
 return site
def sync_node_to_netbox(node,site_id=None):
 labels={'cto':('CTO','cto','CTO'),'host':('Host planejado','host-planejado','Host Planejado'),'junction':('Elemento de rede','elemento-rede','Elemento de Rede'),'cloud':('Operadora','operadora','Operadora / Nuvem')};role_name,role_slug,model=labels.get(node['kind'],labels['junction'])
 manufacturer=nbensure('/api/dcim/manufacturers/','netatlas',{'name':'NetAtlas','slug':'netatlas','description':'Elementos cadastrados e sincronizados pelo LVL - NetAtlas'})
 role=nbensure('/api/dcim/device-roles/',role_slug,{'name':role_name,'slug':role_slug,'color':'2196f3','vm_role':False,'description':'Gerenciado pelo LVL - NetAtlas'})
 dtype_slug=f'netatlas-{role_slug}';dtype=nbensure('/api/dcim/device-types/',dtype_slug,{'manufacturer':manufacturer['id'],'model':model,'slug':dtype_slug,'u_height':0,'is_full_depth':False})
 sites=[s for s in nbget('/api/dcim/sites/?limit=1000') if s.get('latitude') is not None and s.get('longitude') is not None]
 if site_id is not None:site=netbox_site(site_id)
 elif not sites:raise RuntimeError('Nenhum POP com coordenadas disponível no NetBox')
 else:site=min(sites,key=lambda s:(float(s['latitude'])-float(node['latitude']))**2+(float(s['longitude'])-float(node['longitude']))**2)
 marker=f"NetAtlas node ID: {node['id']}";found=nbget(f"/api/dcim/devices/?name={node['name']}&site_id={site['id']}&limit=10")
 for device in found:
  if marker in (device.get('comments') or ''):return device
 splitter_note=f"\nSplitter: {node.get('splitter_name') or node.get('splitter_type')} ({node.get('splitter_type')})" if node.get('splitter_type') else ''
 payload={'name':node['name'],'device_type':dtype['id'],'role':role['id'],'site':site['id'],'status':'planned' if node['kind']=='host' else 'active','latitude':round(float(node['latitude']),6),'longitude':round(float(node['longitude']),6),'description':f'{role_name} cadastrada pelo LVL - NetAtlas','comments':f"{marker}\nTipo: {node['kind']}{splitter_note}"}
 return nbrequest('POST','/api/dcim/devices/',payload)
def sync_zabbix_host_to_netbox(host,ifaces,site_id):
 manufacturer=nbensure('/api/dcim/manufacturers/','zabbix-import',{'name':'Zabbix Import','slug':'zabbix-import','description':'Inventário importado pelo LVL - NetAtlas a partir do Zabbix'})
 role=nbensure('/api/dcim/device-roles/','zabbix-host',{'name':'Host Zabbix','slug':'zabbix-host','color':'22c55e','vm_role':False,'description':'Equipamento monitorado pelo Zabbix e gerenciado no NetAtlas'})
 dtype=nbensure('/api/dcim/device-types/','zabbix-managed-host',{'manufacturer':manufacturer['id'],'model':'Host monitorado pelo Zabbix','slug':'zabbix-managed-host','u_height':0,'is_full_depth':False})
 site=netbox_site(site_id);latitude=float(site['latitude']);longitude=float(site['longitude']);marker=f"Zabbix host ID: {host['hostid']}"
 existing=nbget('/api/dcim/devices/?limit=1000')
 device=next((d for d in existing if marker in (d.get('comments') or '')),None)
 payload={'name':host['name'],'device_type':dtype['id'],'role':role['id'],'site':site['id'],'status':'active','latitude':round(latitude,6),'longitude':round(longitude,6),'description':f"Importado do Zabbix ({host.get('host') or host['name']})",'comments':f"{marker}\nSincronizado pelo LVL - NetAtlas"}
 device=nbrequest('PATCH',f"/api/dcim/devices/{device['id']}/",payload) if device else nbrequest('POST','/api/dcim/devices/',payload)
 current={i['name']:i for i in nbget(f"/api/dcim/interfaces/?device_id={device['id']}&limit=1000")}
 for iface in ifaces:
  ipayload={'device':device['id'],'name':iface['name'],'type':'other','enabled':True,'description':(iface.get('description') or '')[:200]}
  old=current.get(iface['name'])
  if old:nbrequest('PATCH',f"/api/dcim/interfaces/{old['id']}/",ipayload)
  else:nbrequest('POST','/api/dcim/interfaces/',ipayload)
 return device,site
def latest(ids):
 if not ids:return {}
 ph=','.join(['%s']*len(ids));sql=f"SELECT i.itemid,(SELECT h.value FROM history_uint h WHERE h.itemid=i.itemid ORDER BY h.clock DESC LIMIT 1) value FROM items i WHERE i.itemid IN({ph})"
 with closing(zconn()) as c,c.cursor() as q:q.execute(sql,ids);return {int(r['itemid']):int(r['value']) for r in q.fetchall() if r['value'] is not None}
def latest_details(ids):
 if not ids:return {}
 ph=','.join(['%s']*len(ids));sql=f"SELECT i.itemid,(SELECT h.value FROM history_uint h WHERE h.itemid=i.itemid ORDER BY h.clock DESC LIMIT 1) value,(SELECT h.clock FROM history_uint h WHERE h.itemid=i.itemid ORDER BY h.clock DESC LIMIT 1) clock FROM items i WHERE i.itemid IN({ph})"
 with closing(zconn()) as c,c.cursor() as q:q.execute(sql,ids);return {int(r['itemid']):{'value':int(r['value']),'clock':int(r['clock'])} for r in q.fetchall() if r['value'] is not None and r['clock'] is not None}
def latest_numeric(ids):
 if not ids:return {}
 ph=','.join(['%s']*len(ids));sql=f"""SELECT i.itemid,CASE WHEN i.value_type=0 THEN(SELECT h.value FROM history h WHERE h.itemid=i.itemid ORDER BY h.clock DESC LIMIT 1)WHEN i.value_type=3 THEN(SELECT h.value FROM history_uint h WHERE h.itemid=i.itemid ORDER BY h.clock DESC LIMIT 1)END value,CASE WHEN i.value_type=0 THEN(SELECT h.clock FROM history h WHERE h.itemid=i.itemid ORDER BY h.clock DESC LIMIT 1)WHEN i.value_type=3 THEN(SELECT h.clock FROM history_uint h WHERE h.itemid=i.itemid ORDER BY h.clock DESC LIMIT 1)END clock FROM items i WHERE i.itemid IN({ph})"""
 with closing(zconn()) as c,c.cursor() as q:q.execute(sql,ids);return {int(r['itemid']):{'value':float(r['value']),'clock':int(r['clock'])} for r in q.fetchall() if r['value'] is not None and r['clock'] is not None}
def ping_peer(address):
 try:
  ip=ipaddress.ip_address(address);command=['ping','-n','-c','1','-W','1',str(ip)]
  if ip.version==6:command.insert(1,'-6')
  result=subprocess.run(command,capture_output=True,text=True,timeout=3,check=False)
  match=re.search(r'time[=<]([0-9.]+)\s*ms',result.stdout,re.I)
  return {'reachable':result.returncode==0,'latency_ms':float(match.group(1)) if match else None}
 except (ValueError,OSError,subprocess.TimeoutExpired):return {'reachable':False,'latency_ms':None}
def bgp_peers(host_id):
 sql="SELECT itemid,name,key_ FROM items WHERE hostid=%s AND status=0 AND flags<>2 AND(key_ LIKE 'BgpPeerState[%%]' OR key_ LIKE 'BgpPeerFsmEstablishedTime[%%]' OR key_ LIKE 'BgpPeerRoutes[%%]')"
 with closing(zconn()) as c,c.cursor() as q:q.execute(sql,(host_id,));items=q.fetchall()
 values=latest_details([int(item['itemid']) for item in items]);peers={}
 for item in items:
  match=re.match(r'^BgpPeer(State|FsmEstablishedTime|Routes)\[(.+)\]$',item['key_'])
  if not match:continue
  metric,address=match.groups()
  try:address=str(ipaddress.ip_address(address))
  except ValueError:continue
  peer=peers.setdefault(address,{'address':address,'asn':None,'state':None,'uptime_seconds':None,'prefixes':None,'collected_at':None})
  asn=re.search(r'\bAS(\d+)\b',item['name'],re.I)
  if asn:peer['asn']=int(asn.group(1))
  sample=values.get(int(item['itemid']))
  if not sample:continue
  peer['collected_at']=max(peer['collected_at'] or 0,sample['clock'])
  if metric=='State':peer['state']=sample['value']
  elif metric=='FsmEstablishedTime':peer['uptime_seconds']=sample['value']
  else:peer['prefixes']=sample['value']
 ordered=sorted(peers.values(),key=lambda p:(ipaddress.ip_address(p['address']).version,int(ipaddress.ip_address(p['address']))))
 with ThreadPoolExecutor(max_workers=min(12,max(1,len(ordered)))) as pool:results=list(pool.map(lambda peer:ping_peer(peer['address']),ordered))
 for peer,ping in zip(ordered,results):peer['ping']=ping
 return ordered
def zstates(ids):
 if not ids:return {}
 ph=','.join(['%s']*len(ids));sql=f"SELECT h.hostid,h.name,h.status,COALESCE(MAX(i.available),0) availability,GROUP_CONCAT(DISTINCT NULLIF(i.ip,'') ORDER BY i.main DESC SEPARATOR ', ') ips FROM hosts h LEFT JOIN interface i ON i.hostid=h.hostid WHERE h.hostid IN({ph}) GROUP BY h.hostid,h.name,h.status"
 with closing(zconn()) as c,c.cursor() as q:q.execute(sql,ids);return {int(r['hostid']):r for r in q.fetchall()}

@app.post('/api/auth/login')
def login(x:LoginIn,response:Response):
 with pg() as c,c.cursor() as q:
  q.execute('SELECT id,username,display_name,role,password_salt,password_hash,active FROM users WHERE lower(username)=lower(%s)',(x.username,));u=q.fetchone()
  if not u or not u['active'] or not verify_password(x.password,u['password_salt'],u['password_hash']):raise HTTPException(401,'Usuário ou senha inválidos')
  token=secrets.token_urlsafe(48);q.execute('DELETE FROM sessions WHERE expires_at<=now()');q.execute('INSERT INTO sessions(token_hash,user_id,expires_at)VALUES(%s,%s,%s)',(hashlib.sha256(token.encode()).hexdigest(),u['id'],datetime.now(timezone.utc)+timedelta(hours=12)))
 response.set_cookie('netatlas_session',token,httponly=True,samesite='strict',secure=False,max_age=43200,path='/')
 return {k:u[k] for k in ('id','username','display_name','role')}
@app.post('/api/auth/logout',status_code=204)
def logout(request:Request,response:Response):
 token=request.cookies.get('netatlas_session')
 if token:
  with pg() as c,c.cursor() as q:q.execute('DELETE FROM sessions WHERE token_hash=%s',(hashlib.sha256(token.encode()).hexdigest(),))
 response.delete_cookie('netatlas_session',path='/')
@app.get('/api/auth/me')
def me(u=Depends(viewer)):return u
@app.get('/api/users')
def users(u=Depends(superadmin)):
 with pg() as c,c.cursor() as q:q.execute('SELECT id,username,display_name,role,active,created_at FROM users ORDER BY username');return q.fetchall()
@app.post('/api/users',status_code=201)
def create_user(x:UserIn,u=Depends(superadmin)):
 salt,digest=password_hash(x.password)
 try:
  with pg() as c,c.cursor() as q:q.execute('INSERT INTO users(username,display_name,role,password_salt,password_hash)VALUES(%s,%s,%s,%s,%s)RETURNING id',(x.username.lower(),x.display_name,x.role,salt,digest));uid=q.fetchone()['id'];audit(q,u,'create_user','user',uid,x.username.lower(),{'role':x.role,'display_name':x.display_name});return {'id':uid}
 except psycopg.errors.UniqueViolation:raise HTTPException(409,'Este usuário já existe')
@app.get('/api/audit')
def audit_events(limit:int=200,u=Depends(superadmin)):
 limit=max(1,min(limit,500))
 with pg() as c,c.cursor() as q:q.execute('SELECT id,actor_username,actor_role,action,target_kind,target_id,target_name,details,created_at FROM audit_log ORDER BY id DESC LIMIT %s',(limit,));return q.fetchall()

def installed_revision():
 try:return subprocess.run(['git','-c',f'safe.directory={INSTALL_DIR}','-C',INSTALL_DIR,'rev-parse','HEAD'],capture_output=True,text=True,timeout=8,check=True).stdout.strip()
 except (subprocess.SubprocessError,OSError):return None

@app.get('/api/update/status')
def update_status(u=Depends(operator)):
 current=installed_revision()
 if not current:raise HTTPException(503,'Esta instalação não possui uma revisão Git válida')
 try:
  with httpx.Client(timeout=20,headers={'Accept':'application/vnd.github+json','User-Agent':'LVL-NetAtlas-Updater'}) as client:
   response=client.get(f'https://api.github.com/repos/{GITHUB_REPOSITORY}/compare/{current}...main')
   if response.status_code==404:
    latest=client.get(f'https://api.github.com/repos/{GITHUB_REPOSITORY}/commits/main');latest.raise_for_status();target=latest.json()['sha']
    return {'current':current,'latest':target,'available':False,'local_ahead':current!=target,'commits':[],'repository':GITHUB_REPOSITORY}
   response.raise_for_status();data=response.json()
 except (httpx.HTTPError,ValueError,KeyError) as error:raise HTTPException(502,f'Não foi possível consultar atualizações no GitHub: {error}')
 commits=[{'sha':item['sha'][:7],'message':item['commit']['message'].splitlines()[0]} for item in data.get('commits',[])[:20]]
 return {'current':current,'latest':data.get('merge_base_commit',{}).get('sha') if data.get('status')=='behind' else (data.get('commits') or [{'sha':current}])[-1]['sha'],'available':data.get('status') in ('ahead','diverged') and int(data.get('ahead_by',0))>0,'local_ahead':data.get('status')=='behind','commits':commits,'repository':GITHUB_REPOSITORY}

@app.post('/api/update/apply')
def apply_update(u=Depends(operator)):
 try:
  process=subprocess.Popen(['sudo','-n','/usr/local/sbin/netatlas-update'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 except OSError as error:raise HTTPException(503,f'Não foi possível iniciar a atualização: {error}')
 with pg() as c,c.cursor() as q:audit(q,u,'apply_update','system',None,'GitHub',{'repository':GITHUB_REPOSITORY,'from_revision':installed_revision(),'process_id':process.pid})
 return {'status':'started','message':'Atualização iniciada. O serviço será reiniciado automaticamente.'}

@app.get('/api/license')
def license_status(u=Depends(viewer)):
 with pg() as c,c.cursor() as q:
  q.execute('SELECT license_key,valid,last_checked_at,last_response,updated_at FROM license_config WHERE id=1'); row=q.fetchone()
 if not row:return {'configured':False,'product':LICENSE_PRODUCT}
 response=dict(row.pop('last_response') or {})
 return {'configured':bool(row['license_key']),'license_key':mask_license_key(row['license_key']) if row['license_key'] else None,'product':LICENSE_PRODUCT,'valid':bool(row['valid']),'last_checked_at':row['last_checked_at'],'updated_at':row['updated_at'],'details':response}

@app.post('/api/license/activate')
def activate_license(x:LicenseActivateIn,u=Depends(superadmin)):
 key=x.license_key.strip(); data,status=check_license(key)
 with pg() as c,c.cursor() as q:
  q.execute("INSERT INTO license_config(id,license_key,valid,last_checked_at,last_response,updated_at)VALUES(1,%s,%s,now(),%s,now()) ON CONFLICT(id) DO UPDATE SET license_key=EXCLUDED.license_key,valid=EXCLUDED.valid,last_checked_at=EXCLUDED.last_checked_at,last_response=EXCLUDED.last_response,updated_at=now()",(key,bool(data.get('valid')),json.dumps(data)))
  audit(q,u,'activate_license','license',1,LICENSE_PRODUCT,{'valid':bool(data.get('valid')),'reason':data.get('reason'),'license_key':mask_license_key(key)})
 if not data.get('valid'):raise HTTPException(status if status<500 else 503,data.get('reason') or 'Não foi possível validar a licença')
 return {'valid':True,'product':LICENSE_PRODUCT,'details':data}

@app.post('/api/license/check')
def recheck_license(u=Depends(superadmin)):
 with pg() as c,c.cursor() as q:q.execute('SELECT license_key FROM license_config WHERE id=1');row=q.fetchone()
 if not row or not row['license_key']:raise HTTPException(404,'Nenhuma licença foi configurada')
 data,status=check_license(row['license_key'])
 with pg() as c,c.cursor() as q:
  q.execute('UPDATE license_config SET valid=%s,last_checked_at=now(),last_response=%s,updated_at=now() WHERE id=1',(bool(data.get('valid')),json.dumps(data)))
  audit(q,u,'check_license','license',1,LICENSE_PRODUCT,{'valid':bool(data.get('valid')),'reason':data.get('reason')})
 if not data.get('valid'):raise HTTPException(status if status<500 else 503,data.get('reason') or 'Não foi possível validar a licença')
 return {'valid':True,'product':LICENSE_PRODUCT,'details':data}

@app.get('/health')
def health():return {'status':'ok','service':'LVL - NetAtlas'}
@app.get('/api/pops')
def pops(u=Depends(viewer)):
 try:sites,devices=nbget('/api/dcim/sites/?limit=1000'),nbget('/api/dcim/devices/?limit=1000')
 except Exception as e:raise HTTPException(502,f'Falha ao consultar os POPs no NetBox: {e}')
 counts={}
 for device in devices:
  site_id=(device.get('site') or {}).get('id')
  if site_id:counts[site_id]=counts.get(site_id,0)+1
 return [{'id':s['id'],'name':s['name'],'slug':s['slug'],'latitude':float(s['latitude']),'longitude':float(s['longitude']),'device_count':counts.get(s['id'],0)} for s in sites if s.get('latitude') is not None and s.get('longitude') is not None]
@app.post('/api/pops',status_code=201)
def create_pop(x:PopIn,u=Depends(operator)):
 base=slugify(x.name) or 'pop';slug=base
 try:
  existing=nbget(f'/api/dcim/sites/?slug={slug}&limit=1')
  if existing:raise HTTPException(409,'Já existe um POP com este nome')
  site=nbrequest('POST','/api/dcim/sites/',{'name':x.name.strip(),'slug':slug,'status':'active','latitude':round(x.latitude,6),'longitude':round(x.longitude,6),'description':'POP cadastrado pelo LVL - NetAtlas'})
 except HTTPException:raise
 except Exception as e:raise HTTPException(502,f'Não foi possível criar o POP no NetBox: {e}')
 with pg() as c,c.cursor() as q:audit(q,u,'create_pop','site',site['id'],site['name'],{'latitude':x.latitude,'longitude':x.longitude})
 return {'id':site['id'],'name':site['name'],'slug':site['slug'],'latitude':float(site['latitude']),'longitude':float(site['longitude'])}

@app.delete('/api/pops/{site_id}')
def delete_pop(site_id:int,u=Depends(operator)):
 try:
  site=nbrequest('GET',f'/api/dcim/sites/{site_id}/')
  devices=nbget(f'/api/dcim/devices/?site_id={site_id}&limit=1000')
  if devices:
   names=', '.join(d['name'] for d in devices[:5]);extra=f' e mais {len(devices)-5}' if len(devices)>5 else ''
   raise HTTPException(409,f'O POP possui {len(devices)} elemento(s) vinculado(s): {names}{extra}. Exclua ou mova esses elementos primeiro.')
  nbrequest('DELETE',f'/api/dcim/sites/{site_id}/')
 except HTTPException:raise
 except httpx.HTTPStatusError as e:
  if e.response.status_code==404:raise HTTPException(404,'POP não encontrado no NetBox')
  raise HTTPException(502,f'Não foi possível excluir o POP no NetBox: {e.response.text[:500]}')
 except Exception as e:raise HTTPException(502,f'Não foi possível excluir o POP no NetBox: {e}')
 with pg() as c,c.cursor() as q:audit(q,u,'delete_pop','site',site_id,site['name'],{})
 return {'status':'ok','id':site_id,'name':site['name']}

@app.get('/api/inventory/hosts')
def inventory_hosts(u=Depends(operator)):
 try:devices=nbget('/api/dcim/devices/?limit=1000')
 except Exception as e:raise HTTPException(502,f'Falha ao consultar os hosts no NetBox: {e}')
 result=[]
 for device in devices:
  comments=device.get('comments') or ''
  if re.search(r'NetAtlas node ID:\s*\d+',comments):continue
  match=re.search(r'Zabbix host ID:\s*(\d+)',comments)
  result.append({'id':device['id'],'name':device['name'],'site':(device.get('site') or {}).get('name'),'site_id':(device.get('site') or {}).get('id'),'status':(device.get('status') or {}).get('value','unknown'),'zabbix_hostid':int(match.group(1)) if match else None})
 return sorted(result,key=lambda d:((d.get('site') or '').lower(),d['name'].lower()))
@app.get('/api/topology')
def topology(u=Depends(viewer)):
 try:sites,devices=nbget('/api/dcim/sites/?limit=1000'),nbget('/api/dcim/devices/?limit=1000')
 except Exception as e:raise HTTPException(502,f'Falha ao consultar o NetBox: {e}')
 sm={s['id']:{'id':s['id'],'name':s['name'],'slug':s['slug'],'latitude':float(s['latitude']) if s.get('latitude') is not None else None,'longitude':float(s['longitude']) if s.get('longitude') is not None else None,'devices':[]} for s in sites};staged=[];ids=[]
 with pg() as c,c.cursor() as q:
  q.execute("SELECT element_id,ST_Y(geom) latitude,ST_X(geom) longitude FROM element_positions WHERE element_kind='device'");positions={int(r['element_id']):r for r in q.fetchall()}
  q.execute("SELECT device_id FROM bgp_devices WHERE enabled");bgp_enabled={int(r['device_id']) for r in q.fetchall()}
 for d in devices:
  if re.search(r'NetAtlas node ID:\s*\d+',d.get('comments') or ''):continue
  m=re.search(r'Zabbix host ID:\s*(\d+)',d.get('comments') or '');hid=int(m.group(1)) if m else None
  if hid:ids.append(hid)
  staged.append((d,hid))
 try:states=zstates(ids);err=None
 except Exception as e:states={};err=str(e)
 for d,hid in staged:
  sid=(d.get('site') or {}).get('id')
  if sid not in sm:continue
  s=states.get(hid) if hid else None;dt=d.get('device_type') or {}
  p=positions.get(int(d['id']));sm[sid]['devices'].append({'id':d['id'],'name':d['name'],'role':(d.get('role') or {}).get('name','Equipamento'),'role_slug':(d.get('role') or {}).get('slug','device'),'model':dt.get('model'),'manufacturer':(dt.get('manufacturer') or {}).get('name'),'netbox_status':(d.get('status') or {}).get('value','unknown'),'zabbix_hostid':hid,'zabbix_name':s.get('name') if s else None,'zabbix_status':s.get('status') if s else None,'availability':s.get('availability') if s else None,'ips':s.get('ips') if s else None,'bgp_enabled':int(d['id']) in bgp_enabled,'latitude':float(p['latitude']) if p else None,'longitude':float(p['longitude']) if p else None})
 return {'sites':[s for s in sm.values() if s['latitude'] is not None],'zabbix_error':err}

@app.patch('/api/devices/{device_id}/bgp')
def configure_bgp(device_id:int,x:BgpFeatureIn,u=Depends(operator)):
 try:
  with closing(zconn()) as c,c.cursor() as z:z.execute('SELECT name FROM hosts WHERE hostid=%s AND status=0',(x.zabbix_hostid,));host=z.fetchone()
 except Exception as e:raise HTTPException(502,f'Falha ao consultar o host no Zabbix: {e}')
 if not host:raise HTTPException(404,'Host ativo não encontrado no Zabbix')
 if 'bgp' not in host['name'].lower():raise HTTPException(422,'A funcionalidade BGP só pode ser ativada em hosts que tenham BGP no nome')
 with pg() as c,c.cursor() as q:
  q.execute("INSERT INTO bgp_devices(device_id,zabbix_hostid,enabled)VALUES(%s,%s,%s) ON CONFLICT(device_id)DO UPDATE SET zabbix_hostid=excluded.zabbix_hostid,enabled=excluded.enabled,updated_at=now()",(device_id,x.zabbix_hostid,x.enabled));audit(q,u,'configure_bgp','device',device_id,host['name'],{'enabled':x.enabled,'zabbix_hostid':x.zabbix_hostid})
 return {'device_id':device_id,'enabled':x.enabled}

@app.get('/api/devices/{device_id}/bgp/peers')
def device_bgp_peers(device_id:int,u=Depends(viewer)):
 with pg() as c,c.cursor() as q:q.execute('SELECT zabbix_hostid FROM bgp_devices WHERE device_id=%s AND enabled',(device_id,));configured=q.fetchone()
 if not configured:raise HTTPException(404,'A funcionalidade BGP não está ativada neste host')
 try:peers=bgp_peers(int(configured['zabbix_hostid']))
 except Exception as e:raise HTTPException(502,f'Falha ao consultar peers BGP no Zabbix: {e}')
 return {'device_id':device_id,'zabbix_hostid':configured['zabbix_hostid'],'peers':peers,'count':len(peers)}

def operator_interfaces_for_device(device_id:int,u):
 with pg() as c,c.cursor() as q:q.execute('SELECT id,device_id,zabbix_hostid,interface_itemid,interface_name,interface_description,provider_name,address_family,subtitle,image_data IS NOT NULL has_image,updated_at FROM bgp_operator_interfaces WHERE device_id=%s ORDER BY provider_name,address_family,interface_name',(device_id,));configured=q.fetchall()
 if not configured:return []
 live=interfaces(int(configured[0]['zabbix_hostid']),u)
 for row in configured:
  match=next((x for x in live if int(x.get('status_itemid') or x.get('rx_itemid') or x.get('tx_itemid') or 0)==int(row['interface_itemid']) or x['name']==row['interface_name']),None)
  row['metrics']=match;row['image_url']=f"/api/operator-interfaces/{row['id']}/image?v={int(row['updated_at'].timestamp())}" if row['has_image'] else None;row.pop('has_image',None);row['updated_at']=row['updated_at'].isoformat()
 return configured

@app.get('/api/devices/{device_id}/bgp/operator-interfaces')
def list_device_operator_interfaces(device_id:int,u=Depends(viewer)):return operator_interfaces_for_device(device_id,u)

@app.put('/api/devices/{device_id}/bgp/operator-interfaces')
def save_operator_interface(device_id:int,x:OperatorInterfaceIn,u=Depends(operator)):
 with pg() as c,c.cursor() as q:
  q.execute('SELECT 1 FROM bgp_devices WHERE device_id=%s AND zabbix_hostid=%s AND enabled',(device_id,x.zabbix_hostid))
  if not q.fetchone():raise HTTPException(422,'Ative o monitoramento BGP neste host antes de marcar interfaces de operadora')
  q.execute("INSERT INTO bgp_operator_interfaces(device_id,zabbix_hostid,interface_itemid,interface_name,interface_description,provider_name,address_family,subtitle)VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(device_id,interface_itemid)DO UPDATE SET interface_name=excluded.interface_name,interface_description=excluded.interface_description,provider_name=excluded.provider_name,address_family=excluded.address_family,subtitle=excluded.subtitle,updated_at=now() RETURNING id",(device_id,x.zabbix_hostid,x.interface_itemid,x.interface_name,x.interface_description,x.provider_name.strip(),x.address_family,(x.subtitle or '').strip() or None));oid=q.fetchone()['id'];audit(q,u,'mark_operator_interface','device',device_id,x.provider_name.strip(),{'operator_interface_id':oid,'interface_itemid':x.interface_itemid,'interface_name':x.interface_name,'address_family':x.address_family,'subtitle':(x.subtitle or '').strip() or None})
 return {'id':oid,'provider_name':x.provider_name.strip(),'address_family':x.address_family}

@app.delete('/api/operator-interfaces/{operator_id}',status_code=204)
def delete_operator_interface(operator_id:int,u=Depends(operator)):
 with pg() as c,c.cursor() as q:
  q.execute('DELETE FROM bgp_operator_interfaces WHERE id=%s RETURNING device_id,provider_name,interface_name',(operator_id,));row=q.fetchone()
  if not row:raise HTTPException(404,'Interface de operadora não encontrada')
  audit(q,u,'unmark_operator_interface','device',row['device_id'],row['provider_name'],{'operator_interface_id':operator_id,'interface_name':row['interface_name']})

@app.put('/api/operator-interfaces/{operator_id}/image')
async def upload_operator_image(operator_id:int,request:Request,u=Depends(operator)):
 content_type=(request.headers.get('content-type') or '').split(';')[0].lower();allowed={'image/png','image/jpeg','image/webp','image/gif'}
 if content_type not in allowed:raise HTTPException(415,'Envie uma imagem PNG, JPEG, WebP ou GIF')
 data=await request.body()
 if not data or len(data)>2*1024*1024:raise HTTPException(413,'A imagem deve possuir no máximo 2 MB')
 with pg() as c,c.cursor() as q:
  q.execute('SELECT device_id,provider_name FROM bgp_operator_interfaces WHERE id=%s',(operator_id,));row=q.fetchone()
  if not row:raise HTTPException(404,'Interface de operadora não encontrada')
  q.execute('UPDATE bgp_operator_interfaces SET image_data=%s,image_content_type=%s,updated_at=now() WHERE device_id=%s AND lower(provider_name)=lower(%s)',(data,content_type,row['device_id'],row['provider_name']))
  audit(q,u,'upload_operator_image','device',row['device_id'],row['provider_name'],{'operator_interface_id':operator_id,'content_type':content_type,'bytes':len(data)})
 return {'status':'ok'}

@app.get('/api/operator-interfaces/{operator_id}/image')
def operator_image(operator_id:int,u=Depends(viewer)):
 with pg() as c,c.cursor() as q:q.execute('SELECT image_data,image_content_type FROM bgp_operator_interfaces WHERE id=%s',(operator_id,));row=q.fetchone()
 if not row or not row['image_data']:raise HTTPException(404,'Imagem não encontrada')
 return Response(content=bytes(row['image_data']),media_type=row['image_content_type'],headers={'Cache-Control':'private, max-age=3600'})

@app.get('/api/bgp/operator-interfaces')
def all_operator_interfaces(u=Depends(viewer)):
 with pg() as c,c.cursor() as q:q.execute('SELECT DISTINCT oi.device_id FROM bgp_operator_interfaces oi JOIN bgp_devices b ON b.device_id=oi.device_id AND b.enabled ORDER BY oi.device_id');device_ids=[int(r['device_id']) for r in q.fetchall()]
 return [{'device_id':device_id,'interfaces':operator_interfaces_for_device(device_id,u)} for device_id in device_ids]

@app.get('/api/devices/{device_id}/operator-traffic')
def operator_traffic(device_id:int,provider:str,minutes:int=30,u=Depends(viewer)):
 if minutes not in (30,60,180):raise HTTPException(422,'Período inválido. Use 30, 60 ou 180 minutos')
 configured=[item for item in operator_interfaces_for_device(device_id,u) if item['provider_name'].casefold()==provider.casefold()]
 if not configured:raise HTTPException(404,'Operadora não encontrada neste host')
 rx_ids={int(item['metrics']['rx_itemid']) for item in configured if item.get('metrics') and item['metrics'].get('rx_itemid')};tx_ids={int(item['metrics']['tx_itemid']) for item in configured if item.get('metrics') and item['metrics'].get('tx_itemid')};item_ids=sorted(rx_ids|tx_ids)
 if not item_ids:return {'provider':provider,'minutes':minutes,'series':[]}
 since=int(time.time())-minutes*60;marks=','.join(['%s']*len(item_ids));sql=f"SELECT itemid,clock,value FROM history_uint WHERE itemid IN ({marks}) AND clock>=%s UNION ALL SELECT itemid,clock,value FROM history WHERE itemid IN ({marks}) AND clock>=%s ORDER BY clock"
 with closing(zconn()) as c,c.cursor() as q:q.execute(sql,tuple(item_ids)+(since,)+tuple(item_ids)+(since,));rows=q.fetchall()
 bucket_seconds=60 if minutes==30 else 120 if minutes==60 else 300;buckets={}
 for row in rows:
  bucket=int(row['clock'])//bucket_seconds*bucket_seconds;buckets.setdefault(bucket,{})[int(row['itemid'])]=float(row['value'])
 series=[]
 for item in configured:
  metrics=item.get('metrics') or {};rx_id=int(metrics['rx_itemid']) if metrics.get('rx_itemid') else None;tx_id=int(metrics['tx_itemid']) if metrics.get('tx_itemid') else None;points=[]
  for clock,values in sorted(buckets.items()):
   if rx_id not in values and tx_id not in values:continue
   points.append({'clock':clock,'rx_bps':values.get(rx_id) if rx_id else None,'tx_bps':values.get(tx_id) if tx_id else None})
  series.append({'interface_itemid':item['interface_itemid'],'interface_name':item['interface_name'],'subtitle':item.get('subtitle'),'address_family':item['address_family'],'status':metrics.get('status','unknown'),'points':points[-181:]})
 return {'provider':provider,'minutes':minutes,'series':series}

@app.get('/api/host-statuses')
def host_statuses(ids:str='',u=Depends(viewer)):
 try:host_ids=sorted({int(v) for v in ids.split(',') if v.strip()})
 except ValueError:raise HTTPException(422,'Lista de hosts inválida')
 if len(host_ids)>500:raise HTTPException(422,'Limite de 500 hosts por consulta')
 try:states=zstates(host_ids)
 except Exception as e:raise HTTPException(502,f'Falha ao consultar status no Zabbix: {e}')
 return [{'hostid':hid,'name':s.get('name'),'status':s.get('status'),'availability':s.get('availability'),'ips':s.get('ips')} for hid,s in states.items()]

@app.get('/api/zabbix/hosts/search')
def search_zabbix_hosts(q:str='',u=Depends(operator)):
 term=q.strip()
 if len(term)<2:return []
 like=f'%{term}%'
 sql="""SELECT h.hostid,h.host,h.name,h.status,COALESCE(MAX(i.available),0) availability,GROUP_CONCAT(DISTINCT NULLIF(i.ip,'') ORDER BY i.main DESC SEPARATOR ', ') ips FROM hosts h LEFT JOIN interface i ON i.hostid=h.hostid WHERE h.flags=0 AND h.status IN(0,1) AND (h.name LIKE %s OR h.host LIKE %s OR i.ip LIKE %s) GROUP BY h.hostid,h.host,h.name,h.status ORDER BY h.name LIMIT 30"""
 try:
  with closing(zconn()) as c,c.cursor() as z:z.execute(sql,(like,like,like));return z.fetchall()
 except Exception as e:raise HTTPException(502,f'Falha ao pesquisar hosts no Zabbix: {e}')

@app.get('/api/zabbix/hosts')
def list_zabbix_hosts(u=Depends(operator)):
 sql="""SELECT h.hostid,h.host,h.name,h.status,COALESCE(MAX(i.available),0) availability,GROUP_CONCAT(DISTINCT NULLIF(i.ip,'') ORDER BY i.main DESC SEPARATOR ', ') ips FROM hosts h LEFT JOIN interface i ON i.hostid=h.hostid WHERE h.flags=0 AND h.status IN(0,1) GROUP BY h.hostid,h.host,h.name,h.status ORDER BY h.status,h.name"""
 try:
  with closing(zconn()) as c,c.cursor() as z:z.execute(sql);hosts=z.fetchall()
  imported={}
  for device in nbget('/api/dcim/devices/?limit=1000'):
   match=re.search(r'Zabbix host ID:\s*(\d+)',device.get('comments') or '')
   if match:imported[int(match.group(1))]={'id':device['id'],'name':device['name'],'site':(device.get('site') or {}).get('name')}
  for host in hosts:
   device=imported.get(int(host['hostid']));host['imported']=bool(device);host['netbox_device']=device
  return hosts
 except Exception as e:raise HTTPException(502,f'Falha ao listar hosts do Zabbix: {e}')

@app.get('/api/zabbix/hosts/{host_id}')
def preview_zabbix_host(host_id:int,u=Depends(operator)):
 try:
  with closing(zconn()) as c,c.cursor() as z:
   z.execute("SELECT h.hostid,h.host,h.name,h.status,COALESCE(MAX(i.available),0) availability,GROUP_CONCAT(DISTINCT NULLIF(i.ip,'') ORDER BY i.main DESC SEPARATOR ', ') ips FROM hosts h LEFT JOIN interface i ON i.hostid=h.hostid WHERE h.hostid=%s GROUP BY h.hostid,h.host,h.name,h.status",(host_id,));host=z.fetchone()
  if not host:raise HTTPException(404,'Host não encontrado no Zabbix')
  return {'host':host,'interfaces':interfaces(host_id,u)}
 except HTTPException:raise
 except Exception as e:raise HTTPException(502,f'Falha ao consultar o host no Zabbix: {e}')

@app.post('/api/zabbix/hosts/import',status_code=201)
def import_zabbix_host(x:ZabbixHostImportIn,u=Depends(operator)):
 return import_zabbix_host_record(x.hostid,x.site_id,u)

def import_zabbix_host_record(hostid,site_id,u):
 try:
  with closing(zconn()) as c,c.cursor() as z:z.execute('SELECT hostid,host,name,status FROM hosts WHERE hostid=%s',(hostid,));host=z.fetchone()
  if not host:raise HTTPException(404,'Host não encontrado no Zabbix')
  if int(host['status'])!=0:raise HTTPException(422,'Somente hosts ativos no Zabbix podem consumir uma licença')
  license_active_host('claim',host['hostid'],host['name'])
  ifaces=interfaces(hostid,u)
  device,site=sync_zabbix_host_to_netbox(host,ifaces,site_id);latitude=float(site['latitude']);longitude=float(site['longitude'])
  with pg() as c,c.cursor() as q:q.execute("INSERT INTO element_positions(element_kind,element_id,geom)VALUES('device',%s,ST_SetSRID(ST_MakePoint(%s,%s),4326)) ON CONFLICT(element_kind,element_id)DO UPDATE SET geom=excluded.geom,updated_at=now()",(device['id'],longitude,latitude));audit(q,u,'import_zabbix_host','device',device['id'],host['name'],{'zabbix_hostid':hostid,'interfaces_synced':len(ifaces),'site_id':site_id,'latitude':latitude,'longitude':longitude})
  return {'device_id':device['id'],'name':host['name'],'hostid':hostid,'site':site['name'],'interfaces_synced':len(ifaces)}
 except HTTPException:raise
 except Exception as e:raise HTTPException(502,f'Não foi possível importar o host para o NetBox: {e}')

@app.post('/api/zabbix/hosts/import-bulk',status_code=201)
def import_zabbix_hosts_bulk(x:ZabbixHostsImportIn,u=Depends(operator)):
 imported=[];errors=[]
 for hostid in dict.fromkeys(x.hostids):
  try:imported.append(import_zabbix_host_record(hostid,x.site_id,u))
  except HTTPException as error:
   detail=error.detail if isinstance(error.detail,str) else json.dumps(error.detail,ensure_ascii=False)
   errors.append({'hostid':hostid,'error':detail})
 return {'imported':imported,'errors':errors,'requested':len(dict.fromkeys(x.hostids))}

@app.post('/api/nodes/{node_id}/validate-zabbix-host')
def validate_provisional_host(node_id:int,x:ValidateProvisionalHostIn,u=Depends(operator)):
 with pg() as c,c.cursor() as q:
  q.execute('SELECT id,name,kind,netbox_device_id,ST_Y(geom) latitude,ST_X(geom) longitude FROM nodes WHERE id=%s FOR UPDATE',(node_id,));node=q.fetchone()
  if not node:raise HTTPException(404,'Host provisório não encontrado')
  if node['kind']!='host':raise HTTPException(422,'Somente hosts provisórios podem ser validados desta forma')
  try:
   with closing(zconn()) as zc,zc.cursor() as z:z.execute('SELECT hostid,host,name,status FROM hosts WHERE hostid=%s',(x.hostid,));host=z.fetchone()
   if not host:raise HTTPException(404,'Host não encontrado no Zabbix')
   if int(host['status'])!=0:raise HTTPException(422,'Somente hosts ativos no Zabbix podem consumir uma licença')
   license_active_host('claim',host['hostid'],host['name'])
   if not node['netbox_device_id']:raise HTTPException(422,'O host provisório não está associado a um POP no NetBox')
   provisional=nbrequest('GET',f"/api/dcim/devices/{node['netbox_device_id']}/");site_id=(provisional.get('site') or {}).get('id')
   if not site_id:raise HTTPException(422,'O host provisório não está associado a um POP')
   ifaces=interfaces(x.hostid,u);device,site=sync_zabbix_host_to_netbox(host,ifaces,site_id)
  except HTTPException:raise
  except Exception as e:raise HTTPException(502,f'Não foi possível validar o host no NetBox/Zabbix: {e}')
  old_device_id=node['netbox_device_id']
  if old_device_id:
   try:nbrequest('DELETE',f'/api/dcim/devices/{old_device_id}/')
   except httpx.HTTPStatusError as e:
    if e.response.status_code!=404:raise HTTPException(502,f'Não foi possível remover o host provisório no NetBox: {e}')
  q.execute("UPDATE links SET source_kind='device',source_id=%s,source_name=%s,source_zabbix_hostid=%s,source_interface_itemid=NULL,source_interface_name=NULL,source_interface_description=NULL WHERE source_kind='node' AND source_id=%s",(device['id'],host['name'],x.hostid,node_id));moved_source=q.rowcount
  q.execute("UPDATE links SET target_kind='device',target_id=%s,target_name=%s,target_zabbix_hostid=%s,target_interface_itemid=NULL,target_interface_name=NULL,target_interface_description=NULL WHERE target_kind='node' AND target_id=%s",(device['id'],host['name'],x.hostid,node_id));moved_target=q.rowcount
  q.execute("UPDATE issues SET target_kind='device',target_id=%s,target_name=%s WHERE target_kind='node' AND target_id=%s",(device['id'],host['name'],node_id))
  q.execute("INSERT INTO element_positions(element_kind,element_id,geom)VALUES('device',%s,ST_SetSRID(ST_MakePoint(%s,%s),4326)) ON CONFLICT(element_kind,element_id)DO UPDATE SET geom=excluded.geom,updated_at=now()",(device['id'],node['longitude'],node['latitude']))
  q.execute('DELETE FROM nodes WHERE id=%s',(node_id,));audit(q,u,'validate_provisional_host','device',device['id'],host['name'],{'provisional_node_id':node_id,'zabbix_hostid':x.hostid,'interfaces_synced':len(ifaces),'moved_links':moved_source+moved_target,'site':site['name']})
 return {'device_id':device['id'],'name':host['name'],'interfaces_synced':len(ifaces),'moved_links':moved_source+moved_target,'site':site['name']}

@app.post('/api/routes/suggest')
def suggest_route(x:RouteSuggestionIn,u=Depends(operator)):
 valid([x.source,x.target]);a,b=x.source,x.target
 try:
  with httpx.Client(timeout=20) as c:r=c.get(f'{OSRM_URL}/route/v1/driving/{a[0]},{a[1]};{b[0]},{b[1]}',params={'geometries':'geojson','overview':'full','steps':'false'})
  r.raise_for_status();data=r.json()
 except Exception as e:raise HTTPException(502,f'Não foi possível consultar o serviço de rotas: {e}')
 if data.get('code')!='Ok' or not data.get('routes'):raise HTTPException(422,'Não foi encontrado um trajeto pelas ruas entre estes equipamentos')
 coordinates=data['routes'][0].get('geometry',{}).get('coordinates') or []
 if len(coordinates)<2:raise HTTPException(502,'O serviço de rotas retornou uma geometria inválida')
 coordinates[0]=x.source;coordinates[-1]=x.target
 return {'coordinates':coordinates,'distance_m':data['routes'][0].get('distance'),'duration_s':data['routes'][0].get('duration'),'provider':'OSRM / OpenStreetMap'}

@app.get('/api/interfaces/{host_id}')
def interfaces(host_id:int,u=Depends(viewer)):
 sql="SELECT itemid,name,key_ FROM items WHERE hostid=%s AND status=0 AND flags<>2 AND ((name LIKE 'Interface %%' AND(key_ LIKE 'net.if.status%%' OR key_ LIKE 'net.if.in%%' OR key_ LIKE 'net.if.out%%')) OR key_ LIKE 'ramal.status[%%]')"
 with closing(zconn()) as c,c.cursor() as q:q.execute(sql,(host_id,));rows=q.fetchall()
 groups={};pon_status=[]
 for r in rows:
  if r['key_'].startswith('ramal.status'):
   pm=re.search(r'ramal\.status\[[^.\]]+\.(GPON\s+[^\]]+)\]',r['key_'],re.I)
   if pm:pon_status.append((pm.group(1).strip(),int(r['itemid'])))
   continue
  m=re.match(r'^Interface\s+(.+?)(?:\((.*?)\))?:\s*(.+)$',r['name'],re.I)
  if not m:continue
  iface,desc,_=m.groups();km=re.search(r'\[([^\]]+)\]',r['key_']);idx=km.group(1).split('.')[-1] if km else iface;g=groups.setdefault((iface,idx),{'name':iface,'description':desc or '','index':idx,'status_itemid':None,'rx_itemid':None,'tx_itemid':None})
  if r['key_'].startswith('net.if.status'):g['status_itemid']=int(r['itemid'])
  elif r['key_'].startswith('net.if.in'):g['rx_itemid']=int(r['itemid'])
  else:g['tx_itemid']=int(r['itemid'])
 for iface,itemid in pon_status:
  for g in groups.values():
   if g['name'].lower()==iface.lower():g['status_itemid']=itemid;g['status_type']='ponStatus'
 all_items=[i for g in groups.values() for i in (g['status_itemid'],g['rx_itemid'],g['tx_itemid']) if i]
 vals=latest_details(all_items)
 signal_sql="""SELECT itemid,name,key_ FROM items WHERE hostid=%s AND status=0 AND flags<>2 AND lower(units)='dbm' AND (lower(name) REGEXP '(rx|tx|receive|transmit|recebid|transmitid).*(power|signal|pot.ncia)' OR lower(name) REGEXP '(power|signal|pot.ncia).*(rx|tx|receive|transmit|recebid|transmitid)' OR lower(key_) REGEXP '(rx|tx).*(power|signal)|(power|signal).*(rx|tx)')"""
 with closing(zconn()) as c,c.cursor() as q:q.execute(signal_sql,(host_id,));signal_rows=q.fetchall()
 def norm(v):return re.sub(r'[^a-z0-9]','',v.lower())
 chosen={}
 for r in signal_rows:
  text=f"{r['name']} {r['key_']}";nt=norm(text);direction='rx' if re.search(r'rx\s*(?:power|signal)|(?:receive|recebid)',text,re.I) else 'tx' if re.search(r'tx\s*(?:power|signal)|(?:transmit)',text,re.I) else None
  if not direction:continue
  candidates=[]
  for key,g in groups.items():
   ni=norm(g['name'])
   if len(ni)>=4 and ni in nt:
    score=(40 if re.search(r'avg|m[eé]dia|calculado',text,re.I) else 0)-(30 if re.search(r'lane\s*[0-9]',text,re.I) else 0)-max(0,len(nt)-len(ni))/1000
    candidates.append((score,key))
  if not candidates:continue
  score,key=max(candidates,key=lambda x:x[0]);old=chosen.get((key,direction))
  if not old or score>old[0]:chosen[(key,direction)]=(score,int(r['itemid']))
 signal_ids=[v[1] for v in chosen.values()];signal_vals=latest_numeric(signal_ids)
 now=int(datetime.now(timezone.utc).timestamp())
 for key,g in groups.items():
  sv=vals.get(g['status_itemid']) if g['status_itemid'] else None
  traffic=[vals.get(i) for i in (g['rx_itemid'],g['tx_itemid']) if i and vals.get(i)]
  if sv:g['status']='up' if sv['value']==1 else 'down' if sv['value'] in (2,6,7) else 'unknown'
  else:
   g['status']='up' if traffic and max(x['clock'] for x in traffic)>=now-900 else 'unknown'
  g['status_source']=g.get('status_type') or ('ifOperStatus' if g['status_itemid'] else 'recent_traffic' if g['status']=='up' else 'no_status_item')
  rv=vals.get(g['rx_itemid']) if g['rx_itemid'] else None;tv=vals.get(g['tx_itemid']) if g['tx_itemid'] else None
  g['status_value']=sv['value'] if sv else None;g['status_clock']=sv['clock'] if sv else max((x['clock'] for x in traffic),default=None)
  g['download_bps']=rv['value'] if rv else None;g['download_clock']=rv['clock'] if rv else None
  g['upload_bps']=tv['value'] if tv else None;g['upload_clock']=tv['clock'] if tv else None
  rxid=chosen.get((key,'rx'),(None,None))[1];txid=chosen.get((key,'tx'),(None,None))[1];rx=signal_vals.get(rxid);tx=signal_vals.get(txid)
  g['optical_rx_dbm']=rx['value'] if rx else None;g['optical_rx_clock']=rx['clock'] if rx else None
  g['optical_tx_dbm']=tx['value'] if tx else None;g['optical_tx_clock']=tx['clock'] if tx else None
 def natural_interface_key(item):
  return [int(part) if part.isdigit() else part.lower() for part in re.split(r'(\d+)',item['name'])]
 return sorted(groups.values(),key=natural_interface_key)

def require_cto(q,node_id):
 q.execute("SELECT id,name,netbox_device_id FROM nodes WHERE id=%s AND kind='cto'",(node_id,));node=q.fetchone()
 if not node:raise HTTPException(404,'CTO não encontrada')
 return node
def manager_olts():return olt_manager_get('/api/integration/olts').get('olts',[])
def manager_onts(olt_id,sfp):return olt_manager_get('/api/integration/onts',{'olt':olt_id,'sfp':sfp})
def manager_olt_name(olt_id,olts=None):
 olts=olts if olts is not None else manager_olts();match=next((item for item in olts if str(item.get('id'))==str(olt_id)),None)
 return (match or {}).get('name') or (match or {}).get('label') or str(olt_id)
def saved_cto_distribution(node_id):
 with pg() as c,c.cursor() as q:
  require_cto(q,node_id)
  q.execute('SELECT id,node_id,name,splitter_type,olt_id,sfp,link_id,created_at,updated_at FROM cto_splitters WHERE node_id=%s',(node_id,));splitter=q.fetchone()
  if not splitter:return None
  splitter=dict(splitter);splitter['created_at']=splitter['created_at'].isoformat();splitter['updated_at']=splitter['updated_at'].isoformat()
  q.execute("""SELECT o.id,o.output_number,o.name,o.output_kind,a.id assignment_id,a.ont_number,a.ont_name,a.serial,a.status,a.rx_power,a.vlans,a.last_collected_at,ST_Y(a.geom) latitude,ST_X(a.geom) longitude
FROM cto_splitter_outputs o LEFT JOIN cto_ont_assignments a ON a.output_id=o.id WHERE o.splitter_id=%s ORDER BY o.output_number,a.ont_number""",(splitter['id'],));rows=q.fetchall()
 outputs=[];by_id={}
 for row in rows:
  output=by_id.get(row['id'])
  if not output:
   output={'id':row['id'],'output_number':row['output_number'],'name':row['name'],'output_kind':row['output_kind'],'clients':[]};outputs.append(output);by_id[row['id']]=output
  if row['assignment_id']:
   output['clients'].append({'assignment_id':row['assignment_id'],'number':row['ont_number'],'id':row['ont_number'],'name':row['ont_name'],'serial':row['serial'],'status':row['status'],'rx_power':row['rx_power'],'vlans':row['vlans'] or [],'collected_at':row['last_collected_at'].isoformat() if row['last_collected_at'] else None,'latitude':row['latitude'],'longitude':row['longitude']})
 splitter['outputs']=outputs;return splitter
def refresh_cto_clients(splitter):
 warning=None
 if not splitter.get('olt_id') or not splitter.get('sfp'):
  splitter['pon_status']='unknown';splitter['warning']='Aguardando vínculo com uma porta GPON';return splitter
 try:data=manager_onts(splitter['olt_id'],splitter['sfp'])
 except HTTPException as error:data=None;warning=str(error.detail)
 if data:
  live={int(ont['number']):ont for ont in data.get('onts',[]) if ont.get('number') is not None}
  with pg() as c,c.cursor() as q:
   for output in splitter['outputs']:
    for client in output['clients']:
     ont=live.get(int(client['number']))
     if not ont:continue
     q.execute("UPDATE cto_ont_assignments SET ont_name=%s,serial=%s,status=%s,rx_power=%s,vlans=%s,last_collected_at=%s,updated_at=now() WHERE id=%s",(ont.get('name'),ont.get('serial'),ont.get('status'),ont.get('rx_power'),json.dumps(ont.get('vlans') or []),data.get('collected_at'),client['assignment_id']))
     client.update({'name':ont.get('name'),'serial':ont.get('serial'),'status':ont.get('status'),'rx_power':ont.get('rx_power'),'vlans':ont.get('vlans') or [],'collected_at':data.get('collected_at')})
  splitter['pon_status']=(data.get('pon') or {}).get('status');splitter['collected_at']=data.get('collected_at');splitter['olt_name']=data.get('olt_name') or data.get('olt') or manager_olt_name(splitter['olt_id'])
 splitter['warning']=warning;return splitter

@app.get('/api/olt-manager/olts')
def list_manager_olts(u=Depends(viewer)):
 return {'olts':manager_olts()}

@app.get('/api/ctos/{node_id}/pon-contexts')
def cto_contexts(node_id:int,u=Depends(viewer)):
 with pg() as c,c.cursor() as q:require_cto(q,node_id)
 olts=manager_olts();return {'contexts':cto_pon_contexts(node_id,olts),'olts':olts}

@app.get('/api/ctos/{node_id}/distribution')
def get_cto_distribution(node_id:int,u=Depends(viewer)):
 splitter=saved_cto_distribution(node_id)
 if splitter and (not splitter.get('olt_id') or not splitter.get('sfp')):
  try:
   olts=manager_olts();contexts=cto_pon_contexts(node_id,olts);matches=[context for context in contexts if context.get('suggested_olt_id') and (not splitter.get('sfp') or context['sfp']==splitter['sfp'])]
   if len(matches)==1:
    context=matches[0]
    with pg() as c,c.cursor() as q:q.execute('UPDATE cto_splitters SET olt_id=%s,sfp=%s,link_id=%s,updated_at=now() WHERE node_id=%s',(context['suggested_olt_id'],context['sfp'],context['link_id'],node_id))
    splitter=saved_cto_distribution(node_id)
  except HTTPException:pass
 with pg() as c,c.cursor() as q:q.execute("SELECT splitter_type,splitter_name FROM nodes WHERE id=%s AND kind='cto'",(node_id,));preset=q.fetchone()
 return {'splitter':refresh_cto_clients(splitter) if splitter else None,'preset':dict(preset) if preset and preset['splitter_type'] else None}

@app.put('/api/ctos/{node_id}/splitter')
def configure_cto_splitter(node_id:int,x:CtoSplitterIn,u=Depends(operator)):
 olts=manager_olts();olt=next((item for item in olts if item['id']==x.olt_id),None)
 if not olt:raise HTTPException(422,'Selecione uma OLT válida do gerenciador')
 if not any(pon.get('sfp')==x.sfp for pon in olt.get('pons',[])):raise HTTPException(422,f'A porta PON {x.sfp} não foi localizada na OLT selecionada')
 contexts=cto_pon_contexts(node_id,olts)
 if not any(c['sfp']==x.sfp and (x.link_id is None or c['link_id']==x.link_id) for c in contexts):raise HTTPException(422,'Esta CTO não possui um enlace conectado à porta GPON informada')
 count=int(x.splitter_type.split('x')[1])
 with pg() as c,c.cursor() as q:
  node=require_cto(q,node_id)
  q.execute("""INSERT INTO cto_splitters(node_id,name,splitter_type,olt_id,sfp,link_id)VALUES(%s,%s,%s,%s,%s,%s)
ON CONFLICT(node_id)DO UPDATE SET name=excluded.name,splitter_type=excluded.splitter_type,olt_id=excluded.olt_id,sfp=excluded.sfp,link_id=excluded.link_id,updated_at=now() RETURNING id""",(node_id,x.name.strip(),x.splitter_type,x.olt_id,x.sfp,x.link_id));splitter_id=q.fetchone()['id']
  q.execute('DELETE FROM cto_splitter_outputs WHERE splitter_id=%s AND output_number>%s',(splitter_id,count))
  for number in range(1,count+1):q.execute("INSERT INTO cto_splitter_outputs(splitter_id,output_number,name)VALUES(%s,%s,%s) ON CONFLICT(splitter_id,output_number)DO NOTHING",(splitter_id,number,f'Saída {number}'))
  q.execute('UPDATE nodes SET splitter_type=%s,splitter_name=%s,updated_at=now() WHERE id=%s',(x.splitter_type,x.name.strip(),node_id))
  q.execute("UPDATE links SET source_splitter_type=%s WHERE source_kind='node' AND source_id=%s",(x.splitter_type,node_id));q.execute("UPDATE links SET target_splitter_type=%s WHERE target_kind='node' AND target_id=%s",(x.splitter_type,node_id));q.execute('UPDATE link_passive_nodes SET splitter_type=%s WHERE node_id=%s',(x.splitter_type,node_id))
  sync_cto_distribution_to_netbox(q,node_id);audit(q,u,'configure_cto_splitter','node',node_id,node['name'],{'name':x.name.strip(),'splitter_type':x.splitter_type,'olt_id':x.olt_id,'sfp':x.sfp,'link_id':x.link_id})
 return {'splitter':refresh_cto_clients(saved_cto_distribution(node_id))}

@app.patch('/api/ctos/{node_id}/splitter/outputs/{output_number}')
def update_cto_output(node_id:int,output_number:int,x:CtoOutputIn,u=Depends(operator)):
 with pg() as c,c.cursor() as q:
  node=require_cto(q,node_id);q.execute("""UPDATE cto_splitter_outputs o SET name=%s,output_kind=%s,updated_at=now() FROM cto_splitters s WHERE o.splitter_id=s.id AND s.node_id=%s AND o.output_number=%s RETURNING o.id""",(x.name.strip(),x.output_kind,node_id,output_number))
  if not q.fetchone():raise HTTPException(404,'Saída do splitter não encontrada')
  sync_cto_distribution_to_netbox(q,node_id);audit(q,u,'update_cto_splitter_output','node',node_id,node['name'],{'output_number':output_number,'name':x.name.strip(),'output_kind':x.output_kind})
 return {'status':'ok'}

@app.get('/api/ctos/{node_id}/clients')
def cto_client_candidates(node_id:int,u=Depends(viewer)):
 splitter=saved_cto_distribution(node_id)
 if not splitter:raise HTTPException(422,'Configure o splitter desta CTO antes de adicionar clientes')
 if not splitter.get('olt_id') or not splitter.get('sfp'):raise HTTPException(422,'Vincule o splitter a uma porta GPON antes de adicionar clientes')
 data=manager_onts(splitter['olt_id'],splitter['sfp'])
 with pg() as c,c.cursor() as q:
  q.execute("""SELECT a.ont_number,o.output_number,o.name output_name,s.node_id FROM cto_ont_assignments a JOIN cto_splitter_outputs o ON o.id=a.output_id JOIN cto_splitters s ON s.id=o.splitter_id WHERE a.olt_id=%s AND a.sfp=%s""",(splitter['olt_id'],splitter['sfp']));assigned={int(row['ont_number']):dict(row) for row in q.fetchall()}
 for ont in data.get('onts',[]):ont['assigned']=assigned.get(int(ont['number'])) if ont.get('number') is not None else None
 return data

@app.put('/api/ctos/{node_id}/splitter/outputs/{output_number}/clients')
def save_cto_clients(node_id:int,output_number:int,x:CtoClientSelectionIn,u=Depends(operator)):
 requested=sorted(set(int(value) for value in x.ont_numbers))
 if any(value<0 for value in requested):raise HTTPException(422,'ID de ONT inválido')
 splitter=saved_cto_distribution(node_id)
 if not splitter:raise HTTPException(422,'Configure o splitter desta CTO antes de adicionar clientes')
 if not splitter.get('olt_id') or not splitter.get('sfp'):raise HTTPException(422,'Vincule o splitter a uma porta GPON antes de adicionar clientes')
 output=next((item for item in splitter['outputs'] if item['output_number']==output_number),None)
 if not output:raise HTTPException(404,'Saída do splitter não encontrada')
 data=manager_onts(splitter['olt_id'],splitter['sfp']);live={int(ont['number']):ont for ont in data.get('onts',[]) if ont.get('number') is not None}
 missing=[number for number in requested if number not in live]
 if missing:raise HTTPException(422,f"ONT(s) não localizada(s) na porta PON: {', '.join(map(str,missing[:10]))}")
 with pg() as c,c.cursor() as q:
  node=require_cto(q,node_id)
  if requested:q.execute('DELETE FROM cto_ont_assignments WHERE output_id=%s AND NOT (ont_number=ANY(%s))',(output['id'],requested))
  else:q.execute('DELETE FROM cto_ont_assignments WHERE output_id=%s',(output['id'],))
  for number in requested:
   ont=live[number];q.execute("""INSERT INTO cto_ont_assignments(output_id,olt_id,sfp,ont_number,ont_name,serial,status,rx_power,vlans,last_collected_at)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON CONFLICT(olt_id,sfp,ont_number)DO UPDATE SET output_id=excluded.output_id,ont_name=excluded.ont_name,serial=excluded.serial,status=excluded.status,rx_power=excluded.rx_power,vlans=excluded.vlans,last_collected_at=excluded.last_collected_at,updated_at=now()""",(output['id'],splitter['olt_id'],splitter['sfp'],number,ont.get('name'),ont.get('serial'),ont.get('status'),ont.get('rx_power'),json.dumps(ont.get('vlans') or []),data.get('collected_at')))
  if requested:q.execute("UPDATE cto_splitter_outputs SET output_kind='customers',updated_at=now() WHERE id=%s",(output['id'],))
  sync_cto_distribution_to_netbox(q,node_id);audit(q,u,'assign_cto_clients','node',node_id,node['name'],{'output_number':output_number,'client_count':len(requested),'ont_numbers':requested})
 return {'status':'ok','count':len(requested)}

@app.get('/api/ont-map-clients')
def ont_map_clients(u=Depends(viewer)):
 try:olt_names={str(item.get('id')):item.get('name') or item.get('label') or str(item.get('id')) for item in manager_olts()}
 except HTTPException:olt_names={}
 with pg() as c,c.cursor() as q:q.execute('SELECT DISTINCT olt_id,sfp FROM cto_ont_assignments WHERE geom IS NOT NULL');pons=q.fetchall()
 for pon in pons:
  try:data=manager_onts(pon['olt_id'],pon['sfp'])
  except HTTPException:continue
  live={int(ont['number']):ont for ont in data.get('onts',[]) if ont.get('number') is not None}
  with pg() as c,c.cursor() as q:
   for number,ont in live.items():q.execute('UPDATE cto_ont_assignments SET ont_name=%s,serial=%s,status=%s,rx_power=%s,vlans=%s,last_collected_at=%s,updated_at=now() WHERE olt_id=%s AND sfp=%s AND ont_number=%s',(ont.get('name'),ont.get('serial'),ont.get('status'),ont.get('rx_power'),json.dumps(ont.get('vlans') or []),data.get('collected_at'),pon['olt_id'],pon['sfp'],number))
 with pg() as c,c.cursor() as q:
  q.execute("""SELECT a.id assignment_id,s.node_id,n.name cto_name,ST_Y(n.geom) cto_latitude,ST_X(n.geom) cto_longitude,
s.name splitter_name,s.splitter_type,s.olt_id,s.sfp,o.output_number,o.name output_name,a.ont_number,a.ont_name,a.serial,a.status,a.rx_power,a.vlans,a.last_collected_at,ST_Y(a.geom) latitude,ST_X(a.geom) longitude
FROM cto_ont_assignments a JOIN cto_splitter_outputs o ON o.id=a.output_id JOIN cto_splitters s ON s.id=o.splitter_id JOIN nodes n ON n.id=s.node_id
WHERE a.geom IS NOT NULL ORDER BY n.name,o.output_number,a.ont_number""");rows=q.fetchall()
 return [{**dict(row),'olt_name':olt_names.get(str(row['olt_id']),str(row['olt_id'])),'last_collected_at':row['last_collected_at'].isoformat() if row['last_collected_at'] else None} for row in rows]

@app.post('/api/alert-acknowledgements/sync')
def sync_alert_acknowledgements(x:AlertAckSyncIn,u=Depends(viewer)):
 active=list(dict.fromkeys(key for key in x.active_keys if key and len(key)<=200))
 with pg() as c,c.cursor() as q:
  if active:q.execute("DELETE FROM notification_acknowledgements WHERE user_id=%s AND alert_key LIKE 'link:%%' AND NOT (alert_key=ANY(%s))",(u['id'],active))
  else:q.execute("DELETE FROM notification_acknowledgements WHERE user_id=%s AND alert_key LIKE 'link:%%'",(u['id'],))
  q.execute('SELECT alert_key FROM notification_acknowledgements WHERE user_id=%s AND alert_key=ANY(%s)',(u['id'],active or ['']));acks=[row['alert_key'] for row in q.fetchall()]
 return {'acknowledged':acks}

@app.post('/api/alert-acknowledgements')
def acknowledge_alert(x:AlertAckIn,u=Depends(viewer)):
 with pg() as c,c.cursor() as q:
  q.execute('INSERT INTO notification_acknowledgements(user_id,alert_key)VALUES(%s,%s) ON CONFLICT(user_id,alert_key)DO UPDATE SET acknowledged_at=now()',(u['id'],x.alert_key));audit(q,u,'acknowledge_alert','notification',None,x.alert_key)
 return {'status':'acknowledged'}

@app.patch('/api/cto-clients/{assignment_id}/position')
def position_cto_client(assignment_id:int,p:PositionIn,u=Depends(operator)):
 with pg() as c,c.cursor() as q:
  q.execute("""UPDATE cto_ont_assignments a SET geom=ST_SetSRID(ST_MakePoint(%s,%s),4326),updated_at=now() FROM cto_splitter_outputs o,cto_splitters s,nodes n
WHERE a.id=%s AND o.id=a.output_id AND s.id=o.splitter_id AND n.id=s.node_id RETURNING a.id,a.ont_number,a.ont_name,n.id node_id,n.name cto_name,o.output_number,o.name output_name""",(p.longitude,p.latitude,assignment_id));row=q.fetchone()
  if not row:raise HTTPException(404,'Cliente da CTO não encontrado')
  audit(q,u,'position_cto_client','node',row['node_id'],row['cto_name'],{'assignment_id':assignment_id,'ont_number':row['ont_number'],'ont_name':row['ont_name'],'output_number':row['output_number'],'output_name':row['output_name'],'latitude':p.latitude,'longitude':p.longitude})
 return {'status':'ok','assignment_id':assignment_id,'latitude':p.latitude,'longitude':p.longitude}

@app.get('/api/nodes')
def nodes(u=Depends(viewer)):
 with pg() as c,c.cursor() as q:q.execute('SELECT id,name,kind,ST_Y(geom) latitude,ST_X(geom) longitude,netbox_device_id,netbox_sync_error,splitter_type,splitter_name FROM nodes ORDER BY name');return q.fetchall()
@app.post('/api/nodes',status_code=201)
def create_node(n:NodeIn,u=Depends(operator)):
 with pg() as c,c.cursor() as q:
  if n.kind=='host' and n.site_id is None:raise HTTPException(422,'Selecione o POP deste host')
  latitude,longitude=n.latitude,n.longitude
  if n.kind=='host':
   try:site=netbox_site(n.site_id);latitude=float(site['latitude']);longitude=float(site['longitude'])
   except Exception as e:raise HTTPException(502,f'Não foi possível consultar o POP no NetBox: {e}')
  splitter_type=n.splitter_type if n.kind=='cto' else None;splitter_name=(n.splitter_name or f'Splitter {n.name}').strip() if splitter_type else None
  q.execute('INSERT INTO nodes(name,kind,geom,splitter_type,splitter_name)VALUES(%s,%s,ST_SetSRID(ST_MakePoint(%s,%s),4326),%s,%s) RETURNING id',(n.name,n.kind,longitude,latitude,splitter_type,splitter_name));nid=q.fetchone()['id'];node={'id':nid,'name':n.name,'kind':n.kind,'latitude':latitude,'longitude':longitude,'splitter_type':splitter_type,'splitter_name':splitter_name}
  if splitter_type:
   q.execute('INSERT INTO cto_splitters(node_id,name,splitter_type)VALUES(%s,%s,%s) RETURNING id',(nid,splitter_name,splitter_type));splitter_id=q.fetchone()['id']
   for number in range(1,int(splitter_type.split('x')[1])+1):q.execute('INSERT INTO cto_splitter_outputs(splitter_id,output_number,name)VALUES(%s,%s,%s)',(splitter_id,number,f'Saída {number}'))
  try:device=sync_node_to_netbox(node,n.site_id)
  except Exception as e:raise HTTPException(502,f'Não foi possível compartilhar o registro no NetBox: {e}')
  q.execute('UPDATE nodes SET netbox_device_id=%s,netbox_sync_error=NULL WHERE id=%s',(device['id'],nid));audit(q,u,'create_node','node',nid,n.name,{'kind':n.kind,'site_id':n.site_id,'latitude':latitude,'longitude':longitude,'netbox_device_id':device['id'],'splitter_type':splitter_type,'splitter_name':splitter_name});return {'id':nid,'netbox_device_id':device['id'],'netbox_site':(device.get('site') or {}).get('name'),'splitter_type':splitter_type,'splitter_name':splitter_name}

@app.delete('/api/nodes/{node_id}')
def delete_node(node_id:int,u=Depends(operator)):
 with pg() as c,c.cursor() as q:
  q.execute('SELECT id,name,kind,netbox_device_id FROM nodes WHERE id=%s',(node_id,));node=q.fetchone()
  if not node:raise HTTPException(404,'Elemento não encontrado')
  if node['kind']!='cto':raise HTTPException(422,'Esta operação de exclusão está disponível somente para CTOs')
  if node['netbox_device_id']:
   try:nbrequest('DELETE',f"/api/dcim/devices/{node['netbox_device_id']}/")
   except httpx.HTTPStatusError as e:
    if e.response.status_code!=404:raise HTTPException(502,f'Não foi possível excluir a CTO no NetBox: {e}')
  q.execute("SELECT id FROM links WHERE (source_kind='node' AND source_id=%s) OR (target_kind='node' AND target_id=%s)",(node_id,node_id));link_ids=[r['id'] for r in q.fetchall()]
  if link_ids:q.execute("DELETE FROM issues WHERE target_kind='link' AND target_id=ANY(%s)",(link_ids,))
  q.execute("DELETE FROM issues WHERE target_kind='node' AND target_id=%s",(node_id,))
  q.execute("DELETE FROM links WHERE (source_kind='node' AND source_id=%s) OR (target_kind='node' AND target_id=%s)",(node_id,node_id))
  removed_links=q.rowcount;q.execute('DELETE FROM nodes WHERE id=%s',(node_id,));audit(q,u,'delete_cto','node',node_id,node['name'],{'removed_links':removed_links,'netbox_device_id':node['netbox_device_id']})
 return {'status':'ok','name':node['name'],'removed_links':removed_links}

@app.delete('/api/devices/{device_id}')
def delete_device(device_id:int,u=Depends(operator)):
 try:device=nbrequest('GET',f'/api/dcim/devices/{device_id}/')
 except httpx.HTTPStatusError as e:
  if e.response.status_code==404:raise HTTPException(404,'Host não encontrado no NetBox')
  raise HTTPException(502,f'Não foi possível consultar o host no NetBox: {e}')
 zabbix_match=re.search(r'Zabbix host ID:\s*(\d+)',device.get('comments') or '')
 try:nbrequest('DELETE',f'/api/dcim/devices/{device_id}/')
 except Exception as e:raise HTTPException(502,f'Não foi possível excluir o host no NetBox: {e}')
 if zabbix_match:
  try:license_active_host('release',zabbix_match.group(1),device['name'])
  except HTTPException:pass
 with pg() as c,c.cursor() as q:
  q.execute("SELECT id FROM links WHERE (source_kind='device' AND source_id=%s) OR (target_kind='device' AND target_id=%s)",(device_id,device_id));link_ids=[r['id'] for r in q.fetchall()]
  if link_ids:q.execute("DELETE FROM issues WHERE target_kind='link' AND target_id=ANY(%s)",(link_ids,))
  q.execute("DELETE FROM issues WHERE target_kind='device' AND target_id=%s",(device_id,))
  q.execute("DELETE FROM links WHERE (source_kind='device' AND source_id=%s) OR (target_kind='device' AND target_id=%s)",(device_id,device_id));removed_links=q.rowcount
  q.execute("DELETE FROM element_positions WHERE element_kind='device' AND element_id=%s",(device_id,));audit(q,u,'delete_host','device',device_id,device['name'],{'removed_links':removed_links})
 return {'status':'ok','name':device['name'],'removed_links':removed_links}

@app.post('/api/admin/sync-netbox-nodes')
def sync_netbox_nodes(u=Depends(superadmin)):
 results=[]
 with pg() as c,c.cursor() as q:
  q.execute('SELECT id,name,kind,ST_Y(geom) latitude,ST_X(geom) longitude,netbox_device_id FROM nodes ORDER BY id')
  for node in q.fetchall():
   if node['netbox_device_id']:continue
   try:
    device=sync_node_to_netbox(node);q.execute('UPDATE nodes SET netbox_device_id=%s,netbox_sync_error=NULL WHERE id=%s',(device['id'],node['id']));results.append({'id':node['id'],'status':'synced','netbox_device_id':device['id']})
   except Exception as e:q.execute('UPDATE nodes SET netbox_sync_error=%s WHERE id=%s',(str(e)[:1000],node['id']));results.append({'id':node['id'],'status':'error','error':str(e)})
  audit(q,u,'sync_netbox_nodes','system',None,None,{'processed':len(results),'synced':sum(1 for r in results if r['status']=='synced'),'errors':sum(1 for r in results if r['status']=='error')})
 return results

@app.put('/api/elements/{kind}/{element_id}/position')
def move_element(kind:str,element_id:int,p:PositionIn,u=Depends(operator)):
 if kind not in ('device','node'):raise HTTPException(422,'Tipo de elemento inválido')
 point=(p.longitude,p.latitude)
 with pg() as c,c.cursor() as q:
  if kind=='node':
   q.execute('SELECT netbox_device_id FROM nodes WHERE id=%s',(element_id,));node=q.fetchone()
   if not node:raise HTTPException(404,'Elemento não encontrado')
   if node['netbox_device_id']:
    try:nbrequest('PATCH',f"/api/dcim/devices/{node['netbox_device_id']}/",{'latitude':round(p.latitude,6),'longitude':round(p.longitude,6)})
    except Exception as e:raise HTTPException(502,f'Não foi possível atualizar as coordenadas no NetBox: {e}')
   q.execute('UPDATE nodes SET geom=ST_SetSRID(ST_MakePoint(%s,%s),4326),updated_at=now() WHERE id=%s',(*point,element_id))
  else:
   try:device=nbrequest('GET',f'/api/dcim/devices/{element_id}/');site=netbox_site((device.get('site') or {}).get('id'))
   except Exception as e:raise HTTPException(502,f'Não foi possível consultar o POP do host: {e}')
   lat1,lon1=math.radians(float(site['latitude'])),math.radians(float(site['longitude']));lat2,lon2=math.radians(p.latitude),math.radians(p.longitude)
   distance=6371000*2*math.asin(math.sqrt(math.sin((lat2-lat1)/2)**2+math.cos(lat1)*math.cos(lat2)*math.sin((lon2-lon1)/2)**2))
   if distance>50:raise HTTPException(422,f'O host deve permanecer a até 50 metros do POP {site["name"]}. O deslocamento solicitado foi de {distance:.0f} m.')
   q.execute("INSERT INTO element_positions(element_kind,element_id,geom)VALUES('device',%s,ST_SetSRID(ST_MakePoint(%s,%s),4326)) ON CONFLICT(element_kind,element_id)DO UPDATE SET geom=excluded.geom,updated_at=now()",(element_id,*point))
  q.execute("UPDATE links SET geom=ST_SetPoint(geom,0,ST_SetSRID(ST_MakePoint(%s,%s),4326)),updated_at=now() WHERE source_kind=%s AND source_id=%s",(*point,kind,element_id))
  q.execute("UPDATE links SET geom=ST_SetPoint(geom,ST_NPoints(geom)-1,ST_SetSRID(ST_MakePoint(%s,%s),4326)),updated_at=now() WHERE target_kind=%s AND target_id=%s",(*point,kind,element_id));audit(q,u,'move_element',kind,element_id,None,{'latitude':p.latitude,'longitude':p.longitude})
 return {'status':'ok'}

def rows():
 with pg() as c,c.cursor() as q:q.execute('SELECT *,ST_AsGeoJSON(geom) geometry,ST_Length(geom::geography) length_m FROM links ORDER BY id');return q.fetchall()
def link_interface_states(host_id):
 sql="SELECT itemid,name,key_ FROM items WHERE hostid=%s AND status=0 AND flags<>2 AND ((name LIKE 'Interface %%' AND(key_ LIKE 'net.if.status%%' OR key_ LIKE 'net.if.in%%' OR key_ LIKE 'net.if.out%%')) OR key_ LIKE 'ramal.status[%%]')"
 with closing(zconn()) as c,c.cursor() as q:q.execute(sql,(host_id,));rows=q.fetchall()
 groups={};pon_status=[]
 for r in rows:
  if r['key_'].startswith('ramal.status'):
   pm=re.search(r'ramal\.status\[[^.\]]+\.(GPON\s+[^\]]+)\]',r['key_'],re.I)
   if pm:pon_status.append((pm.group(1).strip(),int(r['itemid'])))
   continue
  m=re.match(r'^Interface\s+(.+?)(?:\((.*?)\))?:\s*(.+)$',r['name'],re.I)
  if not m:continue
  iface,_,_=m.groups();km=re.search(r'\[([^\]]+)\]',r['key_']);idx=km.group(1).split('.')[-1] if km else iface;g=groups.setdefault((iface,idx),{'name':iface,'status_itemid':None,'rx_itemid':None,'tx_itemid':None})
  if r['key_'].startswith('net.if.status'):g['status_itemid']=int(r['itemid'])
  elif r['key_'].startswith('net.if.in'):g['rx_itemid']=int(r['itemid'])
  else:g['tx_itemid']=int(r['itemid'])
 for iface,itemid in pon_status:
  for g in groups.values():
   if g['name'].lower()==iface.lower():g['status_itemid']=itemid
 vals=latest_details([i for g in groups.values() for i in (g['status_itemid'],g['rx_itemid'],g['tx_itemid']) if i]);now=int(datetime.now(timezone.utc).timestamp())
 for g in groups.values():
  sv=vals.get(g['status_itemid']) if g['status_itemid'] else None;traffic=[vals.get(i) for i in (g['rx_itemid'],g['tx_itemid']) if i and vals.get(i)]
  g['status']='up' if sv and sv['value']==1 else 'down' if sv and sv['value'] in (2,6,7) else 'up' if not sv and traffic and max(x['clock'] for x in traffic)>=now-900 else 'unknown'
 return list(groups.values())
@app.get('/api/links')
def links(u=Depends(viewer)):
 rs=rows();host_ids={int(r[k]) for r in rs for k in ('source_zabbix_hostid','target_zabbix_hostid') if r[k]};interface_cache={}
 with pg() as c,c.cursor() as q:
  q.execute("SELECT pn.link_id,n.id,n.name,n.kind,pn.position_fraction,pn.splitter_type FROM link_passive_nodes pn JOIN nodes n ON n.id=pn.node_id ORDER BY pn.link_id,pn.position_fraction,pn.created_at")
  passive_by_link={}
  for item in q.fetchall():passive_by_link.setdefault(item['link_id'],[]).append({'id':item['id'],'name':item['name'],'kind':item['kind'],'position_fraction':item['position_fraction'],'splitter_type':item['splitter_type']})
 for hid in host_ids:
  try:interface_cache[hid]=link_interface_states(hid)
  except:interface_cache[hid]=[]
 statuses={}
 endpoint_values={}
 for r in rs:
  endpoint_states=[]
  for side in ('source','target'):
   hid=r[f'{side}_zabbix_hostid'];itemid=r[f'{side}_interface_itemid'];name=r[f'{side}_interface_name']
   if not hid:continue
   candidates=interface_cache.get(int(hid),[]);match=next((x for x in candidates if itemid and x['status_itemid'] and int(x['status_itemid'])==int(itemid)),None) or next((x for x in candidates if x['name']==name),None)
   endpoint_states.append(match['status'] if match else 'unknown')
  endpoint_values[r['id']]=endpoint_states
  statuses[r['id']]='down' if 'down' in endpoint_states else 'up' if endpoint_states and all(v=='up' for v in endpoint_states) else 'unknown'
 # CTOs são passivas: todos os trechos conectados por elas usam as interfaces
 # monitoradas existentes no caminho, sem transformar o estado em "desconhecido".
 adjacent={r['id']:set() for r in rs};by_passive={}
 for r in rs:
  for side in ('source','target'):
   if r[f'{side}_kind']=='node':by_passive.setdefault(r[f'{side}_id'],set()).add(r['id'])
  if r['parent_link_id'] in adjacent:adjacent[r['id']].add(r['parent_link_id']);adjacent[r['parent_link_id']].add(r['id'])
 for link_ids in by_passive.values():
  for a in link_ids:adjacent[a].update(link_ids-{a})
 visited=set()
 for lid in adjacent:
  if lid in visited:continue
  stack=[lid];component=[];values=[];visited.add(lid)
  while stack:
   current=stack.pop();component.append(current);values.extend(endpoint_values[current])
   for nxt in adjacent[current]:
    if nxt not in visited:visited.add(nxt);stack.append(nxt)
  if values:
   inherited_state='down' if 'down' in values else 'up' if all(v=='up' for v in values) else 'unknown'
   for current in component:
    # Um enlace que possui interface monitorada tem estado próprio. A herança
    # existe somente para os trechos totalmente passivos (por exemplo, depois
    # de uma CTO), evitando que um DOWN vizinho contamine duas pontas UP.
    if not endpoint_values[current]:statuses[current]=inherited_state
 out=[]
 for r in rs:
  d=dict(r);d['geometry']=json.loads(d['geometry']);d['status']=statuses[r['id']];d['passive_nodes']=passive_by_link.get(r['id'],[]);d['created_at']=d['created_at'].isoformat();d['updated_at']=d['updated_at'].isoformat();out.append(d)
 return out
def valid(cs):
 if len(cs)<2 or any(len(c)!=2 or not -180<=c[0]<=180 or not -90<=c[1]<=90 for c in cs):raise HTTPException(422,'Geometria inválida')
@app.post('/api/links',status_code=201)
def create_link(x:LinkIn,u=Depends(operator)):
 valid(x.coordinates);geo=json.dumps({'type':'LineString','coordinates':x.coordinates});s=x.source;t=x.target
 with pg() as c,c.cursor() as q:
  q.execute("""INSERT INTO links(name,source_kind,source_id,source_name,source_zabbix_hostid,source_interface_itemid,source_interface_name,source_interface_description,source_splitter_type,target_kind,target_id,target_name,target_zabbix_hostid,target_interface_itemid,target_interface_name,target_interface_description,target_splitter_type,parent_link_id,geom,route_mode,trunk_group,is_trunk)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,ST_SetSRID(ST_GeomFromGeoJSON(%s),4326),%s,%s,%s)RETURNING id""",(x.name,s.kind,s.id,s.name,s.zabbix_hostid,s.interface_itemid,s.interface_name,s.interface_description,s.splitter_type,t.kind,t.id,t.name,t.zabbix_hostid,t.interface_itemid,t.interface_name,t.interface_description,t.splitter_type,x.parent_link_id,geo,x.route_mode,x.trunk_group,x.is_trunk));lid=q.fetchone()['id'];audit(q,u,'create_link','link',lid,x.name,{'source':s.name,'target':t.name,'route_mode':x.route_mode,'trunk':x.is_trunk,'source_splitter':s.splitter_type,'target_splitter':t.splitter_type});return {'id':lid}

@app.post('/api/links/bulk',status_code=201)
def create_links_bulk(batch:LinkBatchIn,u=Depends(operator)):
 ids=[]
 with pg() as c,c.cursor() as q:
  for x in batch.links:
   valid(x.coordinates);s=x.source;t=x.target;geo=json.dumps({'type':'LineString','coordinates':x.coordinates})
   q.execute("""INSERT INTO links(name,source_kind,source_id,source_name,source_zabbix_hostid,source_interface_itemid,source_interface_name,source_interface_description,source_splitter_type,target_kind,target_id,target_name,target_zabbix_hostid,target_interface_itemid,target_interface_name,target_interface_description,target_splitter_type,parent_link_id,geom,route_mode,trunk_group,is_trunk)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,ST_SetSRID(ST_GeomFromGeoJSON(%s),4326),%s,%s,%s)RETURNING id""",(x.name,s.kind,s.id,s.name,s.zabbix_hostid,s.interface_itemid,s.interface_name,s.interface_description,s.splitter_type,t.kind,t.id,t.name,t.zabbix_hostid,t.interface_itemid,t.interface_name,t.interface_description,t.splitter_type,x.parent_link_id,geo,x.route_mode,x.trunk_group,x.is_trunk));lid=q.fetchone()['id'];ids.append(lid);audit(q,u,'create_link','link',lid,x.name,{'source':s.name,'target':t.name,'route_mode':x.route_mode,'batch':True,'trunk_group':x.trunk_group,'is_trunk':x.is_trunk,'source_splitter':s.splitter_type,'target_splitter':t.splitter_type})
 return {'ids':ids,'count':len(ids)}
@app.post('/api/links/{lid}/lags',status_code=201)
def insert_link_lags(lid:int,x:LinkLagsIn,u=Depends(operator)):
 with pg() as c,c.cursor() as q:
  q.execute('SELECT * FROM links WHERE id=%s FOR UPDATE',(lid,));link=q.fetchone()
  if not link:raise HTTPException(404,'Enlace não encontrado')
  if not link['source_zabbix_hostid'] or not link['target_zabbix_hostid']:raise HTTPException(422,'Os dois extremos do enlace precisam ser hosts ativos do Zabbix')
  group=link['trunk_group'] or f'eth-{lid}'
  seen=set()
  for member in x.members:
   s=member.source;t=member.target
   if s.kind!='device' or s.id!=link['source_id'] or s.zabbix_hostid!=link['source_zabbix_hostid']:raise HTTPException(422,'As LAGs precisam pertencer ao host de origem da Trunk')
   if not s.interface_name or not s.interface_itemid:raise HTTPException(422,'Selecione uma interface monitorada para cada LAG')
   key=s.interface_itemid
   if key in seen:raise HTTPException(422,'Não repita o mesmo pareamento de LAG')
   seen.add(key)
  q.execute('UPDATE links SET trunk_group=%s,is_trunk=true,updated_at=now() WHERE id=%s',(group,lid))
  ids=[]
  for member in x.members:
   s=member.source;t=member.target or Endpoint(kind=link['target_kind'],id=link['target_id'],name=link['target_name'],zabbix_hostid=link['target_zabbix_hostid'],interface_itemid=link['target_interface_itemid'],interface_name=link['target_interface_name'],interface_description=link['target_interface_description'])
   q.execute("""INSERT INTO links(name,source_kind,source_id,source_name,source_zabbix_hostid,source_interface_itemid,source_interface_name,source_interface_description,target_kind,target_id,target_name,target_zabbix_hostid,target_interface_itemid,target_interface_name,target_interface_description,parent_link_id,geom,route_mode,trunk_group,is_trunk)
   SELECT %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,parent_link_id,geom,route_mode,%s,false FROM links WHERE id=%s RETURNING id""",(f"{link['name']} · LAG {s.interface_name} → {t.interface_name}",s.kind,s.id,s.name,s.zabbix_hostid,s.interface_itemid,s.interface_name,s.interface_description,t.kind,t.id,t.name,t.zabbix_hostid,t.interface_itemid,t.interface_name,t.interface_description,group,lid));ids.append(q.fetchone()['id'])
  audit(q,u,'insert_trunk_lags','link',lid,link['name'],{'trunk_group':group,'lag_links':ids,'count':len(ids)})
 return {'trunk_link_id':lid,'lag_link_ids':ids,'count':len(ids)}
@app.put('/api/links/{lid}')
def update_link(lid:int,x:LinkGeometry,u=Depends(operator)):
 valid(x.coordinates);geo=json.dumps({'type':'LineString','coordinates':x.coordinates})
 with pg() as c,c.cursor() as q:
  q.execute('UPDATE links SET geom=ST_SetSRID(ST_GeomFromGeoJSON(%s),4326),updated_at=now() WHERE id=%s',(geo,lid))
  if not q.rowcount:raise HTTPException(404,'Enlace não encontrado')
  audit(q,u,'update_link_route','link',lid,None,{'points':len(x.coordinates)})
 return {'status':'ok'}
@app.patch('/api/links/{lid}/name')
def rename_link(lid:int,x:LinkNameIn,u=Depends(operator)):
 with pg() as c,c.cursor() as q:
  q.execute('UPDATE links SET name=%s,updated_at=now() WHERE id=%s',(x.name.strip(),lid))
  if not q.rowcount:raise HTTPException(404,'Enlace não encontrado')
  audit(q,u,'rename_link','link',lid,x.name.strip())
 return {'status':'ok','name':x.name.strip()}
@app.patch('/api/links/{lid}/interface/{side}')
def replace_link_interface(lid:int,side:str,x:LinkInterfaceIn,u=Depends(operator)):
 if side not in ('source','target'):raise HTTPException(422,'Ponta do enlace inválida')
 with pg() as c,c.cursor() as q:
  q.execute(f'SELECT {side}_zabbix_hostid hostid FROM links WHERE id=%s',(lid,));link=q.fetchone()
  if not link:raise HTTPException(404,'Enlace não encontrado')
  if not link['hostid']:raise HTTPException(422,'Esta ponta não possui um host monitorado no Zabbix')
  q.execute(f'UPDATE links SET {side}_interface_itemid=%s,{side}_interface_name=%s,{side}_interface_description=%s,updated_at=now() WHERE id=%s',(x.interface_itemid,x.interface_name,x.interface_description,lid));audit(q,u,'replace_link_interface','link',lid,None,{'side':side,'interface_itemid':x.interface_itemid,'interface_name':x.interface_name})
 return {'status':'ok'}
@app.post('/api/links/{lid}/insert-cto',status_code=201)
def insert_cto_in_link(lid:int,x:LinkCtoIn,u=Depends(operator)):
 with pg() as c,c.cursor() as q:
  q.execute('SELECT *,ST_LineLocatePoint(geom,ST_SetSRID(ST_MakePoint(%s,%s),4326)) fraction FROM links WHERE id=%s FOR UPDATE',(x.longitude,x.latitude,lid));link=q.fetchone()
  if not link:raise HTTPException(404,'Enlace não encontrado')
  fraction=float(link['fraction'])
  if fraction<=0.000001 or fraction>=0.999999:raise HTTPException(422,'Escolha um ponto interno do enlace, afastado das extremidades')
  q.execute('SELECT ST_X(p) longitude,ST_Y(p) latitude FROM (SELECT ST_LineInterpolatePoint(%s::geometry,%s) p)s',(link['geom'],fraction));split=q.fetchone()
  splitter_name=f'Splitter {x.name.strip()}' if x.splitter_type else None
  q.execute("INSERT INTO nodes(name,kind,geom,splitter_type,splitter_name)VALUES(%s,'cto',ST_SetSRID(ST_MakePoint(%s,%s),4326),%s,%s) RETURNING id",(x.name.strip(),split['longitude'],split['latitude'],x.splitter_type,splitter_name));nid=q.fetchone()['id'];node={'id':nid,'name':x.name.strip(),'kind':'cto','latitude':split['latitude'],'longitude':split['longitude'],'splitter_type':x.splitter_type,'splitter_name':splitter_name}
  if x.splitter_type:
   input_name=link[f'{x.input_side}_interface_name'] if x.input_side else None;sfp=pon_sfp(input_name)
   q.execute('INSERT INTO cto_splitters(node_id,name,splitter_type,sfp,link_id)VALUES(%s,%s,%s,%s,%s) RETURNING id',(nid,splitter_name,x.splitter_type,sfp,lid));splitter_id=q.fetchone()['id']
   for number in range(1,int(x.splitter_type.split('x')[1])+1):q.execute('INSERT INTO cto_splitter_outputs(splitter_id,output_number,name)VALUES(%s,%s,%s)',(splitter_id,number,f'Saída {number}'))
  try:device=sync_node_to_netbox(node)
  except Exception as e:raise HTTPException(502,f'Não foi possível compartilhar a CTO no NetBox: {e}')
  q.execute('UPDATE nodes SET netbox_device_id=%s,netbox_sync_error=NULL WHERE id=%s',(device['id'],nid))
  q.execute('INSERT INTO link_passive_nodes(link_id,node_id,position_fraction,splitter_type,input_side)VALUES(%s,%s,%s,%s,%s)',(lid,nid,fraction,x.splitter_type,x.input_side));audit(q,u,'insert_cto_in_link','node',nid,x.name.strip(),{'link_id':lid,'netbox_device_id':device['id'],'position_fraction':fraction,'splitter_type':x.splitter_type,'input_side':x.input_side})
 return {'node_id':nid,'link_id':lid,'latitude':split['latitude'],'longitude':split['longitude'],'netbox_device_id':device['id']}
@app.delete('/api/links/{lid}',status_code=204)
def delete_link(lid:int,u=Depends(superadmin)):
 with pg() as c,c.cursor() as q:
  q.execute('SELECT name FROM links WHERE id=%s',(lid,));link=q.fetchone()
  if not link:raise HTTPException(404,'Enlace não encontrado')
  q.execute('DELETE FROM links WHERE id=%s',(lid,));audit(q,u,'delete_link','link',lid,link['name'])

@app.get('/api/issues')
def list_issues(status:str|None=None,u=Depends(viewer)):
 where='WHERE i.status=%s' if status else '';args=(status,) if status else ()
 with pg() as c,c.cursor() as q:
  q.execute(f"""SELECT i.id,i.target_kind,i.target_id,i.target_name,i.severity,i.description,i.status,i.latitude,i.longitude,i.created_at,i.validated_at,i.resolved_at,ru.display_name reported_by_name,vu.display_name validated_by_name FROM issues i JOIN users ru ON ru.id=i.reported_by LEFT JOIN users vu ON vu.id=i.validated_by {where} ORDER BY CASE i.status WHEN 'pending' THEN 0 WHEN 'validated' THEN 1 ELSE 2 END,i.created_at DESC""",args);return q.fetchall()
@app.post('/api/issues',status_code=201)
def report_issue(x:IssueIn,u=Depends(viewer)):
 if (x.latitude is None)!=(x.longitude is None):raise HTTPException(422,'Informe latitude e longitude juntas')
 if x.target_kind=='link' and x.latitude is None:raise HTTPException(422,'Clique no ponto exato do enlace antes de reportar o erro')
 status='validated' if u['role'] in ('admin','superadmin') else 'pending';validated_by=u['id'] if status=='validated' else None;validated_at=datetime.now(timezone.utc) if status=='validated' else None
 with pg() as c,c.cursor() as q:q.execute("""INSERT INTO issues(target_kind,target_id,target_name,severity,description,status,reported_by,validated_by,validated_at,latitude,longitude)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)RETURNING id""",(x.target_kind,x.target_id,x.target_name,x.severity,x.description,status,u['id'],validated_by,validated_at,x.latitude,x.longitude));iid=q.fetchone()['id'];audit(q,u,'report_issue','issue',iid,x.target_name,{'target_kind':x.target_kind,'target_id':x.target_id,'severity':x.severity,'status':status,'latitude':x.latitude,'longitude':x.longitude});return {'id':iid,'status':status}
@app.post('/api/issues/{issue_id}/validate')
def validate_issue(issue_id:int,u=Depends(operator)):
 with pg() as c,c.cursor() as q:
  q.execute("UPDATE issues SET status='validated',validated_by=%s,validated_at=now() WHERE id=%s AND status='pending'",(u['id'],issue_id))
  if not q.rowcount:raise HTTPException(404,'Erro pendente não encontrado')
  audit(q,u,'validate_issue','issue',issue_id)
 return {'status':'validated'}
@app.post('/api/issues/{issue_id}/resolve')
def resolve_issue(issue_id:int,u=Depends(operator)):
 with pg() as c,c.cursor() as q:
  q.execute("UPDATE issues SET status='resolved',resolved_at=now() WHERE id=%s AND status IN('pending','validated')",(issue_id,))
  if not q.rowcount:raise HTTPException(404,'Erro aberto não encontrado')
  audit(q,u,'resolve_issue','issue',issue_id)
 return {'status':'resolved'}
@app.get('/',response_class=HTMLResponse)
def index():
 with open('/opt/netatlas/static/index.html',encoding='utf-8') as f:return f.read()
