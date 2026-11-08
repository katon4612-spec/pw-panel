#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PassWall 节点状态面板（单文件，只用 Python 自带库，无需安装任何东西）

运行：  python3 pw_panel.py
打开：  http://服务器IP:8899   （第一次运行会在终端打印登录密码，也写在 pw_panel_config.json 里）

原理：通过 frp 映射出来的每台软路由的 LuCI 后台端口，登录后台 →
      读 PassWall 配置（当前节点、节点列表）→ 调 PassWall 自带的检测接口测谷歌/百度 →
      需要时切换节点或用分享链接添加节点。路由器上不用装任何东西。
"""
import base64, http.client, json, os, re, secrets, socket, ssl, sys, threading, time, traceback
import urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE, "pw_panel_config.json")
LOCK = threading.RLock()
STATUS = {}            # router_id -> 最近一次检测结果
LAST_FULL = {"time": None, "running": False}
NETERR = (OSError, http.client.HTTPException)

DEFAULT_CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 8899,
    "panel_user": "admin",
    "panel_password": "",
    "frps": {"url": "http://202.61.72.145:6443", "user": "", "password": ""},
    "router_host": "202.61.72.145",
    "default_luci_user": "root",
    "default_luci_password": "",
    "check_interval_min": 5,
    "test_url": "https://www.google.com/generate_204",
    "notify_webhook": "",
    "telegram": {"bot_token": "", "chat_id": ""},
    "routers": [],
}


class Err(Exception):
    pass


# ---------------------------------------------------------------- 配置
def save_cfg(c):
    with LOCK:
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(c, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CONFIG_PATH)


def load_cfg():
    c = {}
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, encoding="utf-8") as f:
            c = json.load(f)
    changed = False
    for k, v in DEFAULT_CONFIG.items():
        if k not in c:
            c[k] = json.loads(json.dumps(v))
            changed = True
    if not c.get("panel_password"):
        c["panel_password"] = secrets.token_urlsafe(9)
        changed = True
    if changed:
        save_cfg(c)
    return c


CFG = load_cfg()


def get_router(rid):
    for r in CFG["routers"]:
        if r["id"] == rid:
            return r
    raise Err("找不到这个盒子")


def r_host(r):
    return (r.get("host") or CFG.get("router_host") or "").strip()


def r_url(r, app=None):
    scheme = "https" if r.get("https") else "http"
    return f"{scheme}://{r_host(r)}:{r['port']}/cgi-bin/luci/admin/services/{app or 'passwall'}"


# ---------------------------------------------------------------- HTTP 工具
def raw_req(https, host, port, method, path, body=None, headers=None, timeout=10):
    if https:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        if isinstance(body, str):
            body = body.encode("utf-8")
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        return r.status, r.getheaders(), r.read()
    finally:
        conn.close()


# ---------------------------------------------------------------- 路由器客户端
class Router:
    def __init__(self, r):
        self.r = r
        self.host = r_host(r)
        self.port = int(r["port"])
        self.https = bool(r.get("https"))
        self.user = r.get("user") or CFG.get("default_luci_user") or "root"
        self.pw = r.get("password") or CFG.get("default_luci_password") or ""
        self.sid = None
        self.cookie = "sysauth"
        self.stok = ""
        self.app = None
        self.cfg = None

    def req(self, method, path, body=None, headers=None, timeout=12):
        return raw_req(self.https, self.host, self.port, method, path, body, headers, timeout)

    def login(self):
        body = urllib.parse.urlencode({"luci_username": self.user, "luci_password": self.pw})
        st, hdrs, data = self.req("POST", "/cgi-bin/luci/", body,
                                  {"Content-Type": "application/x-www-form-urlencoded"}, timeout=12)
        for k, v in hdrs:
            kl = k.lower()
            if kl == "set-cookie" and not self.sid:
                m = re.match(r"\s*(sysauth[^=]*)=([^;]*)", v)
                if m and m.group(2) and m.group(2) != "deleted":
                    self.cookie, self.sid = m.group(1), m.group(2)
            elif kl == "location":
                m = re.search(r";stok=([0-9a-zA-Z]+)", v)
                if m:
                    self.stok = "/;stok=" + m.group(1)
        if not self.sid:
            if st == 403 or b"luci_password" in data:
                raise Err("后台登录失败：用户名或密码不对")
            raise Err(f"后台登录失败（HTTP {st}），这个端口可能不是软路由后台")
        return self

    # LuCI 里 PassWall 的接口
    def luci(self, sub, params=None, timeout=20, method="GET", data=None):
        path = f"/cgi-bin/luci{self.stok}/admin/services/{self.app or 'passwall'}/{sub}"
        if params:
            path += "?" + urllib.parse.urlencode(params)
        h = {"Cookie": f"{self.cookie}={self.sid}"}
        if data is not None:
            h["Content-Type"] = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(data)
        st, _, d = self.req(method, path, data, h, timeout=timeout)
        return st, d

    def luci_json(self, sub, params=None, timeout=20, method="GET", data=None):
        st, d = self.luci(sub, params, timeout, method, data)
        if st != 200:
            return None
        try:
            return json.loads(d.decode("utf-8", "replace"))
        except ValueError:
            return None

    def ubus(self, obj, method, args=None, timeout=15):
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "call",
                              "params": [self.sid, obj, method, args or {}]})
        st, _, d = self.req("POST", "/ubus", payload, {"Content-Type": "application/json"}, timeout=timeout)
        if st != 200:
            raise Err(f"ubus 接口不可用（HTTP {st}）")
        j = json.loads(d.decode("utf-8", "replace"))
        if "error" in j:
            raise Err("ubus 错误：" + str(j["error"].get("message")))
        res = j.get("result") or []
        if not res or res[0] != 0:
            raise Err(f"ubus {obj}.{method} 失败（代码 {res[0] if res else '?'}）")
        return res[1] if len(res) > 1 else {}

    def load_config(self):
        vals, last = None, None
        for app in ([self.app] if self.app else ["passwall", "passwall2"]):
            try:
                v = self.ubus("uci", "get", {"config": app}).get("values") or {}
            except Err as e:
                last = e
                continue
            if v:
                self.app, vals = app, v
                break
        if not vals:
            raise Err("读不到 PassWall 配置（没装 PassWall，或系统不允许读取）" + (f"：{last}" if last else ""))
        glob = next((x for x in vals.values() if x.get(".type") == "global"), {})
        nodes = []
        for sid, x in vals.items():
            if x.get(".type") == "nodes":
                nodes.append({
                    "id": sid, "remarks": x.get("remarks") or sid, "type": x.get("type", ""),
                    "protocol": x.get("protocol", ""), "address": x.get("address", ""),
                    "port": x.get("port", ""), "_i": x.get(".index", 0),
                })
        nodes.sort(key=lambda n: n.pop("_i"))
        opt = "tcp_node" if self.app == "passwall" else "node"
        self.cfg = {"app": self.app, "enabled": glob.get("enabled") == "1", "current": glob.get(opt),
                    "global_section": glob.get(".name"), "opt": opt, "nodes": nodes}
        return self.cfg

    def node(self, nid):
        for n in (self.cfg or self.load_config())["nodes"]:
            if n["id"] == nid:
                return n
        raise Err("节点不存在（可能已被删掉）")

    def connect_test(self, url, typ):
        d = self.luci_json("connect_status", {"type": typ, "url": url}, timeout=25)
        if not isinstance(d, dict):
            return {"ok": None, "ms": None}
        # 新版 PassWall 只在通的时候返回 use_time（没有 status 字段）；老版本返回 status=true
        ms = d.get("use_time")
        try:
            ms = float(ms) if ms not in (None, "") else None
        except (TypeError, ValueError):
            ms = None
        ok = bool(d.get("status")) or (ms is not None and ms > 0)
        return {"ok": ok, "ms": max(1, round(ms)) if ok and ms else None}

    def test_node(self, n):
        # 新版 PassWall：真实代理测速
        d = self.luci_json("urltest_node", {"id": n["id"]}, timeout=25)
        if isinstance(d, dict):
            try:
                ms = float(d.get("use_time")) if d.get("use_time") not in (None, "") else None
            except ValueError:
                ms = None
            return {"ok": ms is not None and ms > 0, "ms": round(ms) if ms else None, "kind": "真实"}
        # 老版本：只能测到节点服务器的 TCP 延迟
        if n.get("address") and n.get("port"):
            d = self.luci_json("ping_node", {"index": 0, "address": n["address"], "port": n["port"],
                                             "type": "tcping"}, timeout=15)
            if isinstance(d, dict):
                p = d.get("ping")
                try:
                    p = float(p) if p not in (None, "") else None
                except ValueError:
                    p = None
                return {"ok": bool(p), "ms": round(p) if p else None, "kind": "TCP"}
        return {"ok": None, "ms": None, "kind": "无法测"}

    def switch(self, nid):
        cfg = self.cfg or self.load_config()
        self.node(nid)
        done = False
        # 新版参数：type/config/section；老版 PassWall 1：protocol/section。一起带上，两种都认
        try:
            self.luci("set_node", {"type": "@global[0]", "config": cfg["opt"], "protocol": "tcp",
                                   "section": nid}, timeout=60)
            done = self.load_config()["current"] == nid
        except NETERR:
            done = False
        if not done:
            self.ubus("uci", "set", {"config": self.app, "section": cfg["global_section"],
                                     "values": {cfg["opt"]: nid}})
            self.ubus("uci", "commit", {"config": self.app})
            try:
                self.ubus("rc", "init", {"name": self.app, "action": "restart"}, timeout=60)
            except Err:
                self.ubus("file", "exec", {"command": f"/etc/init.d/{self.app}", "params": ["restart"]}, timeout=60)
            if self.load_config()["current"] != nid:
                raise Err("切换没生效，请到后台手动切换")

    def add_link(self, link):
        link = link.strip()
        if not re.match(r"^(ss|ssr|vmess|vless|trojan|hysteria2?|hy2|tuic|socks5?|https?)://\S+$", link, re.I):
            raise Err("这不像节点分享链接（应以 ss:// vmess:// vless:// trojan:// hy2:// 等开头，一次一条）")
        if "'" in link:
            raise Err("链接里不能有单引号")
        before = {n["id"] for n in (self.cfg or self.load_config())["nodes"]}
        self.luci("link_add_node", None, timeout=40, method="POST",
                  data={"link": link, "chunk": link, "chunk_index": 0, "total_chunks": 1})
        for _ in range(5):
            time.sleep(1)
            new = [n for n in self.load_config()["nodes"] if n["id"] not in before]
            if new:
                return new
        raise Err("没加上：这个 PassWall 版本可能不认这条链接，请到后台手动添加")


# ---------------------------------------------------------------- frps
def frps_fetch():
    f = CFG.get("frps") or {}
    url = (f.get("url") or "").strip()
    if not url:
        raise Err("请先在「设置」里填 frps 面板地址")
    u = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    https = u.scheme == "https"
    port = u.port or (443 if https else 80)
    h = {}
    if f.get("user") or f.get("password"):
        h["Authorization"] = "Basic " + base64.b64encode(f"{f.get('user','')}:{f.get('password','')}".encode()).decode()
    out = []
    for typ in ("tcp", "http"):
        try:
            st, _, d = raw_req(https, u.hostname, port, "GET", f"/api/proxy/{typ}", headers=h, timeout=8)
        except NETERR as e:
            raise Err(f"连不上 frps 面板：{e}")
        if st == 401:
            raise Err("frps 面板账号或密码不对")
        if st != 200:
            continue
        for p in (json.loads(d.decode("utf-8", "replace")).get("proxies") or []):
            conf = p.get("conf") or {}
            out.append({"name": p.get("name"), "type": typ,
                        "port": conf.get("remotePort") or conf.get("remote_port"),
                        "online": p.get("status") == "online"})
    return out


def frps_map():
    try:
        lst = frps_fetch()
    except Exception:
        return None
    return {"name": {p["name"]: p["online"] for p in lst},
            "port": {str(p["port"]): p["online"] for p in lst if p["port"]}}


# ---------------------------------------------------------------- 检测
def check_router(r):
    s = {"time": time.time(), "level": "error", "msg": "", "app": None, "enabled": None,
         "node_id": None, "node_name": None, "node_count": 0, "google": None, "baidu": None}
    try:
        c = Router(r).login()
    except Err as e:
        s["msg"] = str(e)
        return s
    except NETERR:
        s.update(level="offline", msg="连不上盒子后台（盒子断电/断网，或 frp 掉线）")
        return s
    try:
        cfg = c.load_config()
        s.update(app=cfg["app"], enabled=cfg["enabled"], node_id=cfg["current"], node_count=len(cfg["nodes"]))
        cur = next((n for n in cfg["nodes"] if n["id"] == cfg["current"]), None)
        s["node_name"] = cur["remarks"] if cur else (cfg["current"] or "未选择")
        s["google"] = c.connect_test(CFG.get("test_url") or DEFAULT_CONFIG["test_url"], "google")
        s["baidu"] = c.connect_test("https://www.baidu.com", "baidu")
        g, b = s["google"]["ok"], s["baidu"]["ok"]
        if g:
            s.update(level="ok", msg="")
        elif b is False:
            s.update(level="no_wan", msg="国内网站也打不开：盒子本身没网，查宽带或上级路由")
        elif not cfg["enabled"]:
            s.update(level="disabled", msg="PassWall 总开关没开")
        elif g is None:
            s.update(level="error", msg="这个 PassWall 版本不支持远程连通测试，请到后台查看")
        else:
            s.update(level="node_bad", msg="国内正常、外网不通：当前节点有问题，建议切换")
    except Err as e:
        s["msg"] = str(e)
    except NETERR:
        s.update(level="offline", msg="检测过程中连接断了")
    return s


def notify(text):
    def run():
        wh = (CFG.get("notify_webhook") or "").strip()
        if wh:  # 企业微信群机器人 / 钉钉机器人都兼容这个格式
            try:
                req = urllib.request.Request(wh, json.dumps({"msgtype": "text", "text": {"content": text}}).encode(),
                                             {"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=10).read()
            except Exception as e:
                print("webhook 通知失败:", e)
        tg = CFG.get("telegram") or {}
        if tg.get("bot_token") and tg.get("chat_id"):
            try:
                data = urllib.parse.urlencode({"chat_id": tg["chat_id"], "text": text}).encode()
                urllib.request.urlopen(f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage", data, timeout=10).read()
            except Exception as e:
                print("Telegram 通知失败:", e)
    threading.Thread(target=run, daemon=True).start()


LEVEL_TEXT = {"ok": "正常", "node_bad": "节点异常", "no_wan": "盒子没网", "disabled": "PassWall 未开",
              "offline": "离线", "error": "出错"}


def check_many(ids=None):
    routers = [r for r in CFG["routers"] if ids is None or r["id"] in ids]
    if not routers:
        return
    fm = frps_map()
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(check_router, routers))
    alerts = []
    for r, s in zip(routers, results):
        if fm is not None:
            on = fm["name"].get(r.get("frp_name")) if r.get("frp_name") in fm["name"] else fm["port"].get(str(r["port"]))
            s["frp"] = on
            if s["level"] == "offline" and on is False:
                s["msg"] = "frp 显示离线：盒子断电/断网，或盒子上的 frpc 没运行"
        prev = (STATUS.get(r["id"]) or {}).get("level")
        STATUS[r["id"]] = s
        if prev and prev != s["level"]:
            if s["level"] != "ok" and prev == "ok":
                alerts.append(f"❌ {r['name']}：{LEVEL_TEXT.get(s['level'])}。{s['msg']}")
            elif s["level"] == "ok":
                alerts.append(f"✅ {r['name']}：已恢复正常（节点 {s['node_name']}）")
    if ids is None:
        LAST_FULL["time"] = time.time()
    if alerts:
        notify("PassWall 面板提醒\n" + "\n".join(alerts))


def bg_loop():
    time.sleep(3)
    while True:
        iv = int(CFG.get("check_interval_min") or 0)
        if iv > 0 and not LAST_FULL["running"]:
            LAST_FULL["running"] = True
            try:
                check_many(None)
            except Exception:
                traceback.print_exc()
            finally:
                LAST_FULL["running"] = False
        time.sleep(max(iv, 1) * 60)


# ---------------------------------------------------------------- API
def pub_router(r):
    x = {k: v for k, v in r.items() if k != "password"}
    x["has_password"] = bool(r.get("password"))
    st = STATUS.get(r["id"])
    x["status"] = st
    x["luci_url"] = r_url(r, st and st.get("app"))
    x["host_eff"] = r_host(r)
    return x


def api_state(_=None):
    return {"routers": [pub_router(r) for r in CFG["routers"]], "last_full": LAST_FULL["time"],
            "checking": LAST_FULL["running"], "interval": CFG.get("check_interval_min")}


def api_check(b):
    if b.get("id"):
        check_many([b["id"]])
    else:
        if LAST_FULL["running"]:
            raise Err("已经在全部检测中，请稍等")
        LAST_FULL["running"] = True
        try:
            check_many(None)
        finally:
            LAST_FULL["running"] = False
    return api_state()


def client_for(b):
    try:
        return Router(get_router(b["id"])).login()
    except NETERR:
        raise Err("连不上盒子后台（盒子离线或 frp 掉线）")


def api_nodes(b):
    c = client_for(b)
    cfg = c.load_config()
    return {"app": cfg["app"], "enabled": cfg["enabled"], "current": cfg["current"], "nodes": cfg["nodes"]}


def api_test_node(b):
    c = client_for(b)
    c.load_config()
    try:
        return {"t": c.test_node(c.node(b["node"]))}
    except NETERR:
        return {"t": {"ok": False, "ms": None, "kind": "超时"}}


def api_switch(b):
    r = get_router(b["id"])
    c = client_for(b)
    try:
        c.switch(b["node"])
    except NETERR:
        raise Err("切换时连接超时，PassWall 可能还在重启，稍后点「检测」确认")
    time.sleep(2)
    check_many([r["id"]])
    return {"status": STATUS.get(r["id"])}


def api_add_link(b):
    r = get_router(b["id"])
    c = client_for(b)
    new = c.add_link(b.get("link", ""))
    res = {"added": new}
    if b.get("switch"):
        c.switch(new[0]["id"])
        time.sleep(2)
        check_many([r["id"]])
        res["status"] = STATUS.get(r["id"])
    return res


def api_autofix(b):
    r = get_router(b["id"])
    c = client_for(b)
    cfg = c.load_config()
    log = []
    url = CFG.get("test_url") or DEFAULT_CONFIG["test_url"]
    g = c.connect_test(url, "google")
    if g["ok"]:
        log.append(f"当前节点正常（{g['ms']}ms），不用换。")
        check_many([r["id"]])
        return {"fixed": True, "log": log}
    log.append("当前节点外网不通。")
    if c.connect_test("https://www.baidu.com", "baidu")["ok"] is False:
        log.append("国内网站也打不开 → 是盒子本身没网，换节点没用，请查宽带或上级路由。")
        return {"fixed": False, "log": log}
    if not cfg["enabled"]:
        log.append("PassWall 总开关没开，请到后台打开。")
        return {"fixed": False, "log": log}
    cands = [n for n in cfg["nodes"] if n["id"] != cfg["current"]]
    if not cands:
        log.append("没有备用节点 → 请点「节点」，粘贴新节点链接添加并切换。")
        return {"fixed": False, "log": log}
    tested = []
    for n in cands[:15]:
        try:
            t = c.test_node(n)
        except NETERR:
            t = {"ok": False, "ms": None, "kind": "超时"}
        log.append(f"测速 {n['remarks']}：" + (f"{t['ms']}ms" if t["ok"] else "不通"))
        if t["ok"]:
            tested.append((t["ms"] or 99999, n))
    tested.sort(key=lambda x: x[0])
    if not tested:
        log.append("所有备用节点都不通 → 请粘贴一个新节点链接添加。")
        return {"fixed": False, "log": log}
    for _, n in tested[:3]:
        log.append(f"切换到 {n['remarks']} …")
        try:
            c.switch(n["id"])
        except (Err, *NETERR) as e:
            log.append(f"切换失败：{e}")
            continue
        for _ in range(3):
            time.sleep(3)
            g = c.connect_test(url, "google")
            if g["ok"]:
                break
        if g["ok"]:
            log.append(f"✅ 已恢复，外网 {g['ms']}ms")
            check_many([r["id"]])
            return {"fixed": True, "log": log}
        log.append("切过去还是不通，试下一个。")
    check_many([r["id"]])
    log.append("自动修复没成功，请到后台手动看看。")
    return {"fixed": False, "log": log}


def api_router_save(b):
    port = str(b.get("port", "")).strip()
    if not port.isdigit():
        raise Err("端口必须是数字")
    fields = {"name": (b.get("name") or "").strip() or f"盒子-{port}", "port": int(port),
              "host": (b.get("host") or "").strip(), "user": (b.get("user") or "").strip(),
              "note": (b.get("note") or "").strip(), "frp_name": (b.get("frp_name") or "").strip(),
              "https": bool(b.get("https"))}
    with LOCK:
        if b.get("id"):
            r = get_router(b["id"])
            r.update(fields)
            if b.get("password"):
                r["password"] = b["password"]
            if b.get("clear_password"):
                r["password"] = ""
        else:
            r = {"id": secrets.token_hex(4), "password": b.get("password") or "", **fields}
            CFG["routers"].append(r)
        save_cfg(CFG)
    return {"id": r["id"]}


def api_router_delete(b):
    with LOCK:
        CFG["routers"] = [r for r in CFG["routers"] if r["id"] != b["id"]]
        STATUS.pop(b["id"], None)
        save_cfg(CFG)
    return {}


def probe_luci(port):
    try:
        st, _, d = raw_req(False, CFG.get("router_host"), int(port), "GET", "/cgi-bin/luci/", timeout=4)
        return st in (200, 403) and b"luci" in d.lower()
    except Exception:
        return False


def api_frps_scan(_):
    lst = frps_fetch()
    have_ports = {str(r["port"]) for r in CFG["routers"]}
    have_names = {r.get("frp_name") for r in CFG["routers"]}
    tcp = [p for p in lst if p["type"] == "tcp" and p["port"]]
    with ThreadPoolExecutor(max_workers=16) as ex:
        probes = list(ex.map(lambda p: probe_luci(p["port"]) if p["online"] else None, tcp))
    for p, pr in zip(tcp, probes):
        p["luci"] = pr
        p["exists"] = str(p["port"]) in have_ports or p["name"] in have_names
    tcp.sort(key=lambda p: (p["exists"], not p["luci"], str(p["name"])))
    return {"items": tcp}


def api_bulk_add(b):
    n = 0
    with LOCK:
        for it in b.get("items") or []:
            if not str(it.get("port", "")).isdigit():
                continue
            CFG["routers"].append({"id": secrets.token_hex(4), "name": it.get("name") or f"盒子-{it['port']}",
                                   "port": int(it["port"]), "host": "", "user": "", "password": "",
                                   "note": "", "frp_name": it.get("name") or "", "https": False})
            n += 1
        save_cfg(CFG)
    return {"added": n}


SECRET_KEYS = ("panel_password", "default_luci_password")


def api_settings_get(_=None):
    s = {k: v for k, v in CFG.items() if k != "routers"}
    s = json.loads(json.dumps(s))
    for k in SECRET_KEYS:
        s[k + "_set"] = bool(s.get(k)); s[k] = ""
    s["frps_password_set"] = bool(s["frps"].get("password")); s["frps"]["password"] = ""
    return s


def api_settings_save(b):
    with LOCK:
        for k in ("router_host", "default_luci_user", "test_url", "notify_webhook", "panel_user"):
            if k in b:
                CFG[k] = str(b[k]).strip()
        if "check_interval_min" in b:
            CFG["check_interval_min"] = max(0, int(b["check_interval_min"] or 0))
        for k in SECRET_KEYS:
            if b.get(k):
                CFG[k] = b[k]
        f = b.get("frps") or {}
        CFG["frps"]["url"] = str(f.get("url", CFG["frps"]["url"])).strip()
        CFG["frps"]["user"] = str(f.get("user", CFG["frps"]["user"])).strip()
        if f.get("password"):
            CFG["frps"]["password"] = f["password"]
        tg = b.get("telegram") or {}
        CFG["telegram"] = {"bot_token": str(tg.get("bot_token", "")).strip(), "chat_id": str(tg.get("chat_id", "")).strip()}
        save_cfg(CFG)
    return {}


def api_test_notify(_):
    notify("PassWall 面板：这是一条测试通知 ✅")
    return {}


POST_ROUTES = {
    "/api/check": api_check, "/api/nodes": api_nodes, "/api/test_node": api_test_node,
    "/api/switch": api_switch, "/api/add_link": api_add_link, "/api/autofix": api_autofix,
    "/api/router/save": api_router_save, "/api/router/delete": api_router_delete,
    "/api/frps/scan": api_frps_scan, "/api/router/bulk_add": api_bulk_add,
    "/api/settings/save": api_settings_save, "/api/settings/test_notify": api_test_notify,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "PWPanel"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _auth(self):
        exp = "Basic " + base64.b64encode(f"{CFG['panel_user']}:{CFG['panel_password']}".encode()).decode()
        got = self.headers.get("Authorization", "")
        if secrets.compare_digest(got.encode("utf-8", "replace"), exp.encode()):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="PassWall Panel", charset="UTF-8"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _send(self, code, obj=None, html=None):
        if html is not None:
            body, ct = html.encode("utf-8"), "text/html; charset=utf-8"
        else:
            body, ct = json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8"
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._auth():
            return
        p = urllib.parse.urlparse(self.path).path
        if p == "/":
            return self._send(200, html=PAGE)
        if p == "/api/state":
            return self._send(200, api_state())
        if p == "/api/settings":
            return self._send(200, api_settings_get())
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            return
        p = urllib.parse.urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return self._send(415, {"ok": False, "error": "bad content-type"})
        fn = POST_ROUTES.get(p)
        if not fn:
            return self._send(404, {"ok": False, "error": "not found"})
        try:
            b = json.loads(raw or b"{}")
            res = fn(b) or {}
            self._send(200, {"ok": True, **res})
        except Err as e:
            self._send(200, {"ok": False, "error": str(e)})
        except NETERR as e:
            self._send(200, {"ok": False, "error": f"网络超时/连接失败：{e}"})
        except Exception as e:
            traceback.print_exc()
            self._send(200, {"ok": False, "error": f"{type(e).__name__}: {e}"})


# ---------------------------------------------------------------- 页面
PAGE = r"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>PassWall 节点面板</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--line:#e6e8ec;--text:#141821;--muted:#6b7280;--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--off:#9ca3af;--pri:#2563eb}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--text)}
header{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line);padding:12px 20px;display:flex;flex-wrap:wrap;gap:12px;align-items:center}
h1{font-size:17px;margin:0 12px 0 0}.sum{display:flex;gap:8px;flex-wrap:wrap}.chip{padding:2px 10px;border-radius:99px;background:#f0f1f3;font-size:13px;cursor:pointer;border:1px solid transparent}
.chip.on{border-color:var(--text)}.actions{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
input,select,textarea{font:inherit;padding:6px 9px;border:1px solid var(--line);border-radius:7px;background:#fff;color:var(--text)}
button{font:inherit;padding:6px 12px;border:1px solid var(--line);border-radius:7px;background:#fff;cursor:pointer;white-space:nowrap}
button:hover{border-color:#c9ccd2}button.pri{background:var(--pri);border-color:var(--pri);color:#fff}button.danger{color:var(--bad)}
button:disabled{opacity:.5;cursor:wait}button.sm{padding:3px 9px;font-size:13px}
main{padding:16px 20px}table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}th{font-weight:600;font-size:13px;color:var(--muted);background:#fafbfc}
tr:last-child td{border-bottom:0}.muted{color:var(--muted)}.small{font-size:12px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.off{color:var(--off)}
.bg-ok{background:var(--ok)}.bg-bad{background:var(--bad)}.bg-warn{background:var(--warn)}.bg-off{background:var(--off)}
.ops{display:flex;gap:5px;flex-wrap:wrap}.tag{font-size:12px;padding:1px 7px;border-radius:5px;background:#eef2ff;color:var(--pri)}
.modal{position:fixed;inset:0;background:rgba(15,18,25,.45);display:flex;align-items:flex-start;justify-content:center;padding:40px 12px;z-index:10;overflow:auto}
.modal[hidden]{display:none}.box{background:#fff;border-radius:12px;width:min(860px,100%);box-shadow:0 10px 40px rgba(0,0,0,.2)}
.mh{display:flex;align-items:center;padding:14px 18px;border-bottom:1px solid var(--line)}.mh b{font-size:15px}.mh button{margin-left:auto;border:0;font-size:20px;padding:0 6px}
.mb{padding:16px 18px}.form{display:grid;grid-template-columns:150px 1fr;gap:10px 12px;align-items:center}.form .full{grid-column:1/-1}
.sec{font-weight:600;margin-top:8px;grid-column:1/-1;border-top:1px solid var(--line);padding-top:12px}
.log{background:#0f1218;color:#d1d5db;border-radius:8px;padding:12px;font:13px/1.6 ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;max-height:420px;overflow:auto}
#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#141821;color:#fff;padding:10px 16px;border-radius:8px;opacity:0;transition:.25s;pointer-events:none;z-index:20;max-width:90vw}
#toast.show{opacity:1}.cur{background:#f0fdf4}.empty{padding:40px;text-align:center;color:var(--muted);background:#fff;border:1px dashed var(--line);border-radius:10px}
@media(max-width:760px){.hide-m{display:none}th,td{padding:7px 6px}.form{grid-template-columns:1fr}}
</style></head><body>
<header><h1>PassWall 节点面板</h1><div class="sum" id="sum"></div>
<div class="actions"><input id="q" placeholder="搜索名称 / 备注 / 端口" oninput="render()" style="width:180px">
<button class="pri" id="btnAll" onclick="checkAll()">全部检测</button><button onclick="openImport()">从 frps 导入</button>
<button onclick="editRouter()">添加盒子</button><button onclick="openSettings()">设置</button></div></header>
<main><div class="muted small" id="meta" style="margin-bottom:8px"></div><div id="list"></div></main>
<div id="modal" class="modal" hidden onclick="if(event.target===this)closeM()"><div class="box"><div class="mh"><b id="mt"></b><button onclick="closeM()">×</button></div><div class="mb" id="mb"></div></div></div>
<div id="toast"></div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const LV={ok:["正常","ok"],node_bad:["节点异常","bad"],error:["出错","bad"],no_wan:["盒子没网","warn"],disabled:["PassWall未开","warn"],offline:["离线","off"],none:["未检测","off"]};
const ORD={node_bad:0,error:1,no_wan:2,disabled:3,offline:4,none:5,ok:6};
let S={routers:[]},FILTER=null,NODES=null;
async function api(p,b){const o=b===undefined?{}:{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)};
 const r=await fetch(p,o);const j=await r.json();if(b!==undefined&&!j.ok)throw new Error(j.error||"失败");return j}
function toast(t,ms=3000){const e=$("toast");e.textContent=t;e.classList.add("show");clearTimeout(e._t);e._t=setTimeout(()=>e.classList.remove("show"),ms)}
function openM(t,h){$("mt").textContent=t;$("mb").innerHTML=h;$("modal").hidden=false}
function closeM(){$("modal").hidden=true;NODES=null}
function ago(ts){if(!ts)return"—";const s=Math.round(Date.now()/1000-ts);return s<60?s+"秒前":s<3600?Math.round(s/60)+"分钟前":Math.round(s/3600)+"小时前"}
function net(t){if(!t)return'<span class="off">—</span>';if(t.ok===null)return'<span class="off">未知</span>';return t.ok?`<span class="ok">${t.ms??"通"}${t.ms!=null?"ms":""}</span>`:'<span class="bad">不通</span>'}
function lvl(r){return r.status?r.status.level:"none"}
async function load(){try{S=await api("/api/state");render()}catch(e){}}
function render(){
 const q=$("q").value.trim().toLowerCase();const cnt={};S.routers.forEach(r=>{const l=lvl(r);cnt[l]=(cnt[l]||0)+1});
 $("sum").innerHTML=`<span class="chip ${FILTER===null?"on":""}" onclick="FILTER=null;render()">全部 ${S.routers.length}</span>`+
  Object.keys(ORD).filter(k=>cnt[k]).map(k=>`<span class="chip ${FILTER===k?"on":""}" onclick="FILTER='${k}';render()"><span class="dot bg-${LV[k][1]}"></span>${LV[k][0]} ${cnt[k]}</span>`).join("");
 $("meta").textContent=(S.checking?"正在全部检测… ":"")+"上次全部检测："+ago(S.last_full)+(S.interval>0?`，每 ${S.interval} 分钟自动检测`:"，自动检测已关闭");
 $("btnAll").disabled=!!S.checking;$("btnAll").textContent=S.checking?"检测中…":"全部检测";
 let rs=S.routers.filter(r=>(!q||[r.name,r.note,r.port,r.frp_name].join(" ").toLowerCase().includes(q))&&(FILTER===null||lvl(r)===FILTER));
 rs.sort((a,b)=>(ORD[lvl(a)]-ORD[lvl(b)])||String(a.name).localeCompare(String(b.name),"zh"));
 if(!S.routers.length){$("list").innerHTML='<div class="empty">还没有盒子。先点「设置」填 frps 面板账号和后台默认密码，再点「从 frps 导入」。</div>';return}
 $("list").innerHTML=`<table><thead><tr><th>状态</th><th>盒子</th><th class="hide-m">端口</th><th class="hide-m">frp</th><th>当前节点</th><th>外网</th><th class="hide-m">国内</th><th class="hide-m">检测</th><th>操作</th></tr></thead><tbody>`+
 rs.map(r=>{const s=r.status||{},l=lvl(r),[lt,lc]=LV[l];
  return `<tr><td><span class="dot bg-${lc}"></span><b class="${lc}">${lt}</b></td>
  <td><b>${esc(r.name)}</b>${r.note?` <span class="muted small">${esc(r.note)}</span>`:""}${s.msg?`<div class="small ${lc}">${esc(s.msg)}</div>`:""}</td>
  <td class="hide-m">${esc(r.port)}</td><td class="hide-m">${s.frp===true?'<span class="ok">在线</span>':s.frp===false?'<span class="bad">离线</span>':'<span class="off">—</span>'}</td>
  <td>${esc(s.node_name||"—")}${s.node_count?` <span class="muted small">共${s.node_count}个</span>`:""}</td>
  <td>${net(s.google)}</td><td class="hide-m">${net(s.baidu)}</td><td class="hide-m muted small">${ago(s.time)}</td>
  <td><div class="ops"><button class="sm" onclick="checkOne('${r.id}',this)">检测</button><button class="sm" onclick="openNodes('${r.id}')">节点</button>
  ${l==="node_bad"?`<button class="sm pri" onclick="autofix('${r.id}')">一键修复</button>`:""}
  <a href="${esc(r.luci_url)}" target="_blank"><button class="sm">后台</button></a><button class="sm" onclick="editRouter('${r.id}')">编辑</button></div></td></tr>`}).join("")+"</tbody></table>"}
async function checkAll(){$("btnAll").disabled=true;$("btnAll").textContent="检测中…";try{S=await api("/api/check",{});render();toast("全部检测完成")}catch(e){toast(e.message);load()}}
async function checkOne(id,btn){btn.disabled=true;btn.textContent="…";try{S=await api("/api/check",{id});render()}catch(e){toast(e.message)}finally{btn.disabled=false;btn.textContent="检测"}}
const R=id=>S.routers.find(r=>r.id===id);
async function openNodes(id){openM(R(id).name+" · 节点",'<p class="muted">正在登录后台读取节点…</p>');
 try{const d=await api("/api/nodes",{id});NODES={id,...d,lat:{}};renderNodes()}catch(e){$("mb").innerHTML=`<p class="bad">${esc(e.message)}</p>`}}
function renderNodes(){if(!NODES)return;const d=NODES;
 $("mb").innerHTML=`<div style="display:flex;gap:8px;align-items:center;margin-bottom:10px"><span class="muted">${esc(d.app)} · 总开关${d.enabled?'<span class="ok">已开</span>':'<span class="bad">未开</span>'} · ${d.nodes.length} 个节点</span>
 <button class="sm" style="margin-left:auto" onclick="testAll(this)">全部测速</button></div>
 <table><thead><tr><th>节点</th><th class="hide-m">类型</th><th class="hide-m">地址</th><th>延迟</th><th></th></tr></thead><tbody>`+
 d.nodes.map(n=>{const c=n.id===d.current,t=d.lat[n.id];
  return `<tr class="${c?"cur":""}"><td>${c?'<span class="tag">当前</span> ':""}${esc(n.remarks)}</td><td class="hide-m muted small">${esc(n.type)} ${esc(n.protocol)}</td>
  <td class="hide-m muted small">${esc(n.address)}${n.port?":"+esc(n.port):""}</td>
  <td id="lat-${n.id}">${t===undefined?'<span class="off">—</span>':t==="…"?"测速中…":t.ok?`<span class="ok">${t.ms}ms</span> <span class="muted small">${esc(t.kind)}</span>`:t.ok===null?`<span class="off">${esc(t.kind)}</span>`:'<span class="bad">不通</span>'}</td>
  <td><div class="ops"><button class="sm" onclick="testNode('${n.id}')">测速</button>${c?"":`<button class="sm pri" onclick="switchNode('${n.id}',this)">切换</button>`}</div></td></tr>`}).join("")+
 `</tbody></table><div style="margin-top:16px"><b>添加新节点</b><div class="muted small">粘贴一条节点分享链接（ss:// vmess:// vless:// trojan:// hy2:// …）</div>
 <textarea id="link" rows="3" style="width:100%;margin-top:6px"></textarea>
 <div style="display:flex;gap:10px;align-items:center;margin-top:6px"><label><input type="checkbox" id="sw" checked> 添加后立即切换过去</label>
 <button class="pri" style="margin-left:auto" onclick="addLink(this)">添加节点</button></div></div>`}
async function testNode(nid){if(!NODES)return;const id=NODES.id;NODES.lat[nid]="…";renderNodes();
 try{const t=(await api("/api/test_node",{id,node:nid})).t;if(NODES&&NODES.id===id){NODES.lat[nid]=t;renderNodes()}}catch(e){if(NODES){NODES.lat[nid]={ok:false};renderNodes()}toast(e.message)}}
async function testAll(btn){btn.disabled=true;for(const n of [...NODES.nodes]){if(!NODES)break;await testNode(n.id)}if(btn)btn.disabled=false}
async function switchNode(nid,btn){const n=NODES.nodes.find(x=>x.id===nid);if(!confirm(`切换到「${n.remarks}」？PassWall 会重启，客户会断网 10~30 秒。`))return;
 btn.disabled=true;btn.textContent="切换中…";const id=NODES.id;
 try{const r=await api("/api/switch",{id,node:nid});const g=r.status&&r.status.google;toast(g&&g.ok?`已切换，外网正常 ${g.ms}ms`:"已切换，但外网还是不通",5000);await load();if(NODES)openNodes(id)}
 catch(e){toast(e.message,5000);btn.disabled=false;btn.textContent="切换"}}
async function addLink(btn){const link=$("link").value.trim();if(!link)return toast("先粘贴节点链接");btn.disabled=true;btn.textContent="添加中…";const id=NODES.id;
 try{const r=await api("/api/add_link",{id,link,switch:$("sw").checked});const g=r.status&&r.status.google;
  toast("已添加："+r.added.map(x=>x.remarks).join("、")+(r.status?(g&&g.ok?`，已切换，外网正常 ${g.ms}ms`:"，已切换，但外网还是不通"):""),6000);await load();openNodes(id)}
 catch(e){toast(e.message,6000);btn.disabled=false;btn.textContent="添加节点"}}
async function autofix(id){openM(R(id).name+" · 一键修复",'<div class="log" id="flog">正在检测当前网络，并给备用节点测速、切换，可能要 1~2 分钟…</div>');
 try{const r=await api("/api/autofix",{id});$("flog").textContent=r.log.join("\n");if(!r.fixed)$("mb").insertAdjacentHTML("beforeend",`<div style="margin-top:10px"><button class="pri" onclick="openNodes('${id}')">打开节点列表 / 添加新节点</button></div>`);load()}
 catch(e){$("flog").textContent="出错："+e.message}}
function editRouter(id){const r=id?R(id):{};
 openM(id?"编辑盒子":"添加盒子",`<div class="form"><label>名称</label><input id="f_name" value="${esc(r.name||"")}" placeholder="客户名 / 位置">
 <label>备注</label><input id="f_note" value="${esc(r.note||"")}" placeholder="微信名、电话等">
 <label>远程端口</label><input id="f_port" value="${esc(r.port||"")}" placeholder="frp 里这个盒子后台的端口">
 <label>主机</label><input id="f_host" value="${esc(r.host||"")}" placeholder="留空 = 设置里的默认 IP">
 <label>后台用户名</label><input id="f_user" value="${esc(r.user||"")}" placeholder="留空 = 默认（root）">
 <label>后台密码</label><input id="f_pw" type="password" placeholder="${r.has_password?"已单独设置，留空不改":"留空 = 用默认密码"}">
 ${r.has_password?'<label></label><label><input type="checkbox" id="f_clr"> 清除单独密码，改用默认密码</label>':""}
 <label>frp 代理名</label><input id="f_frp" value="${esc(r.frp_name||"")}" placeholder="用来对应 frp 在线状态（可选）">
 <label>HTTPS 后台</label><label><input type="checkbox" id="f_https" ${r.https?"checked":""}> 后台是 https</label>
 <div class="full" style="display:flex;gap:8px;margin-top:6px">${id?`<button class="danger" onclick="delRouter('${id}')">删除</button>`:""}
 <button class="pri" style="margin-left:auto" onclick="saveRouter('${id||""}')">保存</button></div></div>`)}
async function saveRouter(id){const b={id:id||undefined,name:$("f_name").value,note:$("f_note").value,port:$("f_port").value,host:$("f_host").value,
 user:$("f_user").value,password:$("f_pw").value,frp_name:$("f_frp").value,https:$("f_https").checked,clear_password:$("f_clr")?$("f_clr").checked:false};
 try{const r=await api("/api/router/save",b);closeM();await load();toast("已保存，正在检测…");S=await api("/api/check",{id:r.id});render()}catch(e){toast(e.message)}}
async function delRouter(id){if(!confirm("确定删除这个盒子？（只是从面板移除，不影响路由器）"))return;try{await api("/api/router/delete",{id});closeM();load()}catch(e){toast(e.message)}}
async function openImport(){openM("从 frps 导入",'<p class="muted">正在读取 frps 代理列表，并探测哪些端口是软路由后台…</p>');
 try{const r=await api("/api/frps/scan",{});if(!r.items.length){$("mb").innerHTML='<p class="muted">frps 里没有 TCP 代理。</p>';return}
 $("mb").innerHTML=`<p class="muted small">已勾选「像软路由后台」且还没加过的。导入后用设置里的默认后台密码登录；个别密码不同的，导入后点「编辑」单独填。</p>
 <table><thead><tr><th><input type="checkbox" onclick="document.querySelectorAll('.imp').forEach(c=>c.checked=this.checked)"></th><th>frp 代理名</th><th>端口</th><th>frp</th><th>后台探测</th></tr></thead><tbody>`+
 r.items.map((p,i)=>`<tr><td><input type="checkbox" class="imp" data-i="${i}" ${p.luci&&!p.exists?"checked":""} ${p.exists?"disabled":""}></td><td>${esc(p.name)}</td><td>${esc(p.port)}</td>
 <td>${p.online?'<span class="ok">在线</span>':'<span class="bad">离线</span>'}</td><td>${p.exists?'<span class="muted">已添加</span>':p.luci?'<span class="ok">像软路由后台</span>':p.luci===false?'<span class="muted">不像</span>':'<span class="off">离线没测</span>'}</td></tr>`).join("")+
 `</tbody></table><div style="text-align:right;margin-top:12px"><button class="pri" id="impBtn">导入选中</button></div>`;
 $("impBtn").onclick=async()=>{const items=[...document.querySelectorAll(".imp:checked")].map(c=>r.items[+c.dataset.i]);if(!items.length)return toast("没选");
  try{const x=await api("/api/router/bulk_add",{items});closeM();toast(`导入了 ${x.added} 台，开始检测…`);await load();checkAll()}catch(e){toast(e.message)}}}
 catch(e){$("mb").innerHTML=`<p class="bad">${esc(e.message)}</p>`}}
async function openSettings(){const s=await api("/api/settings");const ph=x=>x?"已设置，留空不改":"";
 openM("设置",`<div class="form"><div class="sec" style="border:0;padding:0;margin:0">frps 面板</div>
 <label>frps 面板地址</label><input id="s_fu" value="${esc(s.frps.url)}"><label>frps 用户名</label><input id="s_fn" value="${esc(s.frps.user)}">
 <label>frps 密码</label><input id="s_fp" type="password" placeholder="${ph(s.frps_password_set)}">
 <div class="sec">软路由后台（默认值）</div><label>默认 IP</label><input id="s_rh" value="${esc(s.router_host)}">
 <label>默认用户名</label><input id="s_du" value="${esc(s.default_luci_user)}"><label>默认密码</label><input id="s_dp" type="password" placeholder="${ph(s.default_luci_password_set)}">
 <div class="sec">检测</div><label>自动检测间隔（分钟）</label><input id="s_iv" value="${esc(s.check_interval_min)}" placeholder="0 = 关闭">
 <label>外网测试地址</label><input id="s_tu" value="${esc(s.test_url)}">
 <div class="sec">掉线通知（可选）</div><label>企业微信/钉钉机器人 Webhook</label><input id="s_wh" value="${esc(s.notify_webhook)}">
 <label>Telegram Bot Token</label><input id="s_tt" value="${esc(s.telegram.bot_token)}"><label>Telegram Chat ID</label><input id="s_tc" value="${esc(s.telegram.chat_id)}">
 <div class="sec">面板登录</div><label>面板用户名</label><input id="s_pu" value="${esc(s.panel_user)}"><label>新面板密码</label><input id="s_pp" type="password" placeholder="留空不改">
 <div class="full" style="display:flex;gap:8px;margin-top:6px"><button onclick="testNotify()">发送测试通知</button><button class="pri" style="margin-left:auto" onclick="saveSettings()">保存</button></div></div>`)}
async function saveSettings(){const b={frps:{url:$("s_fu").value,user:$("s_fn").value,password:$("s_fp").value},router_host:$("s_rh").value,default_luci_user:$("s_du").value,
 default_luci_password:$("s_dp").value,check_interval_min:$("s_iv").value,test_url:$("s_tu").value,notify_webhook:$("s_wh").value,
 telegram:{bot_token:$("s_tt").value,chat_id:$("s_tc").value},panel_user:$("s_pu").value,panel_password:$("s_pp").value};
 try{await api("/api/settings/save",b);closeM();toast(b.panel_password?"已保存，面板密码已改，请重新登录":"已保存");load()}catch(e){toast(e.message)}}
async function testNotify(){try{await api("/api/settings/save",{frps:{},telegram:{bot_token:$("s_tt").value,chat_id:$("s_tc").value},notify_webhook:$("s_wh").value});await api("/api/settings/test_notify",{});toast("已发送，去看看收到没")}catch(e){toast(e.message)}}
load();setInterval(load,20000);
</script></body></html>"""


def main():
    host, port = CFG.get("listen_host", "0.0.0.0"), int(CFG.get("listen_port", 8899))
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    srv = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=bg_loop, daemon=True).start()
    print(f"PassWall 面板已启动： http://{'127.0.0.1' if host in ('0.0.0.0','') else host}:{port}")
    print(f"登录账号：{CFG['panel_user']}   密码：{CFG['panel_password']}")
    print(f"配置文件：{CONFIG_PATH}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
