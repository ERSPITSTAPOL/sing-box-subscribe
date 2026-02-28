import orjson as json

def safe_json_dumps(obj):
    try:
        return json.dumps(obj).decode()
    except Exception:
        return str(obj)

_SS_CIPHER_MAP = {
    "chacha20-poly1305": "chacha20-ietf-poly1305",
    "xchacha20-poly1305": "xchacha20-ietf-poly1305",
}

def _parse_ports(ports_raw):
    items = []
    for item in str(ports_raw).split(","):
        item = item.strip()
        if "-" in item:
            items.append(item.replace("-", ":"))
    return ",".join(items) if items else None

def _tls_base(node, get, h3=False):
    tls = {"enabled": True}
    sn = get("servername") or get("sni")
    if sn:
        tls["server_name"] = sn
    if get("skip-cert-verify"):
        tls["insecure"] = True
    if not h3 and get("disable-sni"):
        tls["disable_sni"] = True
    alpn = get("alpn")
    if h3:
        tls["alpn"] = (alpn if isinstance(alpn, list) else [alpn]) if alpn else ["h3"]
    elif alpn:
        tls["alpn"] = alpn if isinstance(alpn, list) else [alpn]
    fp = get("client-fingerprint")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    reality = get("reality-opts")
    if reality:
        tls["reality"] = {
            "enabled": True,
            "public_key": reality.get("public-key", ""),
            "short_id": reality.get("short-id", ""),
        }
    ech = get("ech-opts")
    if ech and isinstance(ech, dict) and ech.get("enable"):
        ech_out = {"enabled": True}
        ec = ech.get("config")
        if ec:
            ech_out["config"] = ["-----BEGIN ECH CONFIG-----\n" + ec + "\n-----END ECH CONFIG-----"]
        qsn = ech.get("query-server-name")
        if qsn:
            ech_out["query_server_name"] = qsn
        cp = ech.get("config_path")
        if cp:
            ech_out["config_path"] = cp
        tls["ech"] = ech_out
    cert = get("certificate")
    if cert:
        if isinstance(cert, str) and cert.startswith("./"):
            tls["client_certificate_path"] = cert
        else:
            tls["client_certificate"] = [cert]
    key = get("private-key")
    if key:
        if isinstance(key, str) and key.startswith("./"):
            tls["client_key_path"] = key
        else:
            tls["client_key"] = [key]
    node["tls"] = tls

def _tls(node, get):
    _tls_base(node, get, h3=False)

def _tls_h3(node, get):
    _tls_base(node, get, h3=True)

def _transport(node, get):
    net = get("network") or "tcp"
    if net == "tcp":
        return
    if net == "ws":
        opts = get("ws-opts") or {}
        if not opts:
            return
        t = {"type": "ws", "path": opts.get("path", "/")}
        h = opts.get("headers")
        if h:
            t["headers"] = h
        med = opts.get("max-early-data")
        if med:
            try:
                t["max_early_data"] = int(med)
            except (TypeError, ValueError):
                t["max_early_data"] = med
        edhn = opts.get("early-data-header-name")
        if edhn:
            t["early_data_header_name"] = edhn
        node["transport"] = t
    elif net == "grpc":
        opts = get("grpc-opts") or {}
        if not opts:
            return
        t = {"type": "grpc"}
        sn = opts.get("grpc-service-name")
        if sn:
            t["service_name"] = sn
        node["transport"] = t
    elif net in ("http", "h2"):
        opts = get("http-opts") or get("h2-opts") or {}
        if not opts:
            return
        t = {"type": "http"}
        host = opts.get("host")
        if host:
            t["host"] = host
        path = opts.get("path")
        if path:
            t["path"] = path[0] if isinstance(path, list) else path
        method = opts.get("method")
        if method:
            t["method"] = method
        headers = opts.get("headers")
        if headers:
            t["headers"] = headers
        node["transport"] = t

def _common(node, get):
    d = get("dialer-proxy")
    if d:
        node["detour"] = d
    if get("tfo") and get("type") != "anytls":
        node["tcp_fast_open"] = True
    if get("mptcp"):
        node["tcp_multi_path"] = True
    smux = get("smux")
    if smux and smux.get("enabled"):
        mp = {"enabled": True}
        for k, nk in (
            ("protocol", "protocol"),
            ("max-connections", "max_connections"),
            ("min-streams", "min_streams"),
            ("max-streams", "max_streams"),
        ):
            v = smux.get(k)
            if v:
                mp[nk] = v
        if smux.get("padding"):
            mp["padding"] = True
        brutal = smux.get("brutal-opts")
        if brutal and brutal.get("enabled"):
            mp["brutal"] = {
                "enabled": True,
                "up_mbps": brutal.get("up"),
                "down_mbps": brutal.get("down"),
            }
        node["multiplex"] = mp
    rm = get("routing-mark")
    if rm is not None:
        node["routing_mark"] = rm
    iface = get("interface-name")
    if iface:
        node["bind_interface"] = iface

def _trojan(cfg):
    get = cfg.get
    node = {"type": "trojan"}
    v = get("name");
    if v: node["tag"] = v
    v = get("server");
    if v: node["server"] = v
    v = get("port");
    if v: node["server_port"] = v
    v = get("password");
    if v: node["password"] = v
    if get("tls"):
        _tls(node, get)
    _transport(node, get)
    _common(node, get)
    return node

def _vmess(cfg):
    get = cfg.get
    node = {"type": "vmess"}
    v = get("name");
    if v: node["tag"] = v
    v = get("server");
    if v: node["server"] = v
    v = get("port");
    if v: node["server_port"] = v
    v = get("uuid");
    if v: node["uuid"] = v
    v = get("cipher");
    if v: node["security"] = v
    v = get("alterId");
    if v: node["alter_id"] = v
    v = get("global-padding");
    if v: node["global_padding"] = v
    v = get("authenticated-length");
    if v: node["authenticated_length"] = v
    v = get("packet-encoding");
    if v: node["packet_encoding"] = v
    if get("tls"):
        _tls(node, get)
    _transport(node, get)
    _common(node, get)
    return node

def _vless(cfg):
    get = cfg.get
    node = {"type": "vless", "packet_encoding": get("packet-encoding") or "xudp"}
    v = get("name");
    if v: node["tag"] = v
    v = get("server");
    if v: node["server"] = v
    v = get("port");
    if v: node["server_port"] = v
    v = get("uuid");
    if v: node["uuid"] = v
    v = get("flow");
    if v: node["flow"] = v
    if get("tls"):
        _tls(node, get)
    _transport(node, get)
    _common(node, get)
    return node

def _parse_speed(s):
    s = s.strip()
    num = s.split()[0].rstrip("MmBbGgKk/s")
    if num.replace(".", "", 1).isdigit():
        return int(float(num))
    return s

def _hysteria(cfg):
    get = cfg.get
    node = {"type": "hysteria"}
    v = get("name");
    if v: node["tag"] = v
    v = get("server");
    if v: node["server"] = v
    v = get("port");
    if v: node["server_port"] = v
    ports_raw = get("ports")
    if ports_raw:
        p = _parse_ports(ports_raw)
        if p: node["server_ports"] = p
    for clash_key, mbps_key, raw_key in (
        ("up", "up_mbps", "up"),
        ("down", "down_mbps", "down"),
    ):
        val = get(clash_key)
        if val is None:
            continue
        result = _parse_speed(str(val))
        if isinstance(result, int):
            node[mbps_key] = result
        else:
            node[raw_key] = result
    v = get("obfs");
    if v: node["obfs"] = v
    v = get("auth-str");
    if v: node["auth_str"] = v
    v = get("recv-window-conn");
    if v: node["recv_window_conn"] = v
    v = get("recv-window");
    if v: node["recv_window"] = v
    v = get("disable_mtu_discovery")
    if v is not None: node["disable_mtu_discovery"] = v
    _tls_h3(node, get)
    _common(node, get)
    return node

def _hysteria2(cfg):
    get = cfg.get
    node = {"type": "hysteria2"}
    v = get("name");
    if v: node["tag"] = v
    v = get("server");
    if v: node["server"] = v
    v = get("port");
    if v: node["server_port"] = v
    ports_raw = get("ports")
    if ports_raw:
        p = _parse_ports(ports_raw)
        if p: node["server_ports"] = p
    v = get("password");
    if v: node["password"] = v
    v = get("up")
    if v: node["up_mbps"] = int(float(str(v).strip().split()[0]))
    v = get("down")
    if v: node["down_mbps"] = int(float(str(v).strip().split()[0]))
    obfs = get("obfs")
    if obfs:
        node["obfs"] = {"type": obfs, "password": get("obfs-password") or ""}
    _tls_h3(node, get)
    _common(node, get)
    return node

def _tuic(cfg):
    get = cfg.get
    node = {"type": "tuic"}
    v = get("name");
    if v: node["tag"] = v
    v = get("server");
    if v: node["server"] = v
    v = get("port");
    if v: node["server_port"] = v
    v = get("uuid");
    if v: node["uuid"] = v
    v = get("password");
    if v: node["password"] = v
    v = get("congestion-controller");
    if v: node["congestion_control"] = v
    v = get("udp-relay-mode");
    if v: node["udp_relay_mode"] = v
    v = get("udp-over-stream");
    if v: node["udp_over_stream"] = v
    v = get("reduce-rtt");
    if v: node["zero_rtt_handshake"] = v
    v = get("heartbeat-interval")
    if v:
        try:
            node["heartbeat"] = f"{int(v)}ms"
        except (TypeError, ValueError):
            node["heartbeat"] = str(v)
    _tls_h3(node, get)
    _common(node, get)
    return node

def _anytls(cfg):
    get = cfg.get
    node = {"type": "anytls"}
    v = get("name");
    if v: node["tag"] = v
    v = get("server");
    if v: node["server"] = v
    v = get("port");
    if v: node["server_port"] = v
    v = get("password");
    if v: node["password"] = v
    v = get("idle-session-check-interval");
    if v: node["idle_session_check_interval"] = f"{v}s"
    v = get("idle-session-timeout");
    if v: node["idle_session_timeout"] = f"{v}s"
    v = get("min-idle-session");
    if v: node["min_idle_session"] = v
    _tls(node, get)
    d = get("dialer-proxy");
    if d: node["detour"] = d
    rm = get("routing-mark")
    if rm is not None: node["routing_mark"] = rm
    if get("mptcp"): node["tcp_multi_path"] = True
    return node

def _ss(cfg):
    get = cfg.get
    node = {"type": "shadowsocks"}
    v = get("name");
    if v: node["tag"] = v
    v = get("server");
    if v: node["server"] = v
    v = get("port");
    if v: node["server_port"] = v
    v = get("cipher")
    if v:
        node["method"] = _SS_CIPHER_MAP.get(v, v)
    v = get("password");
    if v: node["password"] = v
    uot = get("udp-over-tcp")
    if uot or "udp-over-tcp-version" in cfg:
        node["udp_over_tcp"] = {
            "enabled": bool(uot),
            "version": get("udp-over-tcp-version") or 2,
        }
    plugin = get("plugin")
    if plugin:
        opts = get("plugin-opts") or {}
        if plugin in ("obfs", "simple-obfs", "obfs-local"):
            node["plugin"] = "obfs-local"
            parts = [f"obfs={opts.get('mode', 'http')}"]
            h = opts.get("host")
            if h: parts.append(f"obfs-host={h}")
            node["plugin_opts"] = ";".join(parts)
        elif plugin == "v2ray-plugin":
            node["plugin"] = "v2ray-plugin"
            parts = [f"mode={opts.get('mode', 'websocket')}"]
            h = opts.get("host")
            if h: parts.append(f"host={h}")
            p = opts.get("path")
            if p: parts.append("path=" + p)
            if opts.get("mux"): parts.append("mux=1")
            hdrs = opts.get("headers")
            if hdrs: parts.append("headers=" + safe_json_dumps(hdrs))
            if opts.get("skip-cert-verify"): parts.append("skip-cert-verify=true")
            if opts.get("tls"): parts.append("tls")
            node["plugin_opts"] = ";".join(parts)
        elif plugin == "shadow-tls":
            detour_tag = f"{node.get('tag', 'ss-out')}_shadowtls"
            node["detour"] = detour_tag
            fp = get("client-fingerprint")
            nt = {
                "tag": detour_tag,
                "type": "shadowtls",
                "server": node.get("server"),
                "server_port": node.get("server_port"),
                "version": opts.get("version", 1),
                "password": opts.get("password", ""),
                "tls": {"enabled": True, "server_name": opts.get("host", "")},
            }
            if fp:
                nt["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
            node.pop("server", None)
            node.pop("server_port", None)
            node["__node_tls__"] = nt
            return node
    if get("tls"):
        _tls(node, get)
    _common(node, get)
    return node

def _ss_entry(cfg):
    res = _ss(cfg)
    if isinstance(res, dict) and "__node_tls__" in res:
        nt = res.pop("__node_tls__")
        return res, nt
    return res

def _http(cfg):
    get = cfg.get
    node = {"type": "http"}
    v = get("name");
    if v: node["tag"] = v
    v = get("server");
    if v: node["server"] = v
    v = get("port");
    if v: node["server_port"] = v
    v = get("username");
    if v: node["username"] = v
    v = get("password");
    if v: node["password"] = v
    v = get("path");
    if v: node["path"] = v
    v = get("headers");
    if v: node["headers"] = v
    if get("tls"):
        _tls(node, get)
    _common(node, get)
    return node

def _socks5(cfg):
    get = cfg.get
    node = {"type": "socks", "version": "5"}
    v = get("name");
    if v: node["tag"] = v
    v = get("server");
    if v: node["server"] = v
    v = get("port");
    if v: node["server_port"] = v
    v = get("username");
    if v: node["username"] = v
    v = get("password");
    if v: node["password"] = v
    if get("tls"):
        _tls(node, get)
    _common(node, get)
    return node

def _wireguard(cfg):
    get = cfg.get
    node = {"type": "wireguard"}
    v = get("name");
    if v: node["tag"] = v
    v = get("private-key");
    if v: node["private_key"] = v
    v = get("mtu");
    if v: node["mtu"] = v
    addr = []
    ip4 = get("ip")
    if ip4: addr.append(ip4 + "/32" if "/" not in ip4 else ip4)
    ip6 = get("ipv6")
    if ip6: addr.append(ip6 + "/128" if "/" not in ip6 else ip6)
    if addr: node["address"] = addr
    peers_out = []
    for cp in get("peers") or []:
        peer = {
            "address": cp.get("server"),
            "port": cp.get("port"),
            "public_key": cp.get("public-key"),
            "allowed_ips": cp.get("allowed-ips", ["0.0.0.0/0"]),
        }
        pki = cp.get("persistent-keepalive")
        if pki is not None: peer["persistent_keepalive_interval"] = pki
        psk = cp.get("pre-shared-key")
        if psk: peer["pre_shared_key"] = psk
        reserved = cp.get("reserved")
        if reserved:
            if isinstance(reserved, list):
                peer["reserved"] = reserved
            elif isinstance(reserved, str):
                peer["reserved"] = (
                    [int(x.strip()) for x in reserved.split(",")]
                    if "," in reserved
                    else reserved
                )
        peers_out.append(peer)
    if peers_out: node["peers"] = peers_out
    dp = get("dialer-proxy")
    if dp: node["detour"] = dp
    return node

_TABLE = {
    "ss": _ss_entry,
    "vmess": _vmess,
    "trojan": _trojan,
    "vless": _vless,
    "tuic": _tuic,
    "hysteria": _hysteria,
    "hysteria2": _hysteria2,
    "anytls": _anytls,
    "wireguard": _wireguard,
    "http": _http,
    "socks5": _socks5,
}
_TABLE_GET = _TABLE.get

def clash2sing(cfg):
    try:
        handler = _TABLE_GET(cfg["type"])
    except (KeyError, TypeError):
        return ""
    if not handler:
        return ""
    try:
        return handler(cfg)
    except Exception as e:
        print(f"转换失败: {e}")
        return ""