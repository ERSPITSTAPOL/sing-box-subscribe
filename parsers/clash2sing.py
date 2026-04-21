_SS_CIPHER_MAP = {
    "chacha20-poly1305": "chacha20-ietf-poly1305",
    "xchacha20-poly1305": "xchacha20-ietf-poly1305",
}

def _parse_ports(ports_raw):
    if not ports_raw:
        return None
    return ",".join([i.strip().replace("-", ":") for i in str(ports_raw).split(",") if "-" in i]) or None

def _parse_speed(s):
    t = type(s)
    if t is int or t is float:
        return int(s)
    num = str(s).split(maxsplit=1)[0].rstrip("MmBbGgKk/s")
    try:
        return int(float(num))
    except ValueError:
        return str(s).strip()

def _parse_mbps(v):
    t = type(v)
    if t is int or t is float:
        return int(v)
    return int(float(str(v).split(maxsplit=1)[0]))

def _tls_base(node, get, h3=False):
    tls = {"enabled": True}

    if sn := (get("servername") or get("sni")):
        tls["server_name"] = sn
    if get("skip-cert-verify"):
        tls["insecure"] = True
    if not h3 and get("disable-sni"):
        tls["disable_sni"] = True

    alpn = get("alpn")
    if h3:
        tls["alpn"] = alpn if type(alpn) is list else ([alpn] if alpn else ["h3"])
    elif alpn:
        tls["alpn"] = alpn if type(alpn) is list else [alpn]

    if fp := get("client-fingerprint"):
        tls["utls"] = {"enabled": True, "fingerprint": fp}

    if reality := get("reality-opts"):
        tls["reality"] = {
            "enabled": True,
            "public_key": reality.get("public-key", ""),
            "short_id": reality.get("short-id", ""),
        }

    if ech := get("ech-opts"):
        if type(ech) is dict and ech.get("enable"):
            ech_out = {"enabled": True}
            if ec := ech.get("config"):
                ech_out["config"] = [f"-----BEGIN ECH CONFIGS-----\n{ec}\n-----END ECH CONFIGS-----"]
            if qsn := ech.get("query-server-name"):
                ech_out["query_server_name"] = qsn
            if cp := ech.get("config_path"):
                ech_out["config_path"] = cp
            tls["ech"] = ech_out

    if cert := get("certificate"):
        if type(cert) is str and cert.startswith("./"):
            tls["client_certificate_path"] = cert
        else:
            tls["client_certificate"] = [cert]

    if key := get("private-key"):
        if type(key) is str and key.startswith("./"):
            tls["client_key_path"] = key
        else:
            tls["client_key"] = [key]

    node["tls"] = tls

def _tls(node, get):
    _tls_base(node, get, h3=False)

def _tls_h3(node, get):
    _tls_base(node, get, h3=True)

def _transport(node, get):
    net = get("network", "tcp")
    if net == "tcp":
        return

    if net == "ws":
        if not (opts := get("ws-opts")): return
        t = {"type": "ws", "path": opts.get("path", "/")}
        if h := opts.get("headers"): t["headers"] = h
        if med := opts.get("max-early-data"):
            try: t["max_early_data"] = int(med)
            except ValueError: t["max_early_data"] = med
        if edhn := opts.get("early-data-header-name"):
            t["early_data_header_name"] = edhn
        node["transport"] = t

    elif net == "grpc":
        if not (opts := get("grpc-opts")): return
        t = {"type": "grpc"}
        if sn := opts.get("grpc-service-name"): t["service_name"] = sn
        node["transport"] = t

    elif net == "h2":
        if not (opts := get("h2-opts")): return
        t = {"type": "http"}
        if host := opts.get("host"): t["host"] = host
        if path := opts.get("path"):
            t["path"] = path[0] if type(path) is list else path
        node["transport"] = t

def _common(node, get):
    if d := get("dialer-proxy"): node["detour"] = d
    if get("tfo") and get("type") != "anytls": node["tcp_fast_open"] = True
    if get("mptcp"): node["tcp_multi_path"] = True

    if (smux := get("smux")) and smux.get("enabled"):
        mp = {"enabled": True}
        if p := smux.get("protocol"): mp["protocol"] = p
        if mc := smux.get("max-connections"): mp["max_connections"] = mc
        if ms := smux.get("min-streams"): mp["min_streams"] = ms
        if mx := smux.get("max-streams"): mp["max_streams"] = mx
        if smux.get("padding"): mp["padding"] = True

        if (brutal := smux.get("brutal-opts")) and brutal.get("enabled"):
            mp["brutal"] = {
                "enabled": True,
                "up_mbps": brutal.get("up"),
                "down_mbps": brutal.get("down"),
            }
        node["multiplex"] = mp

    if (rm := get("routing-mark")) is not None: node["routing_mark"] = rm
    if iface := get("interface-name"): node["bind_interface"] = iface

def _trojan(cfg):
    get = cfg.get
    node = {"type": "trojan"}
    if v := get("name"): node["tag"] = v
    if v := get("server"): node["server"] = v
    if v := get("port"): node["server_port"] = v
    if v := get("password"): node["password"] = v
    if get("tls"): _tls(node, get)
    _transport(node, get)
    _common(node, get)
    return node

def _vmess(cfg):
    get = cfg.get
    node = {"type": "vmess"}
    if v := get("name"): node["tag"] = v
    if v := get("server"): node["server"] = v
    if v := get("port"): node["server_port"] = v
    if v := get("uuid"): node["uuid"] = v
    if v := get("cipher"): node["security"] = v
    if v := get("alterId"): node["alter_id"] = v
    if v := get("global-padding"): node["global_padding"] = v
    if v := get("authenticated-length"): node["authenticated_length"] = v
    if v := get("packet-encoding"): node["packet_encoding"] = v
    if get("tls"): _tls(node, get)
    _transport(node, get)
    _common(node, get)
    return node

def _vless(cfg):
    get = cfg.get
    node = {"type": "vless", "packet_encoding": get("packet-encoding") or "xudp"}
    if v := get("name"): node["tag"] = v
    if v := get("server"): node["server"] = v
    if v := get("port"): node["server_port"] = v
    if v := get("uuid"): node["uuid"] = v
    if v := get("flow"): node["flow"] = v
    if get("tls"): _tls(node, get)
    _transport(node, get)
    _common(node, get)
    return node

def _hysteria(cfg):
    get = cfg.get
    node = {"type": "hysteria"}
    if v := get("name"): node["tag"] = v
    if v := get("server"): node["server"] = v
    if v := get("port"): node["server_port"] = v
    if p := _parse_ports(get("ports")): node["server_ports"] = p

    for clash_key, mbps_key, raw_key in (
        ("up", "up_mbps", "up"),
        ("down", "down_mbps", "down"),
    ):
        if (val := get(clash_key)) is not None:
            result = _parse_speed(val)
            if type(result) is int: node[mbps_key] = result
            else: node[raw_key] = result

    if v := get("obfs"): node["obfs"] = v
    if v := get("auth-str"): node["auth_str"] = v
    if v := get("recv-window-conn"): node["recv_window_conn"] = v
    if v := get("recv-window"): node["recv_window"] = v
    if (v := get("disable_mtu_discovery")) is not None: node["disable_mtu_discovery"] = v

    _tls_h3(node, get)
    _common(node, get)
    return node

def _hysteria2(cfg):
    get = cfg.get
    node = {"type": "hysteria2"}
    if v := get("name"): node["tag"] = v
    if v := get("server"): node["server"] = v
    if v := get("port"): node["server_port"] = v
    if p := _parse_ports(get("ports")): node["server_ports"] = p
    if v := get("password"): node["password"] = v
    if (v := get("up")) is not None: node["up_mbps"] = _parse_mbps(v)
    if (v := get("down")) is not None: node["down_mbps"] = _parse_mbps(v)
    if obfs := get("obfs"):
        node["obfs"] = {"type": obfs, "password": get("obfs-password") or ""}

    _tls_h3(node, get)
    _common(node, get)
    return node

def _tuic(cfg):
    get = cfg.get
    node = {"type": "tuic"}
    if v := get("name"): node["tag"] = v
    if v := get("server"): node["server"] = v
    if v := get("port"): node["server_port"] = v
    if v := get("uuid"): node["uuid"] = v
    if v := get("password"): node["password"] = v
    if v := get("congestion-controller"): node["congestion_control"] = v
    if v := get("udp-relay-mode"): node["udp_relay_mode"] = v
    if v := get("udp-over-stream"): node["udp_over_stream"] = v
    if v := get("reduce-rtt"): node["zero_rtt_handshake"] = v
    if v := get("heartbeat-interval"):
        try: node["heartbeat"] = f"{int(v)}ms"
        except ValueError: node["heartbeat"] = str(v)

    _tls_h3(node, get)
    _common(node, get)
    return node

def _anytls(cfg):
    get = cfg.get
    node = {"type": "anytls"}
    if v := get("name"): node["tag"] = v
    if v := get("server"): node["server"] = v
    if v := get("port"): node["server_port"] = v
    if v := get("password"): node["password"] = v
    if v := get("idle-session-check-interval"): node["idle_session_check_interval"] = f"{v}s"
    if v := get("idle-session-timeout"): node["idle_session_timeout"] = f"{v}s"
    if v := get("min-idle-session"): node["min_idle_session"] = v
    _tls(node, get)

    if d := get("dialer-proxy"): node["detour"] = d
    if (rm := get("routing-mark")) is not None: node["routing_mark"] = rm
    if get("mptcp"): node["tcp_multi_path"] = True
    return node

def _ss(cfg):
    get = cfg.get
    node = {"type": "shadowsocks"}
    if v := get("name"): node["tag"] = v
    if v := get("server"): node["server"] = v
    if v := get("port"): node["server_port"] = v
    if v := get("cipher"): node["method"] = _SS_CIPHER_MAP.get(v, v)
    if v := get("password"): node["password"] = v

    uot = get("udp-over-tcp")
    if uot or "udp-over-tcp-version" in cfg:
        node["udp_over_tcp"] = {
            "enabled": bool(uot),
            "version": get("udp-over-tcp-version") or 2,
        }

    if plugin := get("plugin"):
        opts = get("plugin-opts") or {}
        if plugin == "obfs":
            node["plugin"] = "obfs-local"
            mode = opts.get("mode", "http")
            parts = ["obfs=tls"] if mode == "tls" else [f"obfs={mode}"]
            if h := opts.get("host"):
                parts.append(f"obfs-host={h}")
            node["plugin_opts"] = ";".join(parts)
        elif plugin == "v2ray-plugin":
            node["plugin"] = "v2ray-plugin"
            parts = [f"mode={opts.get('mode', 'websocket')}"]
            if h := opts.get("host"):
                parts.append(f"host={h}")
            if p := opts.get("path"):
                parts.append(f"path={p}")
            if "mux" in opts:
                parts.append("mux=1" if opts.get("mux") else "mux=0")
            if opts.get("tls"):
                parts.append("tls=true")
            node["plugin_opts"] = ";".join(parts)
        elif plugin == "shadow-tls":
            detour_tag = f"{node.get('tag', 'ss-out')}_shadowtls"
            node["detour"] = detour_tag
            nt = {
                "tag": detour_tag,
                "type": "shadowtls",
                "server": node.get("server"),
                "server_port": node.get("server_port"),
                "version": opts.get("version", 1),
                "password": opts.get("password", ""),
                "tls": {"enabled": True, "server_name": opts.get("host", "")},
            }
            if fp := get("client-fingerprint"):
                nt["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
            node.pop("server", None)
            node.pop("server_port", None)
            node["__node_tls__"] = nt
            return node

    if get("tls"): _tls(node, get)
    _common(node, get)
    return node

def _ss_entry(cfg):
    res = _ss(cfg)
    if "__node_tls__" in res:
        return res, res.pop("__node_tls__")
    return res

def _http(cfg):
    get = cfg.get
    node = {"type": "http"}
    if v := get("name"): node["tag"] = v
    if v := get("server"): node["server"] = v
    if v := get("port"): node["server_port"] = v
    if v := get("username"): node["username"] = v
    if v := get("password"): node["password"] = v
    if v := get("path"): node["path"] = v
    if v := get("headers"): node["headers"] = v
    if get("tls"): _tls(node, get)
    _common(node, get)
    return node

def _socks5(cfg):
    get = cfg.get
    node = {"type": "socks", "version": "5"}
    if v := get("name"): node["tag"] = v
    if v := get("server"): node["server"] = v
    if v := get("port"): node["server_port"] = v
    if v := get("username"): node["username"] = v
    if v := get("password"): node["password"] = v
    if get("tls"): _tls(node, get)
    _common(node, get)
    return node

def _wireguard(cfg):
    get = cfg.get
    node = {"type": "wireguard"}
    if v := get("name"): node["tag"] = v
    if v := get("private-key"): node["private_key"] = v
    if v := get("mtu"): node["mtu"] = v

    addr = []
    if ip4 := get("ip"): addr.append(ip4 if "/" in ip4 else f"{ip4}/32")
    if ip6 := get("ipv6"): addr.append(ip6 if "/" in ip6 else f"{ip6}/128")
    if addr: node["address"] = addr

    if peers_raw := get("peers"):
        peers_out = []
        for cp in peers_raw:
            peer = {
                "address": cp.get("server"),
                "port": cp.get("port"),
                "public_key": cp.get("public-key"),
                "allowed_ips": cp.get("allowed-ips", ["0.0.0.0/0"]),
            }
            if (pki := cp.get("persistent-keepalive")) is not None:
                peer["persistent_keepalive_interval"] = pki
            if psk := cp.get("pre-shared-key"):
                peer["pre_shared_key"] = psk

            if reserved := cp.get("reserved"):
                t_res = type(reserved)
                if t_res is list:
                    peer["reserved"] = reserved
                elif t_res is str:
                    peer["reserved"] = [int(x.strip()) for x in reserved.split(",")] if "," in reserved else reserved
            peers_out.append(peer)
        if peers_out: node["peers"] = peers_out

    if dp := get("dialer-proxy"): node["detour"] = dp
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
        if not (handler := _TABLE_GET(cfg.get("type"))):
            return ""
        return handler(cfg)
    except Exception as e:
        print(f"Node conversion failed: {e}")
        return ""

parse = clash2sing