import base64
from functools import partial
try:
    import orjson as json_lib
except ImportError:
    import json as json_lib

_PRUNE_EMPTY = (None, "", [], {})

def identity(v):
    return v

def to_int(v, default=None):
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

def to_bool(v, default=False):
    if v is None:
        return default
    return bool(v)

def to_str(v, default=""):
    if v is None:
        return default
    return str(v)

def to_list_if_str(v):
    if v is None:
        return None
    return v if isinstance(v, list) else [v]

def to_ms_string(v, default_ms=10000):
    if v is None:
        return f"{default_ms}ms"
    try:
        return f"{int(v)}ms"
    except (TypeError, ValueError):
        return str(v)

def parse_ports_raw(ports_raw):
    if not ports_raw:
        return None
    items = []
    for item in str(ports_raw).split(','):
        item = item.strip()
        if not item:
            continue
        if '-' in item:
            items.append(item.replace('-', ':'))
        else:
            items.append(item)
    if not items:
        return None
    return ",".join(items)

def parse_mbps(value):
    if not value:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip().split(' ')[0]
    digits = ''.join(ch for ch in s if ch.isdigit())
    return int(digits) if digits else 0

def safe_json_dumps(obj):
    try:
        dumped = json_lib.dumps(obj)
        if isinstance(dumped, bytes):
            return dumped.decode()
        return dumped
    except Exception:
        return str(obj)

def common_fields_builder(cfg):
    common = {}
    detour = cfg.get('dialer-proxy')
    if detour:
        common["detour"] = detour
    if 'routing-mark' in cfg:
        try:
            common["routing_mark"] = int(cfg['routing-mark'])
        except (TypeError, ValueError):
            pass
    iface = cfg.get('interface-name')
    if iface:
        common["bind_interface"] = iface
    if cfg.get('tfo'):
        common["tcp_fast_open"] = True
    if cfg.get('mptcp'):
        common["tcp_multi_path"] = True
    smux = cfg.get('smux')
    if smux and smux.get('enabled'):
        multiplex = {"enabled": True}
        if smux.get('protocol'):
            multiplex["protocol"] = smux['protocol']
        if 'max-connections' in smux:
            multiplex["max_connections"] = smux['max-connections']
        if 'min-streams' in smux:
            multiplex["min_streams"] = smux['min-streams']
        if 'max-streams' in smux:
            multiplex["max_streams"] = smux['max-streams']
        if smux.get('padding'):
            multiplex["padding"] = True
        brutal = smux.get('brutal-opts')
        if brutal and brutal.get('enabled'):
            multiplex["brutal"] = {
                "enabled": True,
                "up_mbps": brutal.get('up', 1000),
                "down_mbps": brutal.get('down', 1000)
            }
        common["multiplex"] = multiplex
    return common

def tls_config_builder(cfg):
    tls = {"enabled": True}
    server_name = cfg.get('servername') or cfg.get('sni')
    if server_name:
        tls["server_name"] = server_name
    if cfg.get('skip-cert-verify'):
        tls["insecure"] = True
    if cfg.get('disable-sni'):
        tls["disable_sni"] = True
    alpn = cfg.get('alpn')
    if alpn:
        tls["alpn"] = alpn if isinstance(alpn, list) else [alpn]
    else:
        if cfg.get('type') in ('hysteria', 'hysteria2', 'tuic'):
            tls["alpn"] = ["h3"]
    fp = cfg.get('client-fingerprint')
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    reality = cfg.get('reality-opts')
    if reality:
        tls["reality"] = {
            "enabled": True,
            "public_key": reality.get('public-key', ""),
            "short_id": reality.get('short-id', "")
        }
    ech = cfg.get('ech-opts')
    if ech and ech.get('enable'):
        ech_cfg = ech.get('config')
        decoded_cfg = ech_cfg
        if isinstance(ech_cfg, str):
            try:
                decoded_bytes = base64.b64decode(ech_cfg, validate=True)
                try:
                    decoded_cfg = decoded_bytes.decode('utf-8')
                except Exception:
                    decoded_cfg = base64.b64encode(decoded_bytes).decode('ascii')
            except Exception:
                decoded_cfg = ech_cfg
        if isinstance(decoded_cfg, bytes):
            decoded_cfg = base64.b64encode(decoded_cfg).decode('ascii')
        def _sanitize(obj):
            if isinstance(obj, bytes):
                return base64.b64encode(obj).decode('ascii')
            if isinstance(obj, dict):
                return {k: _sanitize(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_sanitize(v) for v in obj]
            return obj
        if isinstance(decoded_cfg, str):
            cfg_val = [decoded_cfg]
        else:
            cfg_val = _sanitize(decoded_cfg)
        ech_out = {"enabled": True, "config": cfg_val}
        if isinstance(ech, dict) and 'query-server-name' in ech:
            ech_out["query_server_name"] = ech.get('query-server-name')
        if isinstance(ech, dict) and 'config_path' in ech:
            ech_out["config_path"] = ech.get('config_path') or ""
        tls["ech"] = ech_out
    cert = cfg.get('certificate')
    if cert:
        if isinstance(cert, str) and cert.startswith('./'):
            tls["client_certificate_path"] = cert
        else:
            tls["client_certificate"] = [cert]
    key = cfg.get('private-key')
    if key:
        if isinstance(key, str) and key.startswith('./'):
            tls["client_key_path"] = key
        else:
            tls["client_key"] = [key]
    return tls

def transport_config_builder(cfg, net):
    if net in ("http", "h2"):
        opts = cfg.get('http-opts') or cfg.get('h2-opts') or {}
        if not opts:
            return {}
        path = opts.get('path')
        return {"transport": {
            "type": "http",
            "host": opts.get('host', []),
            "path": path[0] if isinstance(path, list) else path,
            "method": opts.get('method'),
            "headers": opts.get('headers')
        }}
    if net == "ws":
        opts = cfg.get('ws-opts', {})
        if not opts:
            return {}
        transport = {"type": "ws", "path": opts.get('path', '/'), "headers": opts.get('headers')}
        if opts.get('max-early-data'):
            try:
                transport["max_early_data"] = int(opts['max-early-data'])
            except (TypeError, ValueError):
                transport["max_early_data"] = opts['max-early-data']
        if opts.get('early-data-header-name'):
            transport["early_data_header_name"] = opts['early-data-header-name']
        return {"transport": transport}
    if net == "grpc":
        opts = cfg.get('grpc-opts', {})
        if not opts:
            return {}
        return {"transport": {"type": "grpc", "service_name": opts.get('grpc-service-name')}}
    return {}

FAST_IDENTITY = 0
FAST_STR = 1
FAST_INT = 2
FAST_BOOL = 3
FAST_LIST_IF_STR = 4
FAST_OTHER = -1

def _fast_id(conv):
    if conv is identity:
        return FAST_IDENTITY
    if conv is to_str:
        return FAST_STR
    if conv is to_int:
        return FAST_INT
    if conv is to_bool:
        return FAST_BOOL
    if conv is to_list_if_str:
        return FAST_LIST_IF_STR
    return FAST_OTHER

def _safe_name(prefix, idx):
    return f"_{prefix}_{idx}"

def _repr_default(default):
    return repr(default)

def _make_get_from_key_code(keys, raw_var="raw", cfg_var="cfg"):
    if not keys:
        return [f"{raw_var} = None"]
    if not isinstance(keys, (list, tuple)):
        keys = [keys]
    lines = []
    lines.append(f"{raw_var} = {cfg_var}.get({keys[0]!r})")
    for k in keys[1:]:
        lines.append(f"if {raw_var} is None:")
        lines.append(f"    {raw_var} = {cfg_var}.get({k!r})")
    return lines

_FAST_EXPR_TABLE = {
    FAST_IDENTITY:        "val = raw",
    FAST_INT:             "val = to_int(raw, None)",
    FAST_STR:             "val = to_str(raw, None)",
    FAST_BOOL:            "val = to_bool(raw, None)",
    FAST_LIST_IF_STR:     "val = to_list_if_str(raw)",
    FAST_OTHER:           "val = {conv}(raw)",
}

def _generate_field_code(idx, target, src_key, src_func_name, conv_name, default, cond_name, fast):
    lines = []
    indent = "    "
    if cond_name:
        lines.append(f"{indent}if {cond_name}(cfg):")
        indent += "    "
    if src_func_name:
        lines.append(f"{indent}raw = {src_func_name}(cfg)")
    else:
        key_lines = _make_get_from_key_code(src_key)
        if isinstance(key_lines, str):
            key_lines = [key_lines]
        for ln in key_lines:
            lines.append(f"{indent}{ln}")
    expr_tpl = _FAST_EXPR_TABLE[fast]
    if "{conv}" in expr_tpl:
        lines.append(f"{indent}{expr_tpl.format(conv=conv_name)}")
    else:
        lines.append(f"{indent}{expr_tpl}")
    if default is not None:
        lines.append(f"{indent}if val is None:")
        lines.append(f"{indent}    val = {_repr_default(default)}")
    lines.append(f"{indent}if val not in _PRUNE_EMPTY:")
    lines.append(f"{indent}    node[{target!r}] = val")
    return "\n".join(lines)

def compile_schema_to_function(schema, func_name):
    entries = []
    post_callable = None
    for item in schema:
        if isinstance(item, dict) and item.get("__post__"):
            post_callable = item["__post__"]
            continue
        if isinstance(item, tuple):
            target, src, conv, default, cond = (item + (None, None, None))[:5]
        elif isinstance(item, dict):
            target = item.get("target")
            src = item.get("src")
            conv = item.get("conv", identity)
            default = item.get("default", None)
            cond = item.get("cond", None)
        else:
            continue
        conv = conv or identity
        fast = _fast_id(conv)
        if callable(src):
            src_func = src
            src_key = None
        else:
            src_func = None
            src_key = src
        entries.append({
            "target": target,
            "src_key": src_key,
            "src_func": src_func,
            "conv": conv,
            "default": default,
            "cond": cond,
            "fast": fast,
        })
    func_lines = []
    func_lines.append(f"def {func_name}(cfg):")
    func_lines.append("    node = {}")
    func_lines.append("    # fields")
    inject_map = {}
    for idx, e in enumerate(entries):
        target = e["target"]
        src_key = e["src_key"]
        src_func = e["src_func"]
        conv = e["conv"]
        default = e["default"]
        cond = e["cond"]
        fast = e["fast"]
        src_func_name = None
        conv_name = None
        cond_name = None
        if src_func:
            src_func_name = _safe_name("srcfunc", idx)
            inject_map[src_func_name] = src_func
        if fast == FAST_OTHER:
            conv_name = _safe_name("conv", idx)
            inject_map[conv_name] = conv
        if cond:
            cond_name = _safe_name("cond", idx)
            inject_map[cond_name] = cond
        field_code = _generate_field_code(
            idx=idx,
            target=target,
            src_key=src_key,
            src_func_name=src_func_name,
            conv_name=conv_name,
            default=default,
            cond_name=cond_name,
            fast=fast,
        )
        func_lines.append(field_code)
    if post_callable:
        post_name = "_post_callable"
        inject_map[post_name] = post_callable
        func_lines.append("    try:")
        func_lines.append(f"        post_res = {post_name}(node, cfg)")
        func_lines.append("        if isinstance(post_res, dict):")
        func_lines.append("            node.update(post_res)")
        func_lines.append("    except Exception:")
        func_lines.append("        pass")
    func_lines.append("    return node")
    func_src = "\n".join(func_lines)
    exec_ns = {
        "_PRUNE_EMPTY": _PRUNE_EMPTY,
        "to_int": to_int,
        "to_bool": to_bool,
        "to_str": to_str,
        "to_list_if_str": to_list_if_str,
        "parse_ports_raw": parse_ports_raw,
        "parse_mbps": parse_mbps,
        "safe_json_dumps": safe_json_dumps,
        "tls_config_builder": tls_config_builder,
        "base64": base64,
        "identity": identity,
    }
    exec_ns.update(inject_map)
    try:
        compiled = compile(func_src, filename=f"<generated_{func_name}>", mode="exec")
        exec(compiled, exec_ns)
        generated_func = exec_ns[func_name]
    except Exception as e:
        raise RuntimeError(
            f"Failed to compile generated builder {func_name}: {e}\nSource:\n{func_src}"
        )
    generated_func.__generated_source__ = func_src
    return generated_func

def _ss_post(node, cfg):
    if cfg.get("udp-over-tcp", False) or "udp-over-tcp-version" in cfg:
        node["udp_over_tcp"] = {
            "enabled": cfg.get("udp-over-tcp", False),
            "version": cfg.get("udp-over-tcp-version", 2)
        }
    plugin = cfg.get("plugin")
    plugin_opts = cfg.get("plugin-opts", {}) or {}
    if plugin in ("obfs", "simple-obfs", "obfs-local"):
        node["plugin"] = "obfs-local"
        parts = [f"obfs={plugin_opts.get('mode', 'http')}"]
        if plugin_opts.get("host"):
            parts.append(f"obfs-host={plugin_opts['host']}")
        node["plugin_opts"] = ";".join(parts)
    elif plugin == "v2ray-plugin":
        node["plugin"] = "v2ray-plugin"
        parts = [f"mode={plugin_opts.get('mode', 'websocket')}"]
        if plugin_opts.get("host"):
            parts.append(f"host={plugin_opts['host']}")
        if plugin_opts.get("path"):
            parts.append("path=" + plugin_opts['path'])
        if plugin_opts.get("mux", False):
            parts.append("mux=1")
        if plugin_opts.get("headers"):
            parts.append("headers=" + safe_json_dumps(plugin_opts['headers']))
        if plugin_opts.get("skip-cert-verify", False):
            parts.append("skip-cert-verify=true")
        if plugin_opts.get("tls", False):
            parts.append("tls")
        node["plugin_opts"] = ";".join(parts)
    elif plugin == "shadow-tls":
        detour_tag = f"{node.get('tag','ss-out')}_shadowtls"
        node["detour"] = detour_tag
        fp = cfg.get("client-fingerprint")
        node_tls = {
            "tag": detour_tag,
            "type": "shadowtls",
            "server": node.get("server"),
            "server_port": node.get("server_port"),
            "version": to_int(plugin_opts.get("version", 1)),
            "password": plugin_opts.get("password", ""),
            "tls": {"enabled": True, "server_name": plugin_opts.get("host", "")}
        }
        if fp:
            node_tls["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
        node.pop("server", None)
        node.pop("server_port", None)
        return {"__node_tls__": node_tls}
    method = node.get("method", "") or ""
    if method == 'chacha20-poly1305':
        node['method'] = 'chacha20-ietf-poly1305'
    elif method == 'xchacha20-poly1305':
        node['method'] = 'xchacha20-ietf-poly1305'
    return node

SCHEMAS = {}

SCHEMAS['ss'] = [
    ("tag", "name", to_str, "ss-out", None),
    ("type", lambda cfg: "shadowsocks", identity, None, None),
    ("server", "server", to_str, None, None),
    ("server_port", "port", identity, None, None),
    ("method", "cipher", to_str, None, None),
    ("password", "password", to_str, "", None),
    {"__post__": _ss_post}
]

SCHEMAS['vmess'] = [
    ("tag", "name", to_str, "vmess-out", None),
    ("type", lambda cfg: "vmess", identity, None, None),
    ("server", "server", to_str, None, None),
    ("server_port", "port", identity, None, None),
    ("uuid", "uuid", to_str, None, None),
    ("security", "cipher", to_str, "auto", None),
    ("alter_id", "alterId", to_int, 0, None),
    ("global_padding", "global-padding", to_bool, False, None),
    ("authenticated_length", "authenticated-length", to_bool, False, None),
    ("packet_encoding", "packet-encoding", to_str, "", None),
    {"__post__": lambda node, cfg: (node.update({"tls": tls_config_builder(cfg)}) or node) if (cfg.get("tls", False) or cfg.get("reality-opts")) else node}
]

SCHEMAS['trojan'] = [
    ("type", lambda cfg: "trojan", identity, None, None),
    ("tag", "name", to_str, "trojan-out", None),
    ("server", "server", to_str, None, None),
    ("server_port", "port", identity, None, None),
    ("password", "password", to_str, None, None),
    {"__post__": lambda node, cfg: (node.update({"tls": (lambda t: (t.update({"enabled": True}) or t))(tls_config_builder(cfg))}) or node)}
]

SCHEMAS['vless'] = [
    ("tag", "name", to_str, "vless-out", None),
    ("type", lambda cfg: "vless", identity, None, None),
    ("server", "server", to_str, None, None),
    ("server_port", "port", identity, None, None),
    ("uuid", "uuid", to_str, None, None),
    ("flow", "flow", to_str, "", None),
    ("packet_encoding", "packet-encoding", to_str, "xudp", None),
    {"__post__": lambda node, cfg: (node.update({"tls": tls_config_builder(cfg)}) or node) if (cfg.get("tls", False) or cfg.get("reality-opts")) else node}
]

SCHEMAS['tuic'] = [
    ("tag", "name", to_str, "tuic-out", None),
    ("type", lambda cfg: "tuic", identity, None, None),
    ("server", "server", to_str, None, None),
    ("server_port", "port", identity, None, None),
    ("uuid", lambda cfg: cfg.get("token") or cfg.get("uuid"), to_str, None, None),
    ("password", "password", to_str, "", None),
    ("congestion_control", "congestion-controller", to_str, "bbr", None),
    ("udp_relay_mode", "udp-relay-mode", to_str, "native", None),
    ("udp_over_stream", "udp-over-stream", to_bool, False, None),
    ("zero_rtt_handshake", "reduce-rtt", to_bool, False, None),
    ("heartbeat", "heartbeat-interval", to_ms_string, "10000ms", None),
    {"__post__": lambda node, cfg: (node.update({"tls": (lambda t: (t.update({"server_name": ""}) if cfg.get("disable-sni", False) else t) or t)(tls_config_builder(cfg))}) or node) if ("disable-sni" in cfg or cfg.get("tls", False)) else node}
]

SCHEMAS['hysteria'] = [
    ("tag", "name", to_str, "hysteria-out", None),
    ("type", lambda cfg: "hysteria", identity, None, None),
    ("server", "server", to_str, None, None),
    ("server_port", "port", identity, None, None),
    ("server_ports", "ports", parse_ports_raw, None, None),
    ("up", "up", to_str, "1000 Mbps", None),
    ("up_mbps", "up", parse_mbps, 1000, None),
    ("down", "down", to_str, "1000 Mbps", None),
    ("down_mbps", "down", parse_mbps, 1000, None),
    ("obfs", "obfs", to_str, "", None),
    ("auth_str", "auth-str", to_str, "", None),
    ("recv_window_conn", "recv-window-conn", to_int, 0, None),
    ("recv_window", "recv-window", to_int, 0, None),
    ("disable_mtu_discovery", "disable_mtu_discovery", to_bool, False, None),
    {"__post__": lambda node, cfg: (node.update({"tls": (lambda t: (t.update({"enabled": True}) or t))(tls_config_builder(cfg))}) or node)}
]

SCHEMAS['hysteria2'] = [
    ("tag", "name", to_str, "hy2-out", None),
    ("type", lambda cfg: "hysteria2", identity, None, None),
    ("server", "server", to_str, None, None),
    ("server_port", "port", identity, None, None),
    ("server_ports", "ports", parse_ports_raw, None, None),
    ("password", "password", to_str, None, None),
    ("up_mbps", "up", to_int, 1000, None),
    ("down_mbps", "down", to_int, 1000, None),
    {"__post__": lambda node, cfg: (node.update({"tls": (lambda t: (t.update({"enabled": True}) or t))(tls_config_builder(cfg))}) or node)}
]

SCHEMAS['anytls'] = [
    ("tag", "name", to_str, "anytls-out", None),
    ("type", lambda cfg: "anytls", identity, None, None),
    ("server", "server", to_str, None, None),
    ("server_port", "port", identity, None, None),
    ("password", "password", to_str, None, None),
    ("idle_session_check_interval", "idle-session-check-interval", lambda v: f"{v or 30}s", "30s", None),
    ("idle_session_timeout", "idle-session-timeout", lambda v: f"{v or 30}s", "30s", None),
    ("min_idle_session", "min-idle-session", to_int, 1, None),
    {"__post__": lambda node, cfg: (node.update({"tls": (lambda t: (t.update({"enabled": True}) or t))(tls_config_builder(cfg))}) or node)}
]

SCHEMAS['wireguard'] = [
    ("type", lambda cfg: "wireguard", identity, None, None),
    ("tag", "name", to_str, "wg-out", None),
    ("private_key", "private-key", to_str, None, None),
    ("mtu", "mtu", to_int, 1408, None),
    ("peers", "peers", identity, [], None),
    {"__post__": lambda node, cfg: node}
]

SCHEMAS['http'] = [
    ("type", lambda cfg: "http", identity, None, None),
    ("tag", "name", to_str, "http-out", None),
    ("server", "server", to_str, None, None),
    ("server_port", "port", identity, None, None),
    ("username", "username", to_str, "", None),
    ("password", "password", to_str, "", None),
    ("path", "path", to_str, "", None),
    ("headers", "headers", identity, {}, None),
    {"__post__": lambda node, cfg: (node.update({"tls": tls_config_builder(cfg)}) or node) if cfg.get("tls", False) else node}
]

SCHEMAS['socks5'] = [
    ("type", lambda cfg: "socks", identity, None, None),
    ("tag", "name", to_str, "socks-out", None),
    ("server", "server", to_str, None, None),
    ("server_port", "port", identity, None, None),
    ("version", lambda cfg: "5", identity, "5", None),
    ("username", "username", to_str, "", None),
    ("password", "password", to_str, "", None),
    {"__post__": lambda node, cfg: node}
]

BUILDERS = {}
for proto, schema in SCHEMAS.items():
    func_name = f"build_{proto}"
    try:
        BUILDERS[proto] = compile_schema_to_function(schema, func_name)
    except Exception:
        def fallback_builder(cfg, _schema=schema):
            node = {}
            def _get(cfg, src):
                if callable(src):
                    return src(cfg)
                if isinstance(src, (list, tuple)):
                    for k in src:
                        if k in cfg:
                            return cfg.get(k)
                    return None
                return cfg.get(src)
            for item in _schema:
                if isinstance(item, dict) and item.get("__post__"):
                    continue
                if isinstance(item, tuple):
                    target, src, conv, default, cond = (item + (None, None, None))[:5]
                elif isinstance(item, dict):
                    target = item.get("target")
                    src = item.get("src")
                    conv = item.get("conv", identity)
                    default = item.get("default", None)
                    cond = item.get("cond", None)
                else:
                    continue
                if cond and not cond(cfg):
                    continue
                raw = _get(cfg, src)
                try:
                    val = conv(raw)
                except Exception:
                    val = None
                if val is None:
                    val = default
                if val not in _PRUNE_EMPTY:
                    node[target] = val
            for item in _schema:
                if isinstance(item, dict) and item.get("__post__"):
                    try:
                        post_res = item["__post__"](node, cfg)
                        if isinstance(post_res, dict):
                            node.update(post_res)
                    except Exception:
                        pass
            return node
        BUILDERS[proto] = fallback_builder

def _wireguard_post(node, cfg):
    peers_out = []
    clash_peers = cfg.get("peers", []) or []
    for cp in clash_peers:
        peer = {
            "address": cp.get("server"),
            "port": to_int(cp.get("port", 51820)),
            "public_key": cp.get("public-key"),
            "allowed_ips": cp.get("allowed-ips", ["0.0.0.0/0"]),
            "persistent_keepalive_interval": 30
        }
        if cp.get("pre-shared-key"):
            peer["pre_shared_key"] = cp.get("pre-shared-key")
        reserved = cp.get("reserved")
        if reserved:
            if isinstance(reserved, list):
                peer["reserved"] = reserved
            elif isinstance(reserved, str):
                if "," in reserved:
                    peer["reserved"] = [int(x.strip()) for x in reserved.split(",")]
                else:
                    peer["reserved"] = reserved
        peers_out.append(peer)
    node["peers"] = peers_out
    address = []
    ip4 = cfg.get("ip")
    if ip4:
        address.append(ip4 + "/32" if "/" not in ip4 else ip4)
    ip6 = cfg.get("ipv6")
    if ip6:
        address.append(ip6 + "/128" if "/" not in ip6 else ip6)
    if address:
        node["address"] = address
    if cfg.get("dialer-proxy"):
        node["detour"] = cfg.get("dialer-proxy")
    return node

def wireguard_builder(cfg):
    node = BUILDERS.get('wireguard', lambda c: {})(cfg)
    node = _wireguard_post(node, cfg)
    return node

def ss_builder(cfg):
    res = BUILDERS.get('ss', lambda c: {})(cfg)
    if isinstance(res, dict) and "__node_tls__" in res:
        node_tls = res.pop("__node_tls__")
        return res, node_tls
    return res

def generic_builder_with_transport(proto, cfg):
    builder = BUILDERS.get(proto)
    if not builder:
        return None
    node = builder(cfg)
    net = cfg.get("network", "tcp")
    if net != "tcp":
        t = transport_config_builder(cfg, net)
        if t:
            node.update(t)
    common = common_fields_builder(cfg)
    if common:
        node.update(common)
    return node

PROTOCOLTABLE = {
    'ss': ss_builder,
    'vmess': lambda cfg: generic_builder_with_transport('vmess', cfg),
    'trojan': lambda cfg: generic_builder_with_transport('trojan', cfg),
    'vless': lambda cfg: generic_builder_with_transport('vless', cfg),
    'tuic': lambda cfg: generic_builder_with_transport('tuic', cfg),
    'hysteria': lambda cfg: generic_builder_with_transport('hysteria', cfg),
    'hysteria2': lambda cfg: generic_builder_with_transport('hysteria2', cfg),
    'anytls': lambda cfg: generic_builder_with_transport('anytls', cfg),
    'wireguard': lambda cfg: wireguard_builder(cfg),
    'http': lambda cfg: generic_builder_with_transport('http', cfg),
    'socks5': lambda cfg: generic_builder_with_transport('socks5', cfg),
}

def prune(data):
    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            pv = prune(v)
            if pv not in _PRUNE_EMPTY:
                out[k] = pv
        return out
    if isinstance(data, list):
        out = []
        for x in data:
            px = prune(x)
            if px not in _PRUNE_EMPTY:
                out.append(px)
        return out
    if isinstance(data, tuple):
        return tuple(prune(x) for x in data)
    return data

def clash2sing(clash_config):
    if not isinstance(clash_config, dict):
        return ''
    proto_type = clash_config.get('type')
    handler = PROTOCOLTABLE.get(proto_type)
    if not handler:
        return ''
    try:
        result = handler(clash_config)
        if isinstance(result, tuple):
            node, node_tls = result
            return prune(node), prune(node_tls)
        cleaned = prune(result)
        return cleaned
    except Exception as e:
        print(f"转换失败: {e}")
        return ''