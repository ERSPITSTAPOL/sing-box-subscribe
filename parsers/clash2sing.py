import orjson as json

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
        dumped = json.dumps(obj)
        if isinstance(dumped, bytes):
            return dumped.decode()
        return dumped
    except Exception:
        return str(obj)

def common_fields_builder(cfg):
    common = {}
    if (detour := cfg.get('dialer-proxy')):
        common["detour"] = detour
    if 'routing-mark' in cfg:
        if (rm := cfg.get('routing-mark')) is not None:
             common["routing_mark"] = rm
    if (iface := cfg.get('interface-name')):
        common["bind_interface"] = iface
    if cfg.get('tfo'):
        common["tcp_fast_open"] = True
    if cfg.get('mptcp'):
        common["tcp_multi_path"] = True
    if (smux := cfg.get('smux')) and smux.get('enabled'):
        multiplex = {"enabled": True}
        if (proto := smux.get('protocol')):
            multiplex["protocol"] = proto
        if (max_conn := smux.get('max-connections')):
            multiplex["max_connections"] = max_conn
        if (min_streams := smux.get('min-streams')):
            multiplex["min_streams"] = min_streams
        if (max_streams := smux.get('max-streams')):
            multiplex["max_streams"] = max_streams
        if smux.get('padding'):
            multiplex["padding"] = True
        if (brutal := smux.get('brutal-opts')) and brutal.get('enabled'):
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
    if (alpn := cfg.get('alpn')):
        tls["alpn"] = alpn if isinstance(alpn, list) else [alpn]
    elif cfg.get('type') in ('hysteria', 'hysteria2', 'tuic'):
        tls["alpn"] = ["h3"]
    if (fp := cfg.get('client-fingerprint')):
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if (reality := cfg.get('reality-opts')):
        tls["reality"] = {
            "enabled": True,
            "public_key": reality.get('public-key', ""),
            "short_id": reality.get('short-id', "")
        }
    if (ech := cfg.get('ech-opts')) and ech.get('enable'):
        ech_cfg = ech.get('config')
        ech_out = {"enabled": True}
        if ech_cfg:
            pem_string = f"-----BEGIN ECH CONFIG-----\n{ech_cfg}\n-----END ECH CONFIG-----"
            ech_out["config"] = [pem_string]
        else:
            pass
        if isinstance(ech, dict):
            if (qsn := ech.get('query-server-name')):
                ech_out["query_server_name"] = qsn
            if (cp := ech.get('config_path')):
                ech_out["config_path"] = cp
        tls["ech"] = ech_out
    if (cert := cfg.get('certificate')):
        if isinstance(cert, str) and cert.startswith('./'):
            tls["client_certificate_path"] = cert
        else:
            tls["client_certificate"] = [cert]
    if (key := cfg.get('private-key')):
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
        transport_inner = {"type": "http"}
        if (host := opts.get('host')):
             transport_inner["host"] = host
        path = opts.get('path')
        if path:
             transport_inner["path"] = path[0] if isinstance(path, list) else path
        if (method := opts.get('method')):
             transport_inner["method"] = method
        if (headers := opts.get('headers')):
             transport_inner["headers"] = headers
        return {"transport": transport_inner}
    if net == "ws":
        opts = cfg.get('ws-opts', {})
        if not opts:
            return {}
        transport_inner = {"type": "ws"}
        transport_inner["path"] = opts.get('path', '/')
        if (headers := opts.get('headers')):
            transport_inner["headers"] = headers
        if (med := opts.get('max-early-data')):
            try:
                transport_inner["max_early_data"] = int(med)
            except (TypeError, ValueError):
                transport_inner["max_early_data"] = med
        if (edhn := opts.get('early-data-header-name')):
            transport_inner["early_data_header_name"] = edhn
        return {"transport": transport_inner}
    if net == "grpc":
        opts = cfg.get('grpc-opts', {})
        if not opts:
            return {}
        transport_inner = {"type": "grpc"}
        if (sn := opts.get('grpc-service-name')):
            transport_inner["service_name"] = sn
        return {"transport": transport_inner}
    return {}

FAST_IDENTITY = 0
FAST_LIST_IF_STR = 1
FAST_OTHER = -1

def _fast_id(conv):
    if conv is None:
        return FAST_IDENTITY
    if conv is to_list_if_str:
        return FAST_LIST_IF_STR
    return FAST_OTHER

def _safe_name(prefix, idx):
    return f"_{prefix}_{idx}"

def _repr_default(default):
    return repr(default)

def _generate_field_code(idx, target, src_key, src_func_name, conv_name, default, cond_name, fast):
    lines = []
    indent = "    "
    if cond_name:
        lines.append(f"{indent}if {cond_name}(cfg):")
        indent += "    "
    if src_func_name:
        lines.append(f"{indent}val = {src_func_name}(cfg)")
        if fast == FAST_IDENTITY:
            lines.append(f"{indent}if val is not None:")
            lines.append(f"{indent}    node[{target!r}] = val")
        else:
            lines.append(f"{indent}if val:")
            lines.append(f"{indent}    node[{target!r}] = val")
    else:
        keys = src_key if isinstance(src_key, (list, tuple)) else [src_key]
        primary_key = keys[0]
        if default is None:
            if len(keys) == 1:
                lines.append(f"{indent}if (raw := cfg_get({primary_key!r})) is not None:")
                indent += "    "
                if fast == FAST_LIST_IF_STR:
                    lines.append(f"{indent}if (val := to_list_if_str(raw)):")
                    lines.append(f"{indent}    node[{target!r}] = val")
                elif fast == FAST_IDENTITY:
                    lines.append(f"{indent}if raw:")
                    lines.append(f"{indent}    node[{target!r}] = raw")
                else:
                    lines.append(f"{indent}val = {conv_name}(raw)")
                    lines.append(f"{indent}if val:")
                    lines.append(f"{indent}    node[{target!r}] = val")
            else:
                lines.append(f"{indent}raw = cfg_get({primary_key!r})")
                for k in keys[1:]:
                    lines.append(f"{indent}if raw is None: raw = cfg_get({k!r})")
                lines.append(f"{indent}if raw is not None:")
                indent += "    "
                if fast == FAST_LIST_IF_STR:
                    lines.append(f"{indent}if (val := to_list_if_str(raw)): node[{target!r}] = val")
                elif fast == FAST_IDENTITY:
                    lines.append(f"{indent}if (val := raw) is not None: node[{target!r}] = val")
                else:
                    lines.append(f"{indent}val = {conv_name}(raw) if {conv_name} else raw")
                    lines.append(f"{indent}if val: node[{target!r}] = val")
        else:
            lines.append(f"{indent}raw = cfg_get({primary_key!r})")
            for k in keys[1:]:
                lines.append(f"{indent}if raw is None: raw = cfg_get({k!r})")
            default_repr = _repr_default(default)
            if fast == FAST_LIST_IF_STR:
                lines.append(f"{indent}val = to_list_if_str(raw) if raw is not None else {default_repr}")
                lines.append(f"{indent}if val: node[{target!r}] = val")
            elif fast == FAST_IDENTITY:
                lines.append(f"{indent}val = raw if raw is not None else {default_repr}")
                lines.append(f"{indent}if val is not None: node[{target!r}] = val")
            else:
                lines.append(f"{indent}val = {conv_name}(raw) if raw is not None else {default_repr}")
                lines.append(f"{indent}if val: node[{target!r}] = val")
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
            conv = item.get("conv", None)
            default = item.get("default", None)
            cond = item.get("cond", None)
        else:
            continue
        conv = conv
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
    func_lines.append("    cfg_get = cfg.get")
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
        "to_list_if_str": to_list_if_str,
        "parse_ports_raw": parse_ports_raw,
        "parse_mbps": parse_mbps,
        "safe_json_dumps": safe_json_dumps,
        "tls_config_builder": tls_config_builder,
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
    if plugin:
        plugin_opts = cfg.get("plugin-opts", {}) or {}
        if plugin in ("obfs", "simple-obfs", "obfs-local"):
            node["plugin"] = "obfs-local"
            parts = [f"obfs={plugin_opts.get('mode', 'http')}"]
            if (h := plugin_opts.get("host")):
                parts.append(f"obfs-host={h}")
            node["plugin_opts"] = ";".join(parts)
        elif plugin == "v2ray-plugin":
            node["plugin"] = "v2ray-plugin"
            parts = [f"mode={plugin_opts.get('mode', 'websocket')}"]
            if (h := plugin_opts.get("host")):
                parts.append(f"host={h}")
            if (p := plugin_opts.get("path")):
                parts.append("path=" + p)
            if plugin_opts.get("mux", False):
                parts.append("mux=1")
            if (hdrs := plugin_opts.get("headers")):
                parts.append("headers=" + safe_json_dumps(hdrs))
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
                "version": plugin_opts.get("version", 1),
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

def _wireguard_post(node, cfg):
    peers_out = []
    clash_peers = cfg.get("peers", []) or []
    for cp in clash_peers:
        peer = {
            "address": cp.get("server"),
            "port": cp.get("port", 51820),
            "public_key": cp.get("public-key"),
            "allowed_ips": cp.get("allowed-ips", ["0.0.0.0/0"]),
            "persistent_keepalive_interval": 30
        }
        if (psk := cp.get("pre-shared-key")):
            peer["pre_shared_key"] = psk
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
    if peers_out:
        node["peers"] = peers_out
    address = []
    if (ip4 := cfg.get("ip")):
        address.append(ip4 + "/32" if "/" not in ip4 else ip4)
    if (ip6 := cfg.get("ipv6")):
        address.append(ip6 + "/128" if "/" not in ip6 else ip6)
    if address:
        node["address"] = address
    if (dp := cfg.get("dialer-proxy")):
        node["detour"] = dp
    return node

SCHEMAS = {}

SCHEMAS['ss'] = [
    ("tag", "name", None, None, None),
    ("type", lambda cfg: "shadowsocks", None, None, None),
    ("server", "server", None, None, None),
    ("server_port", "port", None, None, None),
    ("method", "cipher", None, None, None),
    ("password", "password", None, None, None),
    {"__post__": _ss_post}
]

SCHEMAS['vmess'] = [
    ("tag", "name", None, None, None),
    ("type", lambda cfg: "vmess", None, None, None),
    ("server", "server", None, None, None),
    ("server_port", "port", None, None, None),
    ("uuid", "uuid", None, None, None),
    ("security", "cipher", None, None, None),
    ("alter_id", "alterId", None, None, None),
    ("global_padding", "global-padding", None, None, None),
    ("authenticated_length", "authenticated-length", None, None, None),
    ("packet_encoding", "packet-encoding", None, None, None),
    {"__post__": lambda node, cfg: node.update({"tls": tls_config_builder(cfg)}) if (cfg.get("tls", False)) else None}
]

SCHEMAS['trojan'] = [
    ("tag", "name", None, None, None),
    ("type", lambda cfg: "trojan", None, None, None),
    ("server", "server", None, None, None),
    ("server_port", "port", None, None, None),
    ("password", "password", None, None, None),
    {"__post__": lambda node, cfg: node.update({"tls": tls_config_builder(cfg)}) or None}
]

SCHEMAS['vless'] = [
    ("tag", "name", None, None, None),
    ("type", lambda cfg: "vless", None, None, None),
    ("server", "server", None, None, None),
    ("server_port", "port", None, None, None),
    ("uuid", "uuid", None, None, None),
    ("flow", "flow", None, None, None),
    ("packet_encoding", "packet-encoding", None, "xudp", None),
    {"__post__": lambda node, cfg: node.update({"tls": tls_config_builder(cfg)}) if (cfg.get("tls", False)) else None}
]

SCHEMAS['tuic'] = [
    ("tag", "name", None, None, None),
    ("type", lambda cfg: "tuic", None, None, None),
    ("server", "server", None, None, None),
    ("server_port", "port", None, None, None),
    ("uuid", "uuid", None, None, None),
    ("password", "password", None, None, None),
    ("congestion_control", "congestion-controller", None, None, None),
    ("udp_relay_mode", "udp-relay-mode", None, None, None),
    ("udp_over_stream", "udp-over-stream", None, None, None),
    ("zero_rtt_handshake", "reduce-rtt", None, None, None),
    ("heartbeat", "heartbeat-interval", to_ms_string, None, None),
    {"__post__": lambda node, cfg: node.update({"tls": (lambda t: (t.update({"server_name": ""}) if cfg.get("disable-sni", False) else t) or t)(tls_config_builder(cfg))}) if ("disable-sni" in cfg or cfg.get("tls", False)) else None}
]

SCHEMAS['hysteria'] = [
    ("tag", "name", None, None, None),
    ("type", lambda cfg: "hysteria", None, None, None),
    ("server", "server", None, None, None),
    ("server_port", "port", None, None, None),
    ("server_ports", "ports", parse_ports_raw, None, None),
    ("up", "up", None, None, None),
    ("up_mbps", "up", parse_mbps, None, None),
    ("down", "down", None, None, None),
    ("down_mbps", "down", parse_mbps, None, None),
    ("obfs", "obfs", None, None, None),
    ("auth_str", "auth-str", None, None, None),
    ("recv_window_conn", "recv-window-conn", None, None, None),
    ("recv_window", "recv-window", None, None, None),
    ("disable_mtu_discovery", "disable_mtu_discovery", None, None, None),
    {"__post__": lambda node, cfg: node.update({"tls": tls_config_builder(cfg)})}
]

SCHEMAS['hysteria2'] = [
    ("tag", "name", None, None, None),
    ("type", lambda cfg: "hysteria2", None, None, None),
    ("server", "server", None, None, None),
    ("server_port", "port", None, None, None),
    ("server_ports", "ports", parse_ports_raw, None, None),
    ("password", "password", None, None, None),
    ("up_mbps", "up", None, None, None),
    ("down_mbps", "down", None, None, None),
    {"__post__": lambda node, cfg: node.update({"tls": tls_config_builder(cfg)})}
]

SCHEMAS['anytls'] = [
    ("tag", "name", None, None, None),
    ("type", lambda cfg: "anytls", None, None, None),
    ("server", "server", None, None, None),
    ("server_port", "port", None, None, None),
    ("password", "password", None, None, None),
    ("idle_session_check_interval", "idle-session-check-interval", lambda v: f"{v}s" if v else None, None, None),
    ("idle_session_timeout", "idle-session-timeout", lambda v: f"{v}s" if v else None, None, None),
    ("min_idle_session", "min-idle-session", None, None, None),
    {"__post__": lambda node, cfg: node.update({"tls": tls_config_builder(cfg)})}
]

SCHEMAS['wireguard'] = [
    ("tag", "name", None, None, None),
    ("type", lambda cfg: "wireguard", None, None, None),
    ("private_key", "private-key", None, None, None),
    ("mtu", "mtu", None, None, None),
    {"__post__": lambda node, cfg: _wireguard_post(node, cfg)}
]

SCHEMAS['http'] = [
    ("tag", "name", None, None, None),
    ("type", lambda cfg: "http", None, None, None),
    ("server", "server", None, None, None),
    ("server_port", "port", None, None, None),
    ("username", "username", None, None, None),
    ("password", "password", None, None, None),
    ("path", "path", None, None, None),
    ("headers", "headers", None, None, None),
    {"__post__": lambda node, cfg: node.update({"tls": tls_config_builder(cfg)}) if cfg.get("tls", False) else None}
]

SCHEMAS['socks5'] = [
    ("type", lambda cfg: "socks", None, None, None),
    ("tag", "name", None, None, None),
    ("server", "server", None, None, None),
    ("server_port", "port", None, None, None),
    ("version", lambda cfg: "5", None, None, None),
    ("username", "username", None, None, None),
    ("password", "password", None, None, None),
]

BUILDERS = {}
for proto, schema in SCHEMAS.items():
    func_name = f"build_{proto}"
    try:
        BUILDERS[proto] = compile_schema_to_function(schema, func_name)
    except Exception as e:
        print(f"Error compiling {proto}: {e}")

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
        if (t := transport_config_builder(cfg, net)):
            node.update(t)
    if (common := common_fields_builder(cfg)):
        node.update(common)
    return node

def wireguard_builder(cfg):
    return BUILDERS.get('wireguard', lambda c: {})(cfg)

PROTOCOLTABLE = {
    'ss': ss_builder,
    'vmess': lambda cfg: generic_builder_with_transport('vmess', cfg),
    'trojan': lambda cfg: generic_builder_with_transport('trojan', cfg),
    'vless': lambda cfg: generic_builder_with_transport('vless', cfg),
    'tuic': lambda cfg: generic_builder_with_transport('tuic', cfg),
    'hysteria': lambda cfg: generic_builder_with_transport('hysteria', cfg),
    'hysteria2': lambda cfg: generic_builder_with_transport('hysteria2', cfg),
    'anytls': lambda cfg: generic_builder_with_transport('anytls', cfg),
    'wireguard': wireguard_builder,
    'http': lambda cfg: generic_builder_with_transport('http', cfg),
    'socks5': lambda cfg: generic_builder_with_transport('socks5', cfg),
}

def clash2sing(clash_config):
    if not isinstance(clash_config, dict):
        return ''
    proto_type = clash_config.get('type')
    handler = PROTOCOLTABLE.get(proto_type)
    if not handler:
        return ''
    try:
        result = handler(clash_config)
        return result
    except Exception as e:
        print(f"转换失败: {e}")
        return ''