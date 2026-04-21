import re
from tool import genName, b64Decode
from urllib.parse import unquote, unquote_plus

RE_AT_CREDS = re.compile(r'^(.*?)@(.+):(\d+)$')
RE_UNESCAPED_SEMI = re.compile(r'(?<!\\);')
RE_UNESCAPED_EQ = re.compile(r'(?<!\\)=')
RE_UNESCAPE_CHAR = re.compile(r'\\([\s\S])')

def _try_b64url_decode(b64func, s):
    if not s:
        return None
    pad = (-len(s)) % 4
    s_padded = s + ('=' * pad)
    try:
        decoded = b64func(s_padded)
    except Exception:
        return None
    if not isinstance(decoded, (bytes, bytearray)):
        return None
    try:
        txt = decoded.decode('utf-8', errors='strict')
    except Exception:
        return None
    return txt if ':' in txt else None

def _parse_plugin_options(raw):
    if not raw:
        return None, {}

    tokens = RE_UNESCAPED_SEMI.split(raw)
    if not tokens:
        return None, {}

    plugin_name = RE_UNESCAPE_CHAR.sub(r'\1', tokens[0])
    opts = {}

    for token in tokens[1:]:
        if not token:
            continue
        parts = RE_UNESCAPED_EQ.split(token, maxsplit=1)
        key = RE_UNESCAPE_CHAR.sub(r'\1', parts[0]).strip()
        if key:
            val = RE_UNESCAPE_CHAR.sub(r'\1', parts[1]) if len(parts) > 1 else ''
            opts[key] = val

    return plugin_name, opts

def parse(data):
    if not data or not data.startswith('ss://') or len(data) <= 5:
        return None
    
    tail = data[5:]
    tag = None

    if '#' in tail:
        tail, _, frag = tail.partition('#')
        if frag:
            tag = unquote_plus(frag)

    query = ''
    if '?' in tail:
        tail, _, query = tail.partition('?')

    node = {
        'tag': tag,
        'type': 'shadowsocks',
        'server': None,
        'server_port': 0,
        'method': None,
        'password': None,
    }

    plugin_raw = None
    if query:
        for part in query.split('&'):
            if part.startswith('plugin='):
                plugin_raw = unquote(part[7:])
                break

    if plugin_raw:
        plugin_name, plugin_opts = _parse_plugin_options(plugin_raw)
        if plugin_name:
            node['plugin'] = plugin_name
            if plugin_opts:
                parts = [f"{k}={v}" if v != '' else k for k, v in plugin_opts.items()]
                node['plugin_opts'] = ';'.join(parts)
            else:
                node['plugin_opts'] = ''

    if tail.endswith('/'):
        tail = tail[:-1]

    m = RE_AT_CREDS.match(tail)
    if not m:
        return None
    credentials, host, port = m.groups()
    node['server'] = host[1:-1] if host.startswith('[') and host.endswith(']') else host
    node['server_port'] = port

    decoded_cred = _try_b64url_decode(b64Decode, credentials)
    if decoded_cred:
        parts = decoded_cred.split(':', 1)
        if len(parts) != 2:
            return None
        node['method'], node['password'] = parts
    else:
        if ':' in credentials:
            parts = credentials.split(':', 1)
            if len(parts) != 2:
                return None
            node['method'] = unquote(parts[0])
            node['password'] = unquote(parts[1])
        else:
            dec = unquote(credentials)
            parts = dec.split(':', 1)
            if len(parts) != 2:
                return None
            node['method'], node['password'] = parts

    try:
        node['server_port'] = int(node['server_port'])
    except Exception:
        node['server_port'] = 0

    if node.get('tag') is None:
        node['tag'] = genName() + '_shadowsocks'

    return node