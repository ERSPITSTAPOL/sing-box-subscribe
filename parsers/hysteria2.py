import tool, re
from urllib.parse import urlparse, parse_qs, unquote

REGEX_PORT_RANGE = re.compile(r'(\d+)-(\d+)')

def parse(data) -> dict:
    if not data or hasattr(data, 'keys'): return data or {}
    info = data.strip()
    s_idx = info.find("://")

    if s_idx == -1: return {}
    rest = info[s_idx + 3:]
    end_pos = len(rest)

    for c in '/?#&':
        p = rest.find(c)
        if p != -1 and p < end_pos: end_pos = p
    netloc = rest[:end_pos]

    auth_part, sep_at, host_port = netloc.rpartition('@')

    password = ""
    if sep_at:
        password = auth_part.rpartition(':')[-1]

    if host_port.startswith('['):
        host, _, post = host_port[1:].partition(']:')
        raw_port = post
    else:
        h, sep_colon, p = host_port.rpartition(':')
        if sep_colon and any(c in p for c in '0123456789,-'):
            if p.replace('-', '').replace(',', '').isdigit():
                host, raw_port = h, p
            else:
                host, raw_port = host_port, ""
        else:
            host, raw_port = host_port, ""

    query_str = ""
    fragment = ""

    q_start = info.find('?')
    f_start = info.find('#')

    if q_start != -1:
        query_str = info[q_start+1:f_start] if f_start != -1 else info[q_start+1:]
    else:
        amp_start = info.find('&')
        if amp_start != -1 and (f_start == -1 or amp_start < f_start):
            query_str = info[amp_start+1:f_start] if f_start != -1 else info[amp_start+1:]

    netquery = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(query_str).items()}

    if f_start != -1:
        fragment = info[f_start+1:]

    if not password:
        password = netquery.get('auth', "")

    main_port = 443
    port_range = ""
    if raw_port:
        clean_raw_port = raw_port.split('&')[0].split('?')[0]
        if clean_raw_port.isdigit():
            main_port = int(clean_raw_port)
        else:
            main_port_part = clean_raw_port.partition(',')[0].partition('-')[0]
            if main_port_part.isdigit():
                main_port = int(main_port_part)
            potential_range = clean_raw_port.rpartition(',')[-1]
            if '-' in potential_range:
                port_range = potential_range.replace('-', ':')

    node = {
        'tag': unquote(fragment) or tool.genName() + '_hysteria2',
        'type': 'hysteria2',
        'server': host,
        'password': password,
        'server_port': main_port,
    }

    mport = netquery.get('mport')
    if mport:
        m = REGEX_PORT_RANGE.match(str(mport))
        if m: node['server_ports'] = f"{m.group(1)}:{m.group(2)}"
    elif port_range:
        node['server_ports'] = port_range

    sni = netquery.get('sni', netquery.get('peer', ''))
    is_insecure = str(netquery.get('insecure', netquery.get('allowInsecure', ''))).lower() in ('1', 'true')

    if not sni or str(sni).lower() == 'none':
        sni = None
        is_insecure = True

    node['tls'] = {
        'enabled': True,
        'insecure': is_insecure
    }
    if sni:
        node['tls']['server_name'] = sni

    alpn = netquery.get('alpn')
    if alpn:
        node['tls']['alpn'] = alpn.strip('{}').split(',') if isinstance(alpn, str) else [str(v).strip('{}') for v in alpn]
    else:
        node['tls']['alpn'] = ['h3']

    obfs = netquery.get('obfs')
    if obfs and obfs != 'none':
        node['obfs'] = {'type': obfs, 'password': netquery.get('obfs-password', '')}

    for k in ('upmbps', 'downmbps'):
        v = netquery.get(k)
        if v and str(v).isdigit():
            node[k.replace('mbps', '_mbps')] = int(v)

    if 'pinSHA256' in netquery:
        node['tls']['fingerprint'] = netquery['pinSHA256']

    return node