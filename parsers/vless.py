import tool, re
from urllib.parse import parse_qs, unquote

REGEX_WS_ED = re.compile(r'\?ed=(\d+)$')

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
    raw_netloc = rest[:end_pos]

    try:
        netloc = tool.b64Decode(raw_netloc).decode('utf-8')
    except:
        netloc = raw_netloc

    auth_part, sep_at, host_port = netloc.rpartition('@')
    if not sep_at:
        return None

    uuid = auth_part.split(':', 1)[-1]

    if host_port.startswith('['):
        server, _, post = host_port[1:].partition(']:')
        raw_port = post.lstrip(':')
    else:
        server, sep_colon, raw_port = host_port.rpartition(':')
        if not sep_colon:
            return None

    if raw_port.isdigit():
        server_port = int(raw_port)
        server = server.replace("[", "").replace("]", "")
    else:
        return None

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

    if f_start != -1:
        fragment = info[f_start+1:]

    netquery = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(query_str).items()}
    remarks = netquery.get('remarks') or fragment

    node = {
        'tag': unquote(remarks) or tool.genName() + '_vless',
        'type': 'vless',
        'server': server,
        'server_port': server_port,
        'uuid': uuid,
        'packet_encoding': netquery.get('packetEncoding', 'xudp')
    }

    if netquery.get('flow'):
        node['flow'] = 'xtls-rprx-vision'

    security = netquery.get('security', '')
    if (security.lower() not in ['none', '']) or netquery.get('tls') == '1':
        node['tls'] = {
            'enabled': True,
            'insecure': False,
            'server_name': ''
        }
        if netquery.get('allowInsecure') == '1':
            node['tls']['insecure'] = True

        sni = netquery.get('sni') or netquery.get('peer', '')
        node['tls']['server_name'] = '' if sni == 'None' else sni

        if netquery.get('alpn'):
            node['tls']['alpn'] = [unquote(a.strip()) for a in netquery['alpn'].strip('{}').split(',') if a.strip()]

        if netquery.get('fp'):
            node['tls']['utls'] = {
                'enabled': True,
                'fingerprint': netquery['fp']
            }

        if security == 'reality' or netquery.get('pbk'):
            node['tls']['reality'] = {
                'enabled': True,
                'public_key': netquery.get('pbk'),
            }
            sid = netquery.get('sid')
            if isinstance(sid, str) and sid.strip().lower() != "none":
                node['tls']['reality']['short_id'] = sid
            
            if 'utls' not in node['tls']:
                node['tls']['utls'] = {'enabled': True}

    transport_type = netquery.get('type')
    if transport_type:
        if transport_type == 'http':
            node['transport'] = {'type': 'http'}
        elif transport_type == 'ws':
            path_raw = netquery.get('path', '/')
            matches = REGEX_WS_ED.search(path_raw)
            node['transport'] = {
                'type': 'ws',
                "path": path_raw.rsplit("?ed=", 1)[0] if matches else path_raw,
                "headers": {
                    "Host": '' if netquery.get('host') is None and netquery.get('sni') == 'None' else netquery.get('host', netquery.get('sni', ''))
                }
            }
            if node.get('tls') and node['tls']['server_name'] == '':
                if node['transport']['headers']['Host']:
                    node['tls']['server_name'] = node['transport']['headers']['Host']
            if matches:
                node['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol'
                node['transport']['max_early_data'] = int(matches.group(1))
            else:
                if netquery.get('ed'):
                    node['transport']['max_early_data'] = int(netquery.get('ed'))
                if netquery.get('eh'):
                    node['transport']['early_data_header_name'] = netquery.get('eh')

        elif transport_type == 'grpc':
            node['transport'] = {
                'type': 'grpc',
                'service_name': netquery.get('serviceName', '')
            }
    elif netquery.get('obfs') == 'websocket':
        path_raw = netquery.get('path', '/')
        matches = REGEX_WS_ED.search(path_raw)
        node['transport'] = {
            'type': 'ws',
            "path": path_raw.rsplit("?ed=", 1)[0] if matches else path_raw,
            "headers": {
                "Host": '' if netquery.get('obfsParam') is None and netquery.get('sni') == 'None' else netquery.get('peer', netquery.get('obfsParam'))
            }
        }
        if node.get('tls') and node['tls']['server_name'] == '':
            if node['transport']['headers']['Host']:
                node['tls']['server_name'] = node['transport']['headers']['Host']
        if matches:
            node['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol'
            node['transport']['max_early_data'] = int(matches.group(1))
        # else:
        #     if netquery.get('ed'):
        #         node['transport']['max_early_data'] = int(netquery.get('ed'))
        #     if netquery.get('eh'):
        #         node['transport']['early_data_header_name'] = netquery.get('eh')

    if netquery.get('protocol') in ['smux', 'yamux', 'h2mux']:
        node['multiplex'] = {
            'enabled': True,
            'protocol': netquery['protocol']
        }
        if netquery.get('max-streams'):
            node['multiplex']['max_streams'] = int(netquery['max-streams'])
        else:
            if netquery.get('max-connections'):
                node['multiplex']['max_connections'] = int(netquery['max-connections'])
            if netquery.get('min-streams'):
                node['multiplex']['min_streams'] = int(netquery['min-streams'])
        if netquery.get('padding') == 'True':
            node['multiplex']['padding'] = True
    return node