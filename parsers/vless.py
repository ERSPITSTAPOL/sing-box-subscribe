import re
import tool
from urllib.parse import unquote

REGEX_WS_ED = re.compile(r'\?ed=(\d+)$')

def parse(data: str) -> dict:
    main_part_full, _, fragment = data.partition('#')
    at_idx = main_part_full.find('@', 8)
    if at_idx == -1:
        return None
    uuid = main_part_full[8:at_idx].split(':')[-1]
    rest = main_part_full[at_idx+1:]

    netloc_and_path, _, query_str = rest.partition('?')
    hp_part, _, _ = netloc_and_path.partition('/')

    if hp_part.startswith('['):
        r_idx = hp_part.rfind(']')
        server = hp_part[1:r_idx]
        p_part = hp_part[r_idx+1:]
        server_port = int(p_part[1:]) if p_part.startswith(':') else 443
    else:
        r_idx = hp_part.rfind(':')
        if r_idx != -1:
            p_str = hp_part[r_idx+1:]
            if p_str.isdigit():
                server = hp_part[:r_idx]
                server_port = int(p_str)
            else:
                server = hp_part
                server_port = 443
        else:
            server = hp_part
            server_port = 443

    params = {}
    if query_str:
        for pair in query_str.split('&'):
            if pair:
                k, _, v = pair.partition('=')
                params[k] = v

    get = params.get
    security = get('security', '').lower()
    transport_type = get('type')

    path_raw = unquote(get('path', '/'))

    node = {
        'tag': unquote(get('remarks') or fragment) or (tool.genName() + '_vless'),
        'type': 'vless',
        'server': server,
        'server_port': server_port,
        'uuid': uuid,
        'packet_encoding': get('packetEncoding', 'xudp')
    }

    if (flow := get('flow')): 
        node['flow'] = flow

    if security not in ('none', '') or get('tls') == '1':
        sni = get('sni') or get('peer') or ''
        tls_config = {
            'enabled': True,
            'insecure': get('allowInsecure') == '1',
            'server_name': '' if sni == 'None' else sni
        }
        if (alpn := get('alpn')):
            tls_config['alpn'] = [unquote(a.strip()) for a in alpn.strip('{}').split(',') if a]
        if (fp := get('fp')):
            tls_config['utls'] = {'enabled': True, 'fingerprint': fp}
        if security == 'reality' or get('pbk'):
            reality = {'enabled': True, 'public_key': get('pbk')}
            sid = get('sid')
            if sid and sid.lower() != "none":
                reality['short_id'] = sid
            tls_config['reality'] = reality
            if 'utls' not in tls_config:
                tls_config['utls'] = {'enabled': True}
        node['tls'] = tls_config

    if transport_type == 'ws' or get('obfs') == 'websocket':
        if transport_type == 'ws':
            ws_host = get('host') or get('sni') or ''
        else:
            ws_host = get('peer') or get('obfsParam') or ''
        matches = REGEX_WS_ED.search(path_raw)
        ws_config = {
            'type': 'ws',
            'path': path_raw.rsplit('?ed=', 1)[0] if matches else path_raw,
            'headers': {'Host': ws_host}
        }
        if matches:
            ws_config['early_data_header_name'] = 'Sec-WebSocket-Protocol'
            ws_config['max_early_data'] = int(matches.group(1))
        elif (ed := get('ed')):
            ws_config['max_early_data'] = int(ed)
            if (eh := get('eh')): 
                ws_config['early_data_header_name'] = eh
        node['transport'] = ws_config
        if 'tls' in node and not node['tls']['server_name']:
            node['tls']['server_name'] = ws_host
    elif transport_type == 'grpc':
        node['transport'] = {
            'type': 'grpc', 
            'service_name': unquote(get('serviceName', ''))
        }
    elif transport_type == 'http':
        node['transport'] = {
            'type': 'http', 
            'path': path_raw
        }

    if (proto := get('protocol')) in {'smux', 'yamux', 'h2mux'}:
        mux = {'enabled': True, 'protocol': proto}
        if (ms := get('max-streams')): mux['max_streams'] = int(ms)
        elif (mc := get('max-connections')): mux['max_connections'] = int(mc)
        if get('padding') == 'True': mux['padding'] = True
        node['multiplex'] = mux

    return node