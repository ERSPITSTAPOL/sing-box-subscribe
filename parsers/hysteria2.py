import tool
from urllib.parse import unquote

def parse(data: str) -> dict:
    sep_idx = data.find("://")
    if sep_idx == -1:
        return None
    main_part_full, _, fragment = data.partition('#')
    start_pos = sep_idx + 3
    at_idx = main_part_full.find('@', start_pos)
    if at_idx == -1:
        return None
    password = main_part_full[start_pos:at_idx].rpartition(':')[-1]
    rest = main_part_full[at_idx+1:]

    q_idx = rest.find('?')
    a_idx = rest.find('&')
    if q_idx == -1: split_idx = a_idx
    elif a_idx == -1: split_idx = q_idx
    else: split_idx = q_idx if q_idx < a_idx else a_idx

    if split_idx != -1:
        hp_part = rest[:split_idx].partition('/')[0]
        query_str = rest[split_idx+1:]
    else:
        hp_part = rest.partition('/')[0]
        query_str = ""

    if hp_part[0] == '[':
        end_bracket = hp_part.find(']')
        server = hp_part[1:end_bracket]
        raw_port = hp_part[end_bracket+2:]
    else:
        r_idx = hp_part.rfind(':')
        server = hp_part[:r_idx]
        raw_port = hp_part[r_idx+1:]

    main_port = 443
    port_range = ""
    if raw_port:
        p_main, _, p_ext = raw_port.partition(',')
        p_main_val = p_main.partition('-')[0]
        if p_main_val: main_port = int(p_main_val)
        ext_str = p_ext if p_ext else (p_main if '-' in p_main else "")
        if ext_str: port_range = ext_str.replace('-', ':')

    params = {k: v for pair in query_str.split('&') if pair for k, v in [pair.partition('=')[::2]]}
    get = params.get

    mport_val = get('mport')
    final_server_ports = mport_val.replace('-', ':') if mport_val else port_range

    node = {
        'tag': unquote(fragment) or (tool.genName() + '_hy2'),
        'type': 'hysteria2',
        'server': server,
        'password': password or get('auth', ''),
        'server_port': main_port,
    }
    if final_server_ports:
        node['server_ports'] = final_server_ports

    sni = get('sni') or get('peer') or ''
    is_insecure = get('insecure') in {'1', 'true'} or get('allowInsecure') in {'1', 'true'}

    if not sni or sni.lower() == 'none':
        sni = None
        is_insecure = True

    tls_config = {
        'enabled': True,
        'insecure': is_insecure,
        'alpn': [a.strip('{} ') for a in get('alpn', 'h3').split(',')] if get('alpn') else ['h3']
    }
    if sni: tls_config['server_name'] = sni
    if (pin := get('pinSHA256')): tls_config['fingerprint'] = pin
    node['tls'] = tls_config

    obfs = get('obfs')
    if obfs and obfs != 'none':
        node['obfs'] = {'type': obfs, 'password': get('obfs-password', '')}

    if (up := get('upmbps')): node['up_mbps'] = int(up)
    if (down := get('downmbps')): node['down_mbps'] = int(down)

    return node