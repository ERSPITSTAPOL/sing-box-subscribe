import tool
from urllib.parse import unquote

_TRUE_STRINGS = frozenset(('1', 'true'))

def parse(data: str) -> dict:
    sep_idx = data.find("://")
    if sep_idx == -1:
        return None

    main_part, _, fragment = data.partition('#')
    start_pos = sep_idx + 3

    at_idx = main_part.find('@', start_pos)
    if at_idx == -1:
        return None
    password = main_part[start_pos:at_idx]

    rest = main_part[at_idx + 1:]
    q_idx = rest.find('?')

    if q_idx != -1:
        hp_part_raw = rest[:q_idx]
        query_str = rest[q_idx + 1:]
    else:
        hp_part_raw = rest
        query_str = ""

    slash_idx = hp_part_raw.find('/')
    if slash_idx != -1:
        hp_part = hp_part_raw[:slash_idx]
    else:
        hp_part = hp_part_raw

    if hp_part.startswith('['):
        end_bracket = hp_part.find(']')
        server = hp_part[1:end_bracket]
        raw_port = hp_part[end_bracket + 2:]
    else:
        r_idx = hp_part.rfind(':')
        if r_idx != -1:
            server = hp_part[:r_idx]
            raw_port = hp_part[r_idx + 1:]
        else:
            server = hp_part
            raw_port = ""

    main_port = 443
    port_range = ""

    if raw_port:
        comma_idx = raw_port.find(',')
        if comma_idx != -1:
            p_main = raw_port[:comma_idx]
            p_hop = raw_port[comma_idx + 1:]
            if p_main:
                main_port = int(p_main)
            port_range = p_hop.replace('-', ':')
        else:
            hyphen_idx = raw_port.find('-')
            if hyphen_idx != -1:
                main_port = int(raw_port[:hyphen_idx])
                port_range = raw_port.replace('-', ':')
            else:
                main_port = int(raw_port)

    params: dict[str, str] = {}
    if query_str:
        start = 0
        end = len(query_str)
        while start < end:
            amp_idx = query_str.find('&', start)
            if amp_idx == -1:
                amp_idx = end

            eq_idx = query_str.find('=', start, amp_idx)
            if eq_idx != -1:
                params[query_str[start:eq_idx]] = unquote(query_str[eq_idx + 1:amp_idx])

            start = amp_idx + 1

    get = params.get

    mport_raw = get('mport')
    if mport_raw:
        m_ports = mport_raw.replace('-', ':')
    else:
        m_ports = port_range

    sni = get('sni') or get('peer')

    is_insecure = get('insecure') in _TRUE_STRINGS or get('allowInsecure') in _TRUE_STRINGS

    if sni and sni.lower() == 'none':
        sni = None
        is_insecure = True

    alpn_raw = get('alpn')
    if not alpn_raw or alpn_raw == 'h3':
        alpn_list = ['h3']
    else:
        alpn_list = [a.strip() for a in alpn_raw.split(',')]

    node = {
        "tag": unquote(fragment) if fragment else (tool.genName() + '_hy2'),
        "type": "hysteria2",
        "server": server,
        "server_port": main_port,
    }

    if m_ports:
        node["server_ports"] = m_ports

    obfs_type = get('obfs')
    if obfs_type and obfs_type != 'none':
        node["obfs"] = {
            "type": obfs_type,
            "password": get('obfs-password') or get('obfs-param') or "",
        }

    node["password"] = (unquote(password) if '%' in password else password) if password else get('auth', '')

    node["tls"] = {
        "enabled": True,
        "server_name": sni or server,
        "insecure": is_insecure,
        "alpn": alpn_list,
    }

    return node