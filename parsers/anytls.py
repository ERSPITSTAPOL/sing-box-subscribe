import tool
from urllib.parse import unquote

def parse(data: str) -> dict:
    main_part_full, _, fragment = data.partition('#')

    scheme_idx = main_part_full.find('://')
    if scheme_idx != -1:
        main_part_full = main_part_full[scheme_idx+3:]

    netloc_and_path, _, query_str = main_part_full.partition('?')
    netloc, _, _ = netloc_and_path.partition('/')

    at_idx = netloc.rfind('@')
    if at_idx != -1:
        userinfo = netloc[:at_idx]
        host_port = netloc[at_idx+1:]
        pw_from_netloc = userinfo.rsplit(':', 1)[-1]
    else:
        host_port = netloc
        pw_from_netloc = ''

    r_colon_idx = host_port.rfind(':')
    if r_colon_idx != -1:
        server = host_port[:r_colon_idx].replace('[', '').replace(']', '')
        raw_port = host_port[r_colon_idx+1:]
        comma_idx = raw_port.find(',')
        if comma_idx != -1:
            raw_port = raw_port[:comma_idx]
        server_port = int(raw_port)
    else:
        server = host_port.replace('[', '').replace(']', '')
        server_port = 443

    params = {}
    if query_str:
        for pair in query_str.split('&'):
            if pair:
                k, _, v = pair.partition('=')
                params[k] = v

    get = params.get

    auth = get('auth')
    password = unquote(auth) if auth else pw_from_netloc

    sni = get('sni')
    if sni is None:
        sni = get('peer')
    sni = unquote(sni) if sni is not None else ''

    node = {
        'tag': unquote(fragment) or (tool.genName() + '_anytls'),
        'type': 'anytls',
        'server': server,
        'server_port': server_port,
        'password': password,
        'tls': {
            'enabled': True,
            'server_name': sni,
            'insecure': False
        }
    }

    if (check_int := get('idleSessionCheckInterval')):
        node['idle_session_check_interval'] = unquote(check_int) + 's'

    if (timeout := get('idleSessionTimeout')):
        node['idle_session_timeout'] = unquote(timeout) + 's'

    if (min_idle := get('minIdleSession')):
        node['min_idle_session'] = int(unquote(min_idle))

    if (fp := get('fp')):
        node['tls']['utls'] = {
            'enabled': True,
            'fingerprint': unquote(fp)
        }

    if (alpn := get('alpn')):
        node['tls']['alpn'] = unquote(alpn).strip('{}').split(',')

    if get('insecure') == '1' or get('allowInsecure') == '1':
        node['tls']['insecure'] = True

    return node