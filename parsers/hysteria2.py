import re
from urllib.parse import urlparse, parse_qs, unquote
import tool

def split_host_port(netloc: str):
    netloc = netloc.rstrip('/')    
    if netloc.startswith('['):
        host_end = netloc.find(']')
        if host_end == -1:
            return netloc, None
        host = netloc[1:host_end]
        port_part = netloc[host_end+1:]
        if port_part.startswith(':'):
            port = port_part[1:]
        else:
            port = None
    else:
        if ':' in netloc:
            host, port = netloc.rsplit(':', 1)
        else:
            host, port = netloc, None
    return host, port

def parse(data: str) -> dict:
    info = data.strip()
    server_info = urlparse(info)
    netquery = {
        k: v if len(v) > 1 else v[0]
        for k, v in parse_qs(server_info.query).items()
    }
    host = server_info.hostname
    port = server_info.port
    if not host:
        temp_netloc = server_info.netloc
        if server_info.path and server_info.path != '/':
            temp_netloc += server_info.path
            
        netloc_tail = temp_netloc.split("@")[-1]
        host, port_str = split_host_port(netloc_tail)
        if port_str:
            try:
                port = int(port_str)
            except ValueError:
                port = None
    password = netquery.get('auth') or server_info.username
    if not password and "@" in server_info.netloc:
        password = server_info.netloc.split("@")[0].rsplit(":", 1)[-1]
    node = {
        'tag': unquote(server_info.fragment) or tool.genName() + '_hysteria2',
        'type': 'hysteria2',
        'server': host,
        "password": password,
        'tls': {
            'enabled': True,
            'server_name': netquery.get('sni', netquery.get('peer', '')),
            'insecure': False
        }
    }
    ranges = []
    if 'mport' in netquery:
        m = re.match(r'^(\d{1,5})-(\d{1,5})$', str(netquery['mport']))
        if m:
            start_port, end_port = int(m.group(1)), int(m.group(2))
            if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                ranges.append(f"{start_port}:{end_port}")
    if port and 1 <= port <= 65535:
        node['server_port'] = port
    else:
        node['server_port'] = 443
    if ranges:
        node['server_ports'] = ranges[0] if len(ranges) == 1 else ranges
    if netquery.get('insecure') in ['1', 'true', 'TRUE'] or netquery.get('allowInsecure') == '1':
        node['tls']['insecure'] = True
        
    if not node['tls'].get('server_name') or node['tls']['server_name'] == 'None':
        node['tls'].pop('server_name', None)
    if 'alpn' in netquery:
        alpn_val = netquery['alpn']
        if isinstance(alpn_val, list):
            node['tls']['alpn'] = [str(v).strip('{}') for v in alpn_val]
        else:
            node['tls']['alpn'] = alpn_val.strip('{}').split(',')
    if netquery.get('obfs') not in ['none', '', None]:
        node['obfs'] = {
            'type': netquery['obfs'],
            'password': netquery.get('obfs-password', '')
        }
    upmbps = netquery.get('upmbps')
    downmbps = netquery.get('downmbps')
    if upmbps and str(upmbps).isdigit():
        node['up_mbps'] = int(upmbps)
    if downmbps and str(downmbps).isdigit():
        node['down_mbps'] = int(downmbps)
    if 'pinSHA256' in netquery:
        node['tls']['fingerprint'] = netquery['pinSHA256']
    return node