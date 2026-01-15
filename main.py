import json, os, tool, time, requests, sys, importlib, argparse, yaml, ruamel.yaml
import re
from datetime import datetime
from urllib.parse import urlparse
from collections import OrderedDict, defaultdict, deque
from api.app import TEMP_DIR
from parsers.clash2base64 import clash2v2ray
from gh_proxy_helper import set_gh_proxy
import yaml
try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader

parsers_mod = {}
providers = None
color_code = [31, 32, 33, 34, 35, 36, 91, 92, 93, 94, 95, 96]

def loop_color(text):
    text = '\033[1;{color}m{text}\033[0m'.format(color=color_code[0], text=text)
    color_code.append(color_code.pop(0))
    return text

def init_parsers():
    b = os.walk('parsers')
    for path, dirs, files in b:
        for file in files:
            f = os.path.splitext(file)
            if f[1] == '.py':
                parsers_mod[f[0]] = importlib.import_module('parsers.' + f[0])

def get_template():
    template_dir = 'config_template'  # 配置模板文件夹路径
    template_files = os.listdir(template_dir)  # 获取文件夹中的所有文件
    template_list = [os.path.splitext(file)[0] for file in template_files if
                     file.endswith('.json')]  # 移除扩展名并过滤出以.json结尾的文件
    template_list.sort()  # 对文件名进行排序
    return template_list

def load_json(path):
    return json.loads(tool.readFile(path))

def process_subscribes(subscribes):
    nodes = {}
    for subscribe in subscribes:
        _nodes = [] 
        if subscribe.get('enabled') is False:
            continue
        try:
            _nodes = get_nodes(subscribe.get('url', ''))
            if _nodes and len(_nodes) > 0:
                add_emoji(_nodes, subscribe)
                add_prefix(_nodes, subscribe)
                add_suffix(_nodes, subscribe)
                nodefilter(_nodes, subscribe)
                target_tag = subscribe.get('tag')
                sg = subscribe.get('subgroup')
                if sg and str(sg).strip():
                    target_tag = f"{target_tag}-{sg}-subgroup"
                if target_tag not in nodes:
                    nodes[target_tag] = []
                nodes[target_tag] += _nodes
            else:
                tag_name = subscribe.get('tag')
                print(f"没有在订阅 [{tag_name}] 下找到节点，跳过")
        except Exception as e:
            tag_name = subscribe.get('tag')
            print(f"处理订阅 [{tag_name}] 时发生错误: {e}")
            continue
    tool.proDuplicateNodeName(nodes)
    return nodes

def nodes_filter(nodes, filter, group):
    for a in filter:
        if a.get('for') and group not in a['for']:
            continue
        nodes = action_keywords(nodes, a['action'], a['keywords'])
    return nodes

def action_keywords(nodes, action, keywords):
    temp_nodes = []
    flag = False
    if action == 'exclude':
        flag = True
    if action == 'all':
        return nodes
    if isinstance(keywords, (list, tuple)):
        combined_pattern = '|'.join(keywords)
        if not combined_pattern or combined_pattern.isspace():
            return nodes
        compiled_pattern = re.compile(combined_pattern)
    elif isinstance(keywords, str):
        pattern = keywords
        if not pattern or pattern.isspace():
            return nodes
        compiled_pattern = re.compile(pattern)
    else:
        pattern = keywords
        if not pattern or str(pattern).isspace():
            return nodes
        compiled_pattern = re.compile(pattern)
    for node in nodes:
        name = node['tag']
        match_flag = bool(compiled_pattern.search(name))
        if match_flag ^ flag:
            temp_nodes.append(node)
    return temp_nodes

def add_prefix(nodes, subscribe):
    # 添加前缀
    if subscribe.get('prefix'):
        for node in nodes:
            node['tag'] = subscribe['prefix'] + node['tag']
            if node.get('detour'):
                node['detour'] = subscribe['prefix'] + node['detour']
def add_suffix(nodes, subscribe):
    # 添加后缀
    if subscribe.get('suffix'):
        for node in nodes:
            node['tag'] = node['tag'] + subscribe['suffix']
            if node.get('detour'):
                node['detour'] = node['detour'] + subscribe['suffix']

def add_emoji(nodes, subscribe):
    if subscribe.get('emoji'):
        for node in nodes:
            node['tag'] = tool.rename(node['tag'])
            if node.get('detour'):
                node['detour'] = tool.rename(node['detour'])

def nodefilter(nodes, subscribe):
    if subscribe.get('ex-node-name'):
        ex_nodename = re.split(r'[,\|]', subscribe['ex-node-name'])
        for exns in ex_nodename:
            for node in nodes[:]:  # 遍历 nodes 的副本，以便安全地删除元素
                if exns in node['tag']:
                    nodes.remove(node)

def get_nodes(url):
    if url.startswith('sub://'):
        url = tool.b64Decode(url[6:]).decode('utf-8')
    urlstr = urlparse(url)
    if not urlstr.scheme:
        try:
            content = tool.b64Decode(url).decode('utf-8')
            data = parse_content(content)
            processed_list = []
            for item in data:
                if isinstance(item, tuple):
                    processed_list.extend([item[0], item[1]])  # 处理shadowtls
                else:
                    processed_list.append(item)
            return processed_list
        except:
            content = get_content_form_file(url)
    else:
        content = get_content_from_url(url)

    contents = content if isinstance(content, list) else [content]
    nodes_list = []

    for content_item in contents:
        if isinstance(content_item, dict):
            if 'proxies' in content_item:
                share_links = []
                for proxy in content_item['proxies']:
                    share_links.append(clash2v2ray(proxy))
                data = '\n'.join(share_links)
                data = parse_content(data)
                processed_list = []
                for item in data:
                    if isinstance(item, tuple):
                        processed_list.extend([item[0], item[1]])
                    else:
                        processed_list.append(item)
                nodes_list.extend(processed_list)
            elif 'outbounds' in content_item:
                excluded_types = {"selector", "urltest", "direct", "block", "dns"}
                filtered_outbounds = [outbound for outbound in content_item['outbounds'] if outbound.get("type") not in excluded_types]
                nodes_list.extend(filtered_outbounds)
        elif isinstance(content_item, str):
            data = parse_content(content_item)
            processed_list = []
            for item in data:
                if isinstance(item, tuple):
                    processed_list.extend([item[0], item[1]])
                else:
                    processed_list.append(item)
            nodes_list.extend(processed_list)
    return nodes_list

def parse_content(content):
    # firstline = tool.firstLine(content)
    # # print(firstline)
    # if not get_parser(firstline):
    #     return None
    nodelist = []
    for t in content.splitlines():
        t = t.strip()
        if len(t) == 0:
            continue
        factory = get_parser(t)
        if not factory:
            continue
        node = None
        try:
            node = factory(t)
        except Exception as e:  #节点解析失败，跳过
            print(f"解析节点出错: {e}，内容: {t[:30]}...")
            continue
        if node:
            nodelist.append(node)
    return nodelist

def get_parser(node):
    proto = tool.get_protocol(node)
    if providers.get('exclude_protocol'):
        eps = providers['exclude_protocol'].split(',')
        if len(eps) > 0:
            eps = [protocol.strip() for protocol in eps]
            if 'hy2' in eps:
                index = eps.index('hy2')
                eps[index] = 'hysteria2'
            if proto in eps:
                return None
    if not proto or proto not in parsers_mod.keys():
        return None
    return parsers_mod[proto].parse

def get_content_from_url(url, n=10):
    UA = ''
    print('处理: \033[31m' + url + '\033[0m')
    prefixes = ["vmess://", "vless://", "ss://", "ssr://", "trojan://", "tuic://", "hysteria://", "hysteria2://","hy2://", "wg://", "wireguard://", "http2://", "socks://", "socks5://"]

    if any(url.startswith(prefix) for prefix in prefixes):
        response_text = tool.noblankLine(url)
        return response_text

    for subscribe in providers["subscribes"]:
        if 'enabled' in subscribe and not subscribe['enabled']:
            continue
        if subscribe['url'] == url:
            UA = subscribe.get('User-Agent', '')

    def internal_recognize(current_response):
        try:
            response_content = current_response.content
            response_text = response_content.decode('utf-8-sig')
        except:
            return ''

        if response_text.isspace():
            return None

        if re.fullmatch(r'^[A-Za-z0-9+/=_ \-]+$', response_text):
            pass

        elif 'proxies' in response_text:
            yaml_content = current_response.content.decode('utf-8', errors='ignore')
            response_text_no_tabs = yaml_content.replace('\t', ' ')
            # ^proxies:[\s\S]*?(?=\n\S|\z)
            match = re.search(r'^proxies:.*?(?=\n\S|\Z)', response_text_no_tabs, re.M | re.S)
            if match:
                to_parse = match.group(0)
            else:
                to_parse = response_text_no_tabs
            try:
                response_text = yaml.load(to_parse, Loader=SafeLoader)
                if isinstance(response_text, dict):
                    return response_text
            except:
                pass
        elif 'outbounds' in response_text:
            try:
                response_text = json.loads(current_response.text)
                return response_text
            except:
                try:
                    response_text = re.sub(r'//.*', '', current_response.text)
                    response_text = json.loads(response_text)
                    return response_text
                except:
                    pass
        elif any(response_text.startswith(prefix) for prefix in prefixes):
            response_text = tool.noblankLine(response_text)
            return response_text

        try:
            decoded_text = tool.b64Decode(response_text)
            if isinstance(decoded_text, bytes):
                response_text = decoded_text.decode(encoding="utf-8")
            else:
                response_text = decoded_text
        except:
            pass

        return response_text

    response = tool.getResponse(url, custom_user_agent=UA)
    concount = 1
    while concount <= n and not response:
        print('连接出错，正在进行第 ' + str(concount) + ' 次重试，最多重试 ' + str(n) + ' 次...')
        response = tool.getResponse(url)
        concount = concount + 1
        time.sleep(1)

    if not response:
        print('获取错误，跳过此订阅')
        return ''

    main_text_check = ""
    try:
        main_text_check = response.content.decode('utf-8-sig')
    except: pass

    if not main_text_check:
        response = tool.getResponse(url, custom_user_agent='clashmeta')

    response_text = internal_recognize(response)

    if isinstance(response_text, dict):
        return response_text

    if response_text is None:
        return None

    final_content = []
    lines = response_text.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue

        if (line.startswith("http://") or line.startswith("https://")) and line != url:
            print(f'正在处理子链接: \033[32m{line}\033[0m')
            sub_res = tool.getResponse(line, custom_user_agent=UA)
            if not sub_res:
                sub_res = tool.getResponse(line)

            if sub_res:
                sub_result = internal_recognize(sub_res)
                if sub_result:
                    final_content.append(sub_result)
        else:
            final_content.append(line)

    has_dict = any(isinstance(item, dict) for item in final_content)
    if has_dict:
        if len(final_content) == 1 and isinstance(final_content[0], dict):
            return final_content[0]
        return final_content

    response_text = '\n'.join(final_content)
    response_text = tool.noblankLine(response_text)
    return response_text

def get_content_form_file(url):
    print(f"处理: \033[31m{url}\033[0m")
    # encoding = tool.get_encoding(url)
    file_extension = os.path.splitext(url)[1]  # 获取文件的后缀名
    if file_extension.lower() == '.yaml':
        with open(url, 'rb') as file:
            content = file.read()
        text_content = content.decode('utf-8', errors='ignore')
        # ^proxies:[\s\S]*?(?=\n\S|\z)
        match = re.search(r'^proxies:.*?(?=\n\S|\Z)', text_content, re.M | re.S)
        if match:
            yaml_data = dict(yaml.load(match.group(0), Loader=SafeLoader))
        else:
            yaml_data = dict(yaml.load(text_content, Loader=SafeLoader))
        share_links = []
        for proxy in yaml_data.get('proxies', []):
            share_links.append(clash2v2ray(proxy))
        node = '\n'.join(share_links)
        processed_list = tool.noblankLine(node)
        return processed_list
    else:
        data = tool.readFile(url)
        data = bytes.decode(data, encoding='utf-8')
        data = tool.noblankLine(data)
        return data

def save_config(path, nodes):
    try:
        clean_filename = os.path.basename(path)
        # if 'auto_backup' in providers and providers['auto_backup']:
        #     now = datetime.now().strftime('%Y%m%d%H%M%S')
        #     if os.path.exists(path):
        #         try:
        #             os.rename(path, f'{path}.{now}.bak')
        #         except: pass
        if os.path.exists(path):
            os.remove(path)
            print(f"已删除旧文件并尝试重新保存：\033[33m{path}\033[0m")
        else:
            print(f"正在保存到：\033[33m{path}\033[0m")
        tool.saveFile(path, json.dumps(nodes, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"原始路径保存出错：{e}")
        config_path_raw = providers.get("save_config_path", "config.json")
        filename = os.path.basename(config_path_raw)
        config_file_path = os.path.join('/tmp', filename)
        print(f"正在尝试回退方案，保存至：\033[33m{config_file_path}\033[0m")
        try:
            if os.path.exists(config_file_path):
                os.remove(config_file_path)
            tool.saveFile(config_file_path, json.dumps(nodes, indent=2, ensure_ascii=False))
            print(f"成功保存到临时目录: \033[32m{config_file_path}\033[0m")
        except Exception as retry_e:
            print(f"回退保存依然失败：{str(retry_e)}")

def set_proxy_rule_dns(config):
    # dns_template = {
    #     "tag": "remote",
    #     "address": "tls://1.1.1.1",
    #     "detour": ""
    # }
    config_rules = config['route']['rules']
    outbound_dns = []
    dns_rules = config['dns']['rules']
    asod = providers["auto_set_outbounds_dns"]
    for rule in config_rules:
        if rule['outbound'] not in ['block', 'dns-out']:
            if rule['outbound'] != 'direct':
                outbounds_dns_template = \
                    list(filter(lambda server: server['tag'] == asod["proxy"], config['dns']['servers']))[0]
                dns_obj = outbounds_dns_template.copy()
                dns_obj['tag'] = rule['outbound'] + '_dns'
                dns_obj['detour'] = rule['outbound']
                if dns_obj not in outbound_dns:
                    outbound_dns.append(dns_obj)
            if rule.get('type') and rule['type'] == 'logical':
                dns_rule_obj = {
                    'type': 'logical',
                    'mode': rule['mode'],
                    'rules': [],
                    'server': rule['outbound'] + '_dns' if rule['outbound'] != 'direct' else asod["direct"]
                }
                for _rule in rule['rules']:
                    child_rule = pro_dns_from_route_rules(_rule)
                    if child_rule:
                        dns_rule_obj['rules'].append(child_rule)
                if len(dns_rule_obj['rules']) == 0:
                    dns_rule_obj = None
            else:
                dns_rule_obj = pro_dns_from_route_rules(rule)
            if dns_rule_obj:
                dns_rules.append(dns_rule_obj)
    # 清除重复规则
    _dns_rules = []
    for dr in dns_rules:
        if dr not in _dns_rules:
            _dns_rules.append(dr)
    config['dns']['rules'] = _dns_rules
    config['dns']['servers'].extend(outbound_dns)

def pro_dns_from_route_rules(route_rule):
    dns_route_same_list = ["inbound", "ip_version", "network", "protocol", 'domain', 'domain_suffix', 'domain_keyword',
                           'domain_regex', 'geosite', "source_geoip", "source_ip_cidr", "source_port",
                           "source_port_range", "port", "port_range", "process_name", "process_path", "package_name",
                           "user", "user_id", "clash_mode", "invert"]
    dns_rule_obj = {}
    for key in route_rule:
        if key in dns_route_same_list:
            dns_rule_obj[key] = route_rule[key]
    if len(dns_rule_obj) == 0:
        return None
    if route_rule.get('outbound'):
        dns_rule_obj['server'] = route_rule['outbound'] + '_dns' if route_rule['outbound'] != 'direct' else \
            providers["auto_set_outbounds_dns"]['direct']
    return dns_rule_obj

def pro_node_template(data_nodes, config_outbound, group):
    if config_outbound.get('filter'):
        data_nodes = nodes_filter(data_nodes, config_outbound['filter'], group)
    return [node.get('tag') for node in data_nodes]

def combin_to_config(config, data):
    _globals = globals()
    template_func = _globals.get('pro_node_template')
    has_template_func = template_func is not None
    set_dns_func = _globals.get('set_proxy_rule_dns')
    providers_obj = _globals.get('providers', {})
    empty_data_keys = {k for k, v in data.items() if not v}
    if "outbounds" not in config:
        config["outbounds"] = []
    existing_tags = {o.get("tag") for o in config["outbounds"]}
    proxy_node = next((o for o in config["outbounds"] if o.get("tag") == "Proxy"), None)
    new_subgroup_nodes = []
    subgroup_tags_set = set() 
    proxy_additions = []
    for group_key in data:
        if 'subgroup' in group_key:
            subgroup_tag = (group_key.rsplit("-", 1)[0]).rsplit("-", 1)[-1]
            subgroup_tags_set.add(subgroup_tag)
            if subgroup_tag not in existing_tags:
                new_subgroup_nodes.append({
                    'tag': subgroup_tag,
                    'type': 'selector',
                    'outbounds': ['{' + group_key + '}']
                })
                existing_tags.add(subgroup_tag)
            if proxy_node:
                proxy_additions.append(subgroup_tag)
        else:
            if proxy_node:
                proxy_additions.append('{' + group_key + '}')
    if new_subgroup_nodes:
        insert_pos = max(0, len(config["outbounds"]) - 2)
        config["outbounds"][insert_pos:insert_pos] = new_subgroup_nodes
    if proxy_node and proxy_additions:
        if "outbounds" not in proxy_node: proxy_node["outbounds"] = []
        if isinstance(proxy_node["outbounds"], str): proxy_node["outbounds"] = [proxy_node["outbounds"]]
        current_proxy_tags = set(proxy_node["outbounds"])
        final_additions = [t for t in proxy_additions if t not in current_proxy_tags]
        if final_additions:
            if '{all}' in proxy_node["outbounds"]:
                idx = proxy_node["outbounds"].index('{all}')
                proxy_node["outbounds"][idx:idx] = final_additions
            else:
                proxy_node["outbounds"].extend(final_additions)
    nodes = {o.get("tag"): {'obj': o, 'tag': o.get("tag"), 'resolved': []} for o in config["outbounds"]}
    reverse_dep = defaultdict(set)
    for node in nodes.values():
        o = node['obj']
        raw = o.get("outbounds", [])
        if isinstance(raw, str): raw = [raw]
        temp_resolved = []
        has_group_reference = False
        has_real_node = False
        for item in raw:
            if item.startswith('{') and item.endswith('}'):
                key = item[1:-1]
                if key == 'all':
                    for g, members in data.items():
                        temp_resolved.extend(template_func(members, o, g) if has_template_func else members)
                        if members: has_real_node = True
                elif key in data:
                    members = data[key]
                    temp_resolved.extend(template_func(members, o, key) if has_template_func else members)
                    if members: has_real_node = True
            else:
                temp_resolved.append(item)
                if item in nodes and item != node['tag']:
                    has_group_reference = True
                elif item not in subgroup_tags_set:
                    has_real_node = True
        if has_group_reference and not has_real_node:
            for s_tag in subgroup_tags_set:
                if s_tag not in temp_resolved:
                    temp_resolved.append(s_tag)
        node['resolved'] = [
            tag for tag in dict.fromkeys(temp_resolved)
            if not (tag not in nodes and tag in empty_data_keys)
        ]
        for tag in node['resolved']:
            if tag in nodes:
                reverse_dep[tag].add(node['tag'])
    group_types = {'selector', 'urltest', 'fallback', 'loadbalance'}
    empty_queue = deque([
        n['tag'] for n in nodes.values() 
        if n['obj'].get('type') in group_types and not n['resolved']
    ])
    alive = {
        n['tag']: (n['obj'].get('type') not in group_types or bool(n['resolved'])) 
        for n in nodes.values()
    }
    while empty_queue:
        dead_tag = empty_queue.popleft()
        for parent_tag in reverse_dep.get(dead_tag, []):
            if not alive.get(parent_tag): continue
            p_node = nodes[parent_tag]
            p_node['resolved'] = [t for t in p_node['resolved'] if t != dead_tag]
            if not p_node['resolved']:
                alive[parent_tag] = False
                empty_queue.append(parent_tag)
    for node in nodes.values():
        if alive.get(node['tag']):
            current_default = node['obj'].get('default')
            if current_default and current_default not in node['resolved']:
                node['obj'].pop('default', None)
    out = []
    _append = out.append
    for node in nodes.values():
        if alive.get(node['tag']):
            obj = node['obj']
            if "outbounds" in obj or obj.get('type') in group_types:
                obj["outbounds"] = node['resolved']
            obj.pop("filter", None)
            _append(obj)
    for group in data:
        members = data[group]
        if members:
            out.extend(members)

    if config.get('dns') and config['dns'].get('servers'):
        dns_tags = {server.get('tag') for server in config['dns']['servers']}
        asod = providers_obj.get("auto_set_outbounds_dns")
        if asod and asod.get('proxy') and asod.get('direct'):
             if asod['proxy'] in dns_tags and asod['direct'] in dns_tags:
                if set_dns_func: set_dns_func(config)

    wireguard_items = [item for item in config['outbounds'] if item.get('type') == 'wireguard']
    if wireguard_items:
        config['endpoints'] = wireguard_items
        out = [item for item in out if item.get('type') != 'wireguard']

    config['outbounds'] = out
    return config

def updateLocalConfig(local_host, path):
    header = {
        'Content-Type': 'application/json'
    }
    r = requests.put(local_host + '/configs?force=false', json={"path": path}, headers=header)
    print(r.text)

def display_template(tl):
    print_str = ''
    for i in range(len(tl)):
        print_str += loop_color('{index}、{name} '.format(index=i + 1, name=tl[i]))
    print(print_str)

def select_config_template(tl, selected_template_index=None):
    if args.template_index is not None:
        uip = args.template_index
    else:
        uip = input('输入序号，载入对应config模板（直接回车默认选第一个配置模板）：')
        try:
            if uip == '':
                return 0
            uip = int(uip)
            if uip < 1 or uip > len(tl):
                print('输入了错误信息！重新输入')
                return select_config_template(tl)
            else:
                uip -= 1
        except:
            print('输入了错误信息！重新输入')
            return select_config_template(tl)
    return uip

# 自定义函数，用于解析参数为 JSON 格式
def parse_json(value):
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        raise argparse.ArgumentTypeError(f"Invalid JSON: {value}")

if __name__ == '__main__':
    init_parsers()
    parser = argparse.ArgumentParser()
    parser.add_argument('--temp_json_data', type=parse_json, help='临时内容')
    parser.add_argument('--template_index', type=int, help='模板序号')
    parser.add_argument('--gh_proxy_index', type=str, help='github加速链接')
    args = parser.parse_args()
    temp_json_data = args.temp_json_data
    gh_proxy_index = args.gh_proxy_index
    if temp_json_data and temp_json_data != '{}':
        providers = json.loads(temp_json_data)
    else:
        providers = load_json('providers.json')  # 加载本地 providers.json
    if providers.get('config_template'):
        config_template_path = providers['config_template']
        print('选择: \033[33m' + config_template_path + '\033[0m')
        response = requests.get(providers['config_template'])
        response.raise_for_status()
        config = response.json()
    else:
        template_list = get_template()
        if len(template_list) < 1:
            print('没有找到模板文件')
            sys.exit()
        display_template(template_list)
        uip = select_config_template(template_list, selected_template_index=args.template_index)
        config_template_path = 'config_template/' + template_list[uip] + '.json'
        print('选择: \033[33m' + template_list[uip] + '.json\033[0m')
        config = load_json(config_template_path)
    nodes = process_subscribes(providers["subscribes"])

    # 处理github加速
    if args.gh_proxy_index and str(args.gh_proxy_index).strip() not in ['None', '']:
        gh_proxy_value = str(args.gh_proxy_index).strip()
        print(gh_proxy_value)
        urls = [item["url"] for item in config["route"]["rule_set"]]
        new_urls = set_gh_proxy(urls, gh_proxy_value)
        for item, new_url in zip(config["route"]["rule_set"], new_urls):
            item["url"] = new_url

    if providers.get('Only-nodes'):
        combined_contents = []
        for sub_tag, contents in nodes.items():
            # 遍历每个机场的内容
            for content in contents:
                # 将内容添加到新列表中
                combined_contents.append(content)
        final_config = {"outbounds":combined_contents} # 只返回节点信息
    else:
        final_config = combin_to_config(config, nodes)  # 节点信息添加到模板
    save_config(providers["save_config_path"], final_config)
    # updateLocalConfig('http://127.0.0.1:9090',providers['save_config_path'])