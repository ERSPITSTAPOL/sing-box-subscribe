import os
import importlib
import re
import asyncio
import httpx
import tool
# from datetime import datetime
from contextvars import ContextVar
from urllib.parse import urlparse
from collections import defaultdict, deque
try:
    import orjson as json_lib
except ImportError:
    import json as json_lib
parsers_mod = {
    'vmess': 'parsers.vmess',
    'vless': 'parsers.vless',
    'ss': 'parsers.ss',
    'ssr': 'parsers.ssr',
    'trojan': 'parsers.trojan',
    'tuic': 'parsers.tuic',
    'hysteria': 'parsers.hysteria',
    'hysteria2': 'parsers.hysteria2',
    'wg': 'parsers.wg',
    'hy2': 'parsers.hysteria2',
    'anytls': 'parsers.anytls',
    'socks': 'parsers.socks',
    'http': 'parsers.http',
    'https': 'parsers.https',
    'clash2sing': 'parsers.clash2sing',
    'clash2v2ray': 'parsers.clash2base64'
}
_PARSER_CACHE = {}
_parsers_warmed = False
_warmup_lock = asyncio.Lock()
_warmup_done = asyncio.Event()
COMMON_PARSERS = {'vless', 'ss', 'trojan', 'hysteria2', 'tuic', 'anytls'}

providers_ctx: ContextVar[dict] = ContextVar("providers_ctx")
# color_code = [31, 32, 33, 34, 35, 36, 91, 92, 93, 94, 95, 96]

RE_BASE64 = re.compile(r'^[A-Za-z0-9+/=_ \-]+$')
RE_CLEAN_COMMENT = re.compile(r'//.*')
RE_PROXIES = re.compile(r'^proxies:.*?(?=\n\S|\Z)', re.M | re.S)

# def loop_color(text):
#     text = '\033[1;{color}m{text}\033[0m'.format(color=color_code[0], text=text)
#     color_code.append(color_code.pop(0))
#     return text

def get_template_list():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(base_dir, 'config_template')
    if not os.path.exists(template_dir):
        return []
    template_files = os.listdir(template_dir)
    template_list = [
        os.path.splitext(file)[0] 
        for file in template_files 
        if file.endswith('.json')
    ]
    template_list.sort()
    return template_list

def load_json(path):
    content = tool.readFile(path)
    return json_lib.loads(content)

async def process_subscribes(subscribes, client):
    nodes = {}
    tasks = []
    for subscribe in subscribes:
        if subscribe.get('enabled') is False:
            continue
        tasks.append(process_single_subscribe(client, subscribe))
    results = await asyncio.gather(*tasks)

    for result in results:
        if not result: continue
        target_tag, _nodes = result
        if target_tag not in nodes:
            nodes[target_tag] = []
        nodes[target_tag] += _nodes

    tool.proDuplicateNodeName(nodes)
    return nodes

async def process_single_subscribe(client, subscribe):
    try:
        _nodes = await get_nodes(client, subscribe.get('url', ''))
        if _nodes and len(_nodes) > 0:
            add_emoji(_nodes, subscribe)
            add_prefix(_nodes, subscribe)
            add_suffix(_nodes, subscribe)
            nodefilter(_nodes, subscribe)
            target_tag = subscribe.get('tag')
            sg = subscribe.get('subgroup')
            if sg and str(sg).strip():
                target_tag = f"{target_tag}-{sg}-subgroup"
            return target_tag, _nodes
        else:
            tag_name = subscribe.get('tag')
            print(f"没有在订阅 [{tag_name}] 下找到节点，跳过")
            return None
    except Exception as e:
        tag_name = subscribe.get('tag')
        print(f"处理订阅 [{tag_name}] 时发生错误: {e}")
        return None

def nodes_filter(nodes, filter, group):
    for a in filter:
        if a.get('for') and group not in a['for']:
            continue
        nodes = action_keywords(nodes, a['action'], a['keywords'])
    return nodes

def action_keywords(nodes, action, keywords):
    if action == 'all' or not keywords:
        return nodes
    if isinstance(keywords, str):
        keywords = [keywords]
    if action == 'regex':
        pattern_str = '|'.join(keywords)
    else:
        pattern_str = '|'.join(map(str, keywords))
    if not pattern_str.strip():
        return nodes
    try:
        compiled_pattern = re.compile(pattern_str, re.IGNORECASE)
    except re.error:
        return nodes
    exclude = (action == 'exclude')
    return [node for node in nodes if bool(compiled_pattern.search(node.get('tag', ''))) ^ exclude]

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

async def get_nodes(client, url):
    if url.startswith('sub://'):
        url = tool.b64Decode(url[6:]).decode('utf-8')
    urlstr = urlparse(url)
    if not urlstr.scheme:
        try:
            content = tool.b64Decode(url).decode('utf-8')
            data = parse_content(content)
            return [node for item in data for node in (item if isinstance(item, tuple) else [item])]
        except:
            print(f"Base64 解码失败，返回原文: {url}，错误: {e}")
            return [url]
            # content = get_content_form_file(url)
    else:
        content = await get_content_from_url(client, url)

    contents = content if isinstance(content, list) else [content]
    nodes_list = []

    for content_item in contents:
        if isinstance(content_item, dict):
            if 'proxies' in content_item:
                c2s = _PARSER_CACHE.get('clash2sing')
                if not c2s:
                    from clash2sing import clash2sing as c2s
                    _PARSER_CACHE['clash2sing'] = c2s
                for proxy in content_item['proxies']:
                    res = c2s(proxy)
                    if not res:
                        continue
                    if isinstance(res, tuple):
                        nodes_list.extend(list(res))
                    else:
                        nodes_list.append(res)
            elif 'outbounds' in content_item:
                excluded_types = {"selector", "urltest", "direct", "block", "dns"}
                filtered_outbounds = [
                    outbound for outbound in content_item['outbounds'] 
                    if outbound.get("type") not in excluded_types
                ]
                nodes_list.extend(filtered_outbounds)
        elif isinstance(content_item, str):
            data = parse_content(content_item)
            nodes_list.extend([node for item in data for node in (item if isinstance(item, tuple) else [item])])
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

async def warmup_parsers(parsers_mod, timeout=2.0):
    global _parsers_warmed, _PARSER_CACHE
    if _parsers_warmed or _warmup_done.is_set():
        return
    async with _warmup_lock:
        if _parsers_warmed:
            return
        coros = []
        async def _import_PARSERS(proto, path, finished=False):
            try:
                def _sync_import():
                    if finished:
                        mod = importlib.import_module(path)
                        return getattr(mod, 'clash2sing')
                    return importlib.import_module(path)
                result = await asyncio.to_thread(_sync_import)
                _PARSER_CACHE[proto] = result
            except Exception:
                pass
        for proto in COMMON_PARSERS:
            if proto == 'clash2sing': continue
            if proto in parsers_mod and proto not in _PARSER_CACHE:
                coros.append(_import_PARSERS(proto, parsers_mod[proto]))
        if 'clash2sing' not in _PARSER_CACHE:
            coros.append(_import_PARSERS('clash2sing', 'parsers.clash2sing', finished=True))
        if not coros:
            _parsers_warmed = True
            _warmup_done.set()
            return
        try:
            await asyncio.wait_for(asyncio.gather(*coros), timeout=timeout)
            _parsers_warmed = True
        except asyncio.TimeoutError:
            pass
        finally:
            _warmup_done.set()

def get_parser(node):
    providers = providers_ctx.get()
    proto = tool.get_protocol(node)
    if not proto:
        return None
    if proto == 'hy2':
        proto = 'hysteria2'
    if providers.get('exclude_protocol'):
        eps = [p.strip() for p in providers['exclude_protocol'].split(',') if p.strip()]
        if 'hy2' in eps:
            eps[eps.index('hy2')] = 'hysteria2'
        if proto in eps:
            return None
    if proto in _PARSER_CACHE:
        return getattr(_PARSER_CACHE[proto], 'parse', None)
    module_path = parsers_mod.get(proto)
    if not module_path:
        return None
    try:
        mod = importlib.import_module(module_path)
        _PARSER_CACHE[proto] = mod
        return getattr(mod, 'parse', None)
    except Exception as e:
        print(f"Parser 加载失败 [{proto}]: {e}")
        return None

async def get_content_from_url(client, url, n=3, can_fetch_sub=True, current_ua=None):
    global _parsers_warmed
    providers = providers_ctx.get()
    UA = ''
    print('处理: \033[31m' + url + '\033[0m')
    prefixes = [r"vmess://", r"vless://", r"ss://", r"ssr://", r"trojan://", r"tuic://", r"hysteria://", r"hysteria2://", r"hy2://", r"wg://", r"wireguard://", r"http2://", r"socks://", r"socks5://"]

    if any(url.startswith(prefix) for prefix in prefixes):
        response_text = tool.noblankLine(url)
        return response_text

    if current_ua:
        UA = current_ua
    else:
        for subscribe in providers["subscribes"]:
            if 'enabled' in subscribe and not subscribe['enabled']:
                continue
            if subscribe['url'] == url:
                UA = subscribe.get('User-Agent', '')
                break

    def internal_recognize(text, content_bytes):
        if not text or text.isspace(): return None

        if RE_BASE64.fullmatch(text):
            pass
        elif 'proxies' in text:
            try:
                from ruamel.yaml import YAML
                yaml = YAML(typ="safe")
            except ImportError:
                yaml = None
            yaml_content = content_bytes.decode('utf-8', errors='ignore')
            response_text_no_tabs = yaml_content.replace('\t', ' ')
            # ^proxies:[\s\S]*?(?=\n\S|\z)
            match = RE_PROXIES.search(response_text_no_tabs)
            to_parse = match.group(0) if match else response_text_no_tabs
            try:
                data = yaml.load(to_parse)
                if isinstance(data, dict): return data
            except Exception as e:
                print(f"YAML Parse Error: {e}")
        elif 'outbounds' in text:
            try:
                return json_lib.loads(text)
            except:
                try:
                    cleaned = RE_CLEAN_COMMENT.sub('', text)
                    return json_lib.loads(cleaned)
                except: pass
        elif any(text.startswith(prefix) for prefix in prefixes):
            return tool.noblankLine(text)

        try:
            decoded_text = tool.b64Decode(text)
            if isinstance(decoded_text, bytes):
                return decoded_text.decode(encoding="utf-8")
            else:
                return decoded_text
        except: pass

        return text

    headers = {'User-Agent': UA if UA else "Mozilla/5.0"}
    response = None
    concount = 1
    while concount <= n:
        try:
            if not _parsers_warmed:
                resp_task = asyncio.create_task(client.get(url, headers=headers))
                warm_task = asyncio.create_task(warmup_parsers(parsers_mod, timeout=1.5))
                done, pending = await asyncio.wait({resp_task, warm_task}, return_when=asyncio.FIRST_COMPLETED)
                if resp_task not in done:
                    response = await resp_task
                else:
                    response = resp_task.result()
                try:
                    await asyncio.wait_for(warm_task, timeout=0.05)
                except asyncio.TimeoutError:
                    pass
                if _parsers_warmed:
                    pass
            else:
                response = await client.get(url, headers=headers)
            response.raise_for_status()
            break
        except Exception as e:
            print(f'连接出错: {e}，正在进行第 {concount} 次重试...')
            concount += 1
            await asyncio.sleep(1)
    if not response:
        print('获取错误，跳过此订阅')
        return ''

    try:
        main_text = response.content.decode('utf-8-sig')
    except:
        main_text = response.text

    if not main_text:
        try:
            headers['User-Agent'] = 'clashmeta'
            response = await client.get(url, headers=headers)
            main_text = response.content.decode('utf-8-sig')
        except: pass

    response_text = internal_recognize(main_text, response.content)

    if isinstance(response_text, dict):
        return response_text
    if response_text is None:
        return None

    final_content = []
    lines = response_text.splitlines()
    sub_links = []
    for line in lines:
        line = line.strip()
        if not line: continue
        if can_fetch_sub and (line.startswith("http://") or line.startswith("https://")) and line != url:
            sub_links.append(line)
        else:
            final_content.append(line)

    if sub_links:
        print(f"发现 {len(sub_links)} 个子链接，正在并发抓取...")
        sub_tasks = []
        for sub_link in sub_links:
            sub_tasks.append(get_content_from_url(client, sub_link, n=2, can_fetch_sub=False, current_ua=UA))
        sub_results = await asyncio.gather(*sub_tasks, return_exceptions=True)
        for res in sub_results:
            if isinstance(res, Exception):
                continue
            if res:
                if isinstance(res, list):
                    final_content.extend(res)
                else:
                    final_content.append(res)

    has_dict = any(isinstance(item, dict) for item in final_content)
    if has_dict:
        if len(final_content) == 1 and isinstance(final_content[0], dict):
            return final_content[0]
        return final_content

    return tool.noblankLine('\n'.join([str(x) for x in final_content if isinstance(x, str)]))

# def get_content_form_file(url):
#     print(f"处理: \033[31m{url}\033[0m")
#     file_extension = os.path.splitext(url)[1].lower()
#     if file_extension in ['.yaml', '.yml']:
#         try:
#             try:
#                 from ruamel.yaml import YAML
#                 yaml = YAML(typ="safe")
#             except ImportError:
#                 yaml = None
#             with open(url, 'rb') as file:
#                 content = file.read()
#             text_content = content.decode('utf-8', errors='ignore')
#             match = RE_PROXIES.search(text_content)
#             to_parse = match.group(0) if match else text_content
#             yaml_data = yaml.load(to_parse)
#             if not isinstance(yaml_data, dict):
#                 return ""
#             proxies = yaml_data.get('proxies', [])
#             from parsers.clash2base64 import clash2v2ray
#             share_links = [clash2v2ray(proxy) for proxy in proxies]
#             return tool.noblankLine('\n'.join(share_links))
#         except Exception as e:
#             print(f"本地 YAML 解析出错: {e}")
#             return ""
#     else:
#         data = tool.readFile(url)
#         if not data: 
#             return ""
#         try:
#             text_data = data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else str(data)
#             return tool.noblankLine(text_data)
#         except Exception as e:
#             print(f"读取或转换文件内容失败: {e}")
#             return ""

def save_config(path, nodes):
    providers = providers_ctx.get()
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
        if 'orjson' in str(json_lib.__name__):
            json_bytes = json_lib.dumps(nodes, option=json_lib.OPT_INDENT_2)
            json_text = json_bytes.decode('utf-8')
        else:
            json_text = json_lib.dumps(nodes, indent=2, ensure_ascii=False)
        tool.saveFile(path, json_text)
    except Exception as e:
        print(f"原始路径保存出错：{e}")
        config_path_raw = providers.get("save_config_path", "config.json")
        filename = os.path.basename(config_path_raw)
        config_file_path = os.path.join('/tmp', filename)
        print(f"正在尝试回退方案，保存至：\033[33m{config_file_path}\033[0m")
        try:
            if os.path.exists(config_file_path):
                os.remove(config_file_path)
            if 'orjson' in str(json_lib.__name__):
                json_text = json_lib.dumps(nodes, option=json_lib.OPT_INDENT_2).decode('utf-8')
            else:
                json_text = json_lib.dumps(nodes, indent=2, ensure_ascii=False)
            tool.saveFile(config_file_path, json_text)
            print(f"成功保存到临时目录: \033[32m{config_file_path}\033[0m")
        except Exception as retry_e:
            print(f"回退保存依然失败：{str(retry_e)}")

def set_proxy_rule_dns(config):
    providers = providers_ctx.get()
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
    providers = providers_ctx.get({})
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
    providers_obj = providers_ctx.get({})
    _globals = globals()
    template_func = _globals.get('pro_node_template')
    has_template_func = template_func is not None
    set_dns_func = _globals.get('set_proxy_rule_dns')
    wg_nodes = []
    wg_tags = set()
    other_nodes = []
    for key, members in data.items():
        if not members: continue
        for m in members:
            if isinstance(m, dict):
                tag = m.get('tag')
                if m.get('type') == 'wireguard':
                    wg_nodes.append(m)
                    if tag: wg_tags.add(tag)
                else:
                    other_nodes.append(m)
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
        if "outbounds" not in proxy_node: 
            proxy_node["outbounds"] = []
        if isinstance(proxy_node["outbounds"], str): 
            proxy_node["outbounds"] = [proxy_node["outbounds"]]
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
    template_cache = {}
    def get_template_result(members, obj, key):
        cache_key = (id(members), id(obj), key)
        if cache_key in template_cache:
            return template_cache[cache_key]
        res = template_func(members, obj, key) if has_template_func else members
        final_tags = []
        for m in res:
            if isinstance(m, dict):
                final_tags.append(m.get('tag'))
            else:
                final_tags.append(m)
        template_cache[cache_key] = final_tags
        return final_tags
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
                target_keys = []
                if key == 'all':
                    target_keys = data.keys()
                elif key in data:
                    target_keys = [key]
                for k in target_keys:
                    members = data[k]
                    if not members: continue
                    expanded_tags = get_template_result(members, o, k)
                    filtered_tags = [t for t in expanded_tags if t not in wg_tags]
                    temp_resolved.extend(filtered_tags)
                    if members: has_real_node = True
            else:
                if item in wg_tags:
                    continue
                temp_resolved.append(item)
                if item in nodes and item != node['tag']:
                    has_group_reference = True
                elif item not in subgroup_tags_set:
                    has_real_node = True
        if has_group_reference and not has_real_node:
            for s_tag in subgroup_tags_set:
                if s_tag not in temp_resolved and s_tag not in wg_tags:
                    temp_resolved.append(s_tag)
        unique_tags = list(dict.fromkeys(temp_resolved))
        node['resolved'] = [
            t for t in unique_tags 
            if not (t not in nodes and t in empty_data_keys)
        ]
        for tag in node['resolved']:
            if tag in nodes:
                reverse_dep[tag].add(node['tag'])
    group_types = {'selector', 'urltest', 'fallback', 'loadbalance'}
    dead_queue = deque()
    alive_status = {}
    for n in nodes.values():
        tag = n['tag']
        is_group = n['obj'].get('type') in group_types
        is_alive = (not is_group) or bool(n['resolved'])
        alive_status[tag] = is_alive
        if not is_alive and is_group:
            dead_queue.append(tag)
    all_dead_tags = set()
    while dead_queue:
        dead_tag = dead_queue.popleft()
        if dead_tag in all_dead_tags:
            continue
        all_dead_tags.add(dead_tag)
        for parent_tag in reverse_dep.get(dead_tag, []):
            if not alive_status.get(parent_tag): continue
            p_node = nodes[parent_tag]
            has_alive_child = False
            for child in p_node['resolved']:
                if child not in all_dead_tags and child != dead_tag:
                    has_alive_child = True
                    break
            if not has_alive_child:
                alive_status[parent_tag] = False
                dead_queue.append(parent_tag)
    out = []
    for node in nodes.values():
        if alive_status.get(node['tag']):
            obj = node['obj']
            if "outbounds" in obj or obj.get('type') in group_types:
                obj["outbounds"] = [t for t in node['resolved'] if t not in all_dead_tags]
            obj.pop("filter", None)
            current_default = obj.get('default')
            if current_default and current_default not in obj.get("outbounds", []):
                obj.pop('default', None)
            out.append(obj)
    out.extend(other_nodes)
    if config.get('dns') and config['dns'].get('servers'):
        dns_tags = {server.get('tag') for server in config['dns']['servers']}
        asod = providers_obj.get("auto_set_outbounds_dns")
        if asod and asod.get('proxy') and asod.get('direct'):
             if asod['proxy'] in dns_tags and asod['direct'] in dns_tags:
                if set_dns_func: set_dns_func(config)
    if wg_nodes:
        config['endpoints'] = wg_nodes

    config['outbounds'] = out
    return config

async def updateLocalConfig(local_host, path):
    async with httpx.AsyncClient() as client:
        r = await client.put(local_host + '/configs?force=false', json={"path": path})
        print(r.text)

# def display_template(tl):
#     print_str = ''
#     for i in range(len(tl)):
#         print_str += loop_color('{index}、{name} '.format(index=i + 1, name=tl[i]))
#     print(print_str)

async def generate_config_logic(input_providers, client, template_index=0, gh_proxy_index=None):
    providers_ctx.set(input_providers)
    tpl_val = str(input_providers.get('config_template', '')).strip()
    if tpl_val and not tpl_val.isdigit():
        try:
            response = await client.get(tpl_val, timeout=5)
            response.raise_for_status()
            config = json_lib.loads(response.content)
        except Exception as e:
            raise Exception(f"远程模板获取失败: {str(e)}")
    else:
        template_list = get_template_list()
        if not template_list:
            raise Exception("No template files found in config_template/")
        target_idx = tpl_val if tpl_val.isdigit() else template_index
        idx = int(target_idx) - 1 if str(target_idx).isdigit() else 0
        uip = idx if 0 <= idx < len(template_list) else 0
        base_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = f"{template_list[uip]}.json"
        template_path = os.path.join(base_dir, "config_template", file_name)
        if not os.path.exists(template_path):
            parent_dir = os.path.dirname(base_dir)
            template_path = os.path.join(parent_dir, "config_template", file_name)
        config = load_json(template_path)
    nodes = await process_subscribes(input_providers["subscribes"], client)

    if gh_proxy_index and str(gh_proxy_index).strip().lower() not in ['none', '']:
        gh_proxy_value = str(gh_proxy_index).strip()
        if config.get("route") and config["route"].get("rule_set"):
            rule_sets = config["route"]["rule_set"]
            urls = [item["url"] for item in rule_sets if "url" in item]
            if urls:
                from gh_proxy_helper import set_gh_proxy
                new_urls = set_gh_proxy(urls, gh_proxy_value)
                url_idx = 0
                for item in rule_sets:
                    if "url" in item:
                        item["url"] = new_urls[url_idx]
                        url_idx += 1

    if input_providers.get('Only-nodes'):
        combined_contents = [node for contents in nodes.values() for node in contents]
        final_config = {"outbounds": combined_contents}
    else:
        final_config = combin_to_config(config, nodes)

    return final_config