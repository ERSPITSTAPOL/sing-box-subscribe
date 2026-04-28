import os
import importlib
import re
import asyncio
import tool
from contextvars import ContextVar
from urllib.parse import urlparse
from collections import defaultdict, deque
import orjson as json
import yaml
from yaml import CSafeLoader

URI_PARSERS = {
    'vmess': 'parsers.vmess',
    'vless': 'parsers.vless',
    'shadowsocks': 'parsers.ss',
    'shadowsocksr': 'parsers.ssr',
    'trojan': 'parsers.trojan',
    'tuic': 'parsers.tuic',
    'hysteria': 'parsers.hysteria',
    'hysteria2': 'parsers.hysteria2',
    'wireguard': 'parsers.wg',
    'anytls': 'parsers.anytls',
    'socks': 'parsers.socks',
    'http': 'parsers.http',
    'https': 'parsers.https',
}
CLASH_CONVERTERS = {
    'clash2sing': 'parsers.clash2sing',
    # 'clash2v2ray': 'parsers.clash2base64',   # No used anymore
}
_PARSER_CACHE = {}
_PROTO_FACTORY_CACHE = {}
_EX_PROTOCOL_CACHE = {}
_parsers_warmed = False
_warmup_lock: asyncio.Lock | None = None
_warmup_done: asyncio.Event | None = None
COMMON_PARSERS = {'vless', 'ss', 'trojan', 'hysteria2', 'anytls', 'clash2sing'}
providers_ctx: ContextVar[dict] = ContextVar("providers_ctx")

RE_BASE64 = re.compile(r'^[A-Za-z0-9+/=_ \-]+$')
RE_CLEAN_COMMENT = re.compile(r'//.*')
RE_PROXIES = re.compile(r'^proxies:.*?(?=\n\S|\Z)', re.M | re.S)

def _get_warmup_lock():
    global _warmup_lock
    if _warmup_lock is None:
        _warmup_lock = asyncio.Lock()
    return _warmup_lock

def _get_warmup_done():
    global _warmup_done
    if _warmup_done is None:
        _warmup_done = asyncio.Event()
    return _warmup_done

def get_template_list():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(base_dir, 'config_template')
    if not os.path.isdir(template_dir):
        return []
    template_list = []
    with os.scandir(template_dir) as it:
        for entry in it:
            if not entry.is_file() or not entry.name.lower().endswith('.json'):
                continue
            template_list.append(os.path.splitext(entry.name)[0])
    template_list.sort()
    return template_list

def _read_json(path: str) -> dict:
    content = tool.readFile(path)
    return json.loads(content)

async def get_template_list_async() -> list[str]:
    return await asyncio.to_thread(get_template_list)

async def load_json_async(path: str) -> dict:
    return await asyncio.to_thread(_read_json, path)

async def generate_config_logic(input_providers, client, template_index=0, gh_proxy_index=None):
    providers_ctx.set(input_providers)
    tpl_val = str(input_providers.get('config_template', '')).strip()
    if tpl_val and not tpl_val.isdigit():
        try:
            response = await client.get(tpl_val, timeout=5)
            response.raise_for_status()
            config = await asyncio.to_thread(json.loads, response.content)
        except Exception as e:
            raise Exception(f"Fetch remote template failed: {str(e)}")
    else:
        template_list = await get_template_list_async()
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
        config = await load_json_async(template_path)

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
        endpoints = []
        outbounds = []
        for contents in nodes.values():
            for n in contents:
                if n.get('type') == 'wireguard':
                    endpoints.append(n)
                else:
                    outbounds.append(n)
        final_config = {"outbounds": outbounds}
        if endpoints:
            final_config["endpoints"] = endpoints
    else:
        final_config = await asyncio.to_thread(combin_to_config, config, nodes)

    return final_config

async def process_subscribes(subscribes, client):
    nodes = {}
    async def with_timeout(sub):
        try:
            return await asyncio.wait_for(
                process_single_subscribe(sub, client),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            print(f"Subscription [{sub.get('tag')}] timed out, skipping")
            return None
        except Exception as exc:
            print(f"Subscription [{sub.get('tag')}] failed: {exc}")
            return None
    tasks = [asyncio.create_task(with_timeout(sub)) for sub in subscribes if sub.get('enabled') is not False]
    if not tasks:
        tool.DuplicateNodeName(nodes)
        return nodes
    results = await asyncio.gather(*tasks)
    for result in results:
        if not result or result[0] is None:
            continue
        target_tag, _nodes = result
        if target_tag not in nodes:
            nodes[target_tag] = []
        nodes[target_tag].extend(_nodes)
    tool.DuplicateNodeName(nodes)
    return nodes

async def process_single_subscribe(subscribe, client):
    tag_name = subscribe.get('tag')
    subgroup = subscribe.get('subgroup')
    url = subscribe.get('url')
    user_agent = subscribe.get('User-Agent')
    prefix = subscribe.get('prefix')
    suffix = subscribe.get('suffix')
    ex_node_name = subscribe.get('ex-node-name')
    exclude_protocol = subscribe.get('exclude_protocol')
    target_tag = tag_name
    try:
        _nodes = await get_nodes(client, url, user_agent, exclude_protocol)
        if not _nodes:
            print(f"No nodes found under subscription [{tag_name}], skipping")
            return None, None
        add_emoji(_nodes, subscribe)
        if ex_node_name is not None or exclude_protocol is not None:
            nodefilter(_nodes, ex_node_name, exclude_protocol)
        if prefix is not None or suffix is not None:
            add_prefix_and_suffix(_nodes, prefix, suffix)
        if subgroup:
            subgroup_str = str(subgroup).strip()
            if subgroup_str:
                target_tag = f"{tag_name}-{subgroup_str}-subgroup"
        return target_tag, _nodes
    except Exception as e:
        print(f"Error occurred while processing subscription [{tag_name}]: {e}")
        return None, None

async def get_nodes(client, url, user_agent, exclude_protocol):
    if url.startswith('sub://'):
        url = tool.b64Decode(url[6:]).decode('utf-8')
    urlstr = urlparse(url)
    if not urlstr.scheme:
        try:
            asyncio.create_task(warmup_parsers(URI_PARSERS, timeout=0.5))
            content = await asyncio.to_thread(lambda: tool.b64Decode(url).decode('utf-8'))
            data = await asyncio.to_thread(parse_content, content, exclude_protocol)
            return [node for item in data for node in (item if isinstance(item, tuple) else [item])]
        except Exception as e:
            print(f"Base64 decode failed, returning original text: {url}, error: {e}")
            return [url]
    else:
        content = await get_content_from_url(client, url, user_agent)

    contents = content if isinstance(content, list) else [content]
    nodes_list = []

    for content_item in contents:
        if isinstance(content_item, dict):
            if 'proxies' in content_item:
                mod = _load_clash_converter('clash2sing')
                c2s = getattr(mod, 'parse', None) if mod else None
                if not c2s:
                    print(f"Parser load failed [clash2sing]: unable to load module")
                    continue
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
                for outbound in content_item.get('outbounds', []):
                    if outbound.get("type") in excluded_types:
                        continue
                    nodes_list.append(outbound)
        elif isinstance(content_item, str):
            data = await asyncio.to_thread(parse_content, content_item, exclude_protocol)
            nodes_list.extend([node for item in data for node in (item if isinstance(item, tuple) else [item])])
    return nodes_list

async def get_content_from_url(client, url, user_agent=None, max_retries=3, can_fetch_sub=True):
    global _parsers_warmed
    providers = providers_ctx.get()
    UA = user_agent or ''
    print(f"Processing: {url}")
    # print(f"User-Agent: {UA}")
    prefixes = ("vmess://", "vless://", "anytls://", "ss://", "ssr://", "trojan://", "tuic://", "hysteria://", "hysteria2://", "hy2://", "wg://", "wireguard://", "http2://", "socks://", "socks5://")

    if url.startswith(prefixes):
        return tool.noblankLine(url)

    if not user_agent:
        for subscribe in providers["subscribes"]:
            if subscribe.get('enabled') is False:
                continue
            if subscribe['url'] == url:
                UA = subscribe.get('User-Agent', '')
                break
    # if UA:
    #     print(f"Final User-Agent: {UA}")

    def internal_recognize(text, content_bytes):
        if not text or text.isspace():
            return None
        # printed_stages = set()

        def action_yaml():
            if '\t' in text:
                yaml_text = text.replace('\t', ' ')
            else:
                yaml_text = text
            # ^proxies:[\s\S]*?(?=\n\S|\z)
            match = RE_PROXIES.search(yaml_text)
            to_parse = match.group(0) if match else yaml_text
            try:
                data = yaml.load(to_parse, Loader=CSafeLoader)
                if isinstance(data, dict):
                    return data
            except Exception as e:
                print(f"YAML Parseing Error: {e}")
            return None

        def action_json():
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    return data
            except Exception:
                try:
                    cleaned = RE_CLEAN_COMMENT.sub('', text)
                    data = json.loads(cleaned)
                    if isinstance(data, dict):
                        return data
                except Exception as e:
                    print(f"JSON Parseing Error: {e}")
            return None

        def action_URI():
            lines = text.splitlines()
            if any(line.lstrip()[:16].startswith(prefixes) for line in lines if line.strip()):
                return tool.noblankLine(text)
            try:
                decoded = tool.b64Decode(text)
                if decoded:
                    if isinstance(decoded, bytes):
                        return decoded.decode('utf-8')
                    return decoded
                return None
            except Exception:
                return None

        methods = {
            'yaml': action_yaml,
            'json': action_json,
            'URI': action_URI
        }
        tried_methods = set()
        primary = None

        ua_lower = UA.lower()
        if 'sing' in ua_lower or 'box' in ua_lower:
            primary = 'json'
        elif 'clash' in ua_lower:
            primary = 'yaml'
        elif 'ray' in ua_lower:
            primary = 'URI'
        if primary:
            result = methods[primary]()
            tried_methods.add(primary)
        #     if 'stage1' not in printed_stages:
        #         print(f"[Stage1] Attempting preferred ({primary}), methods tried so far: {sorted(tried_methods)}")
        #         printed_stages.add('stage1')
            if isinstance(result, (dict, str)):
        #         if 'result' not in printed_stages:
        #             print(f"[Stage1 result] Preferred ({primary}) returned a valid result, methods tried so far: {sorted(tried_methods)}")
        #             printed_stages.add('result')
                return result

        if 'json' not in tried_methods and (text.startswith('{') or 'outbounds' in text):
        #     if 'stage2' not in printed_stages:
        #         print(f"[Stage2] Feature match triggered (json), methods tried so far: {sorted(tried_methods)}")
        #         printed_stages.add('stage2')
            result = methods['json']()
            tried_methods.add('json')
            if isinstance(result, dict):
        #         print(f"[Stage2 result] Feature match succeeded (json), methods tried so far: {sorted(tried_methods)}")
        #         printed_stages.add('result')
                return result
        #     else:
        #         print(f"[Stage2 result] JSON parsing failed, methods tried so far: {sorted(tried_methods)}")
        elif 'yaml' not in tried_methods and any(line.lstrip().startswith('proxies') for line in text.splitlines()):
        #     if 'stage2' not in printed_stages:
        #         print(f"[Stage2] Feature match triggered (yaml), methods tried so far: {sorted(tried_methods)}")
        #         printed_stages.add('stage2')
            result = methods['yaml']()
            tried_methods.add('yaml')
            if isinstance(result, dict):
        #         print(f"[Stage2 result] Feature match succeeded (yaml), methods tried so far: {sorted(tried_methods)}")
        #         printed_stages.add('result')
                return result
        #     else:
        #         print(f"[Stage2 result] YAML parsing failed, methods tried so far: {sorted(tried_methods)}"
        elif 'URI' not in tried_methods and (text.startswith(prefixes) or RE_BASE64.match(text)):
        #     if 'stage2' not in printed_stages:
        #         print(f"[Stage2] Feature match triggered (URI), methods tried so far: {sorted(tried_methods)}")
        #         printed_stages.add('stage2')
            result = methods['URI']()
            tried_methods.add('URI')
            if isinstance(result, str):
        #         print(f"[Stage2 result] Feature match succeeded (URI), methods tried so far: {sorted(tried_methods)}")
        #         printed_stages.add('result')
                return result
        #     else:
        #         print(f"[Stage2 result] URI parsing failed, methods tried so far: {sorted(tried_methods)}")
        # if 'stage2_end' not in printed_stages:
        #     print(f"[Stage2 end] tried_methods: {sorted(tried_methods)}")
        #     printed_stages.add('stage2_end')

        remaining = [name for name in methods.keys() if name not in tried_methods]
        # if 'stage3_start' not in printed_stages:
        #     print(f"[Stage3] Before fallback attempts, tried_methods: {sorted(tried_methods)}, remaining: {remaining}")
        #     printed_stages.add('stage3_start')
        for name in remaining:
            result = methods[name]()
            tried_methods.add(name)
        #     if 'stage3' not in printed_stages:
        #         print(f"[Stage3] Fallback attempt ({name}), methods tried so far: {sorted(tried_methods)}")
        #         printed_stages.add('stage3')
            if isinstance(result, (dict, str)):
        #         print(f"[Stage3 result] Fallback method succeeded ({name}), methods tried so far: {sorted(tried_methods)}")
        #         printed_stages.add('result')
                return result
        # if 'final' not in printed_stages:
        #     print(f"[Final] Unable to parse into structured data, methods tried: {sorted(tried_methods)}")
        #     printed_stages.add('final')
        return text

    headers = {'User-Agent': UA if UA else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"}
    response = None
    concount = 1

    while concount <= max_retries:
        try:
            if concount == 1 and not _parsers_warmed:
                resp_task = asyncio.create_task(client.get(url, headers=headers))
                warm_task = asyncio.create_task(warmup_parsers(URI_PARSERS, timeout=1.0))
                done, _ = await asyncio.wait({resp_task, warm_task}, return_when=asyncio.FIRST_COMPLETED)
                if resp_task not in done:
                    response = await resp_task
                else:
                    response = resp_task.result()
            else:
                response = await client.get(url, headers=headers)
            response.raise_for_status()
            break
        except Exception as e:
            print(f"Connection error: {e}, retrying attempt {concount}...")
            concount += 1
    if not response:
        print('Fetch failed, Skipping this subscription')
        return ''

    try:
        main_text = response.content.decode('utf-8-sig')
    except Exception:
        main_text = response.text
    if not main_text:
        try:
            headers['User-Agent'] = 'v2rayNG'
            response = await client.get(url, headers=headers)
            main_text = response.content.decode('utf-8-sig')
        except Exception:
            pass
    response_text = await asyncio.to_thread(internal_recognize, main_text, response.content)

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
        if can_fetch_sub and line.startswith(("http://", "https://")) and line != url:
            sub_links.append(line)
        else:
            final_content.append(line)

    if sub_links:
        print(f"Found {len(sub_links)} sub-links: {sub_links}")
        sub_tasks = [
            get_content_from_url(client, sub_link, user_agent=UA, max_retries=2, can_fetch_sub=False)
            for sub_link in sub_links
        ]
        sub_results = await asyncio.gather(*sub_tasks, return_exceptions=True)
        for res in sub_results:
            if isinstance(res, Exception):
                print(f"Fetch sub-link failed: {res}")
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

async def warmup_parsers(URI_PARSERS, timeout=1.0):
    global _parsers_warmed, _PARSER_CACHE
    if _parsers_warmed or _get_warmup_done().is_set():
        return
    async with _get_warmup_lock():
        if _parsers_warmed:
            return
        coros = []
        async def _import_one(proto):
            if proto in URI_PARSERS:
                await asyncio.to_thread(_load_parser, proto)
            elif proto in CLASH_CONVERTERS:
                await asyncio.to_thread(_load_clash_converter, proto)
        for proto in COMMON_PARSERS:
            if proto not in _PARSER_CACHE:
                coros.append(_import_one(proto))
        if not coros:
            _parsers_warmed = True
            _get_warmup_done().set()
            return
        try:
            await asyncio.wait_for(asyncio.gather(*coros), timeout=timeout)
            _parsers_warmed = True
        except asyncio.TimeoutError:
            pass
        finally:
            for proto in URI_PARSERS:
                if proto not in _PROTO_FACTORY_CACHE:
                    factory = get_parser(f"{proto}://")
                    if factory:
                        _PROTO_FACTORY_CACHE[proto] = factory
            _get_warmup_done().set()

def parse_content(content, exclude_protocol_override):
    lines = [t.strip() for t in content.splitlines() if t.strip()]
    if not lines:
        return []
    task_factories = {}
    unique_protos = {tool.get_protocol(line) for line in lines}
    unique_protos.discard(None)
    for proto in unique_protos:
        if exclude_protocol_override:
            factory = get_parser(f"{proto}://", exclude_protocol_override)
        elif proto in _PROTO_FACTORY_CACHE:
            factory = _PROTO_FACTORY_CACHE[proto]
        else:
            factory = get_parser(f"{proto}://")
        if factory:
            task_factories[proto] = factory
    nodelist = []
    _get_proto = tool.get_protocol
    for line in lines:
        proto = _get_proto(line)
        if proto in task_factories:
            try:
                node = task_factories[proto](line)
                if node:
                    nodelist.append(node)
            except Exception as e:
                print(f"Error: {e}, content: {line[:30]}")
                continue
    return nodelist

def get_parser(node, exclude_protocol_override=None):
    canonical = tool.get_protocol(node)
    if not canonical:
        return None
    excluded_raw = exclude_protocol_override
    if excluded_raw:
        cache_key = tuple(excluded_raw) if isinstance(excluded_raw, list) else excluded_raw
        ex_set = _EX_PROTOCOL_CACHE.get(cache_key)
        if ex_set is None:
            if isinstance(excluded_raw, str):
                items = [p.strip().lower() for p in excluded_raw.split(',') if p.strip()]
            else:
                items = [str(p).strip().lower() for p in excluded_raw]
            ex_set = {getattr(tool, '_PROTOCOL_MAP', {}).get(p, p) for p in items}
            _EX_PROTOCOL_CACHE[cache_key] = ex_set
        if canonical in ex_set:
            return None
    mod = _load_parser(canonical)
    return getattr(mod, 'parse', None) if mod else None

def _load_parser(proto):
    if proto in _PARSER_CACHE:
        return _PARSER_CACHE[proto]
    module_path = URI_PARSERS.get(proto)
    if not module_path:
        return None
    try:
        mod = importlib.import_module(module_path)
        _PARSER_CACHE[proto] = mod
        return mod
    except Exception as e:
        print(f"URI Parser loading failure [{proto}]: {e}")
        return None

def _load_clash_converter(name):
    if name in _PARSER_CACHE:
        return _PARSER_CACHE[name]
    module_path = CLASH_CONVERTERS.get(name)
    if not module_path:
        return None
    try:
        mod = importlib.import_module(module_path)
        _PARSER_CACHE[name] = mod
        return mod
    except Exception as e:
        print(f"Clash converter loading failure [{name}]: {e}")
        return None

def add_emoji(nodes, subscribe):
    if subscribe.get('emoji'):
        rename_func = tool.rename
        for node in nodes:
            if 'tag' in node:
                node['tag'] = rename_func(node['tag'])
            if (detour := node.get('detour')):
                node['detour'] = rename_func(detour)

def add_prefix_and_suffix(nodes, prefix, suffix):
    p = prefix or ''
    s = suffix or ''
    if p and not s:
        prefix_str = f"{p} "
        for node in nodes:
            if 'tag' in node:
                node['tag'] = prefix_str + node['tag']
            if (detour := node.get('detour')):
                node['detour'] = prefix_str + detour
    elif s and not p:
        suffix_str = f" {s}"
        for node in nodes:
            if 'tag' in node:
                node['tag'] = node['tag'] + suffix_str
            if (detour := node.get('detour')):
                node['detour'] = detour + suffix_str
    else:
        prefix_str = f"{p} "
        suffix_str = f" {s}"
        for node in nodes:
            if 'tag' in node:
                node['tag'] = prefix_str + node['tag'] + suffix_str
            if (detour := node.get('detour')):
                node['detour'] = prefix_str + detour + suffix_str

def nodefilter(nodes, ex_node_name, exclude_protocol):
    ex_node_str = ex_node_name
    ex_node_protocol = exclude_protocol
    name_list = [re.escape(s.strip()) for s in str(ex_node_str).split(',') if s.strip()] if ex_node_str else []
    proto_list = [re.escape(s.strip()) for s in str(ex_node_protocol).split(',') if s.strip()] if ex_node_protocol else []
    if not name_list and not proto_list:
        return
    name_pattern = re.compile('|'.join(name_list)) if name_list else None
    proto_pattern = re.compile('|'.join(proto_list)) if proto_list else None
    n_search = name_pattern.search if name_pattern else None
    p_search = proto_pattern.search if proto_pattern else None
    nodes[:] = [
        node for node in nodes
        if not (
            (n_search(tag) if n_search and (tag := node.get('tag')) else False) or
            (p_search(proto) if p_search and (proto := node.get('type')) else False)
        )
    ]

def combin_to_config(config, data):
    providers_obj = providers_ctx.get({})
    template_func = globals().get('pro_node_template')
    has_template_func = template_func is not None
    set_dns_func = globals().get('set_proxy_rule_dns')

    wg_nodes = []
    wg_tags = set()
    other_nodes = []
    wg_nodes_append = wg_nodes.append
    wg_tags_add = wg_tags.add
    other_nodes_append = other_nodes.append
    for members in data.values():
        if not members: continue
        for m in members:
            if isinstance(m, dict):
                tag = m.get('tag')
                if m.get('type') == 'wireguard':
                    wg_nodes_append(m)
                    if tag: wg_tags_add(tag)
                else:
                    other_nodes_append(m)

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
                    'interrupt_exist_connections':True,
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
            all_idx = next((i for i, t in enumerate(proxy_node["outbounds"]) if t == '{all}'), None)
            if all_idx is not None:
                proxy_node["outbounds"][all_idx:all_idx] = final_additions
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
        final_tags = [m.get('tag') if isinstance(m, dict) else m for m in res]
        template_cache[cache_key] = final_tags
        return final_tags

    _nodes = nodes
    _data = data
    _wg_tags = wg_tags
    _subgroup_tags_set = subgroup_tags_set
    _empty_data_keys = empty_data_keys
    _dead_empty = _empty_data_keys - nodes.keys()

    for node in _nodes.values():
        o = node['obj']
        raw = o.get("outbounds", [])
        if isinstance(raw, str): raw = [raw]
        temp_resolved = []
        temp_resolved_extend = temp_resolved.extend
        temp_resolved_append = temp_resolved.append
        has_group_reference = False
        has_real_node = False
        for item in raw:
            if item.startswith('{') and item.endswith('}'):
                key = item[1:-1]
                target_keys = _data.keys() if key == 'all' else ([key] if key in _data else [])
                for k in target_keys:
                    members = _data[k]
                    if not members: continue
                    expanded_tags = get_template_result(members, o, k)
                    temp_resolved_extend(t for t in expanded_tags if t not in _wg_tags)
                    has_real_node = True
            else:
                if item in _wg_tags:
                    continue
                temp_resolved_append(item)
                if item in _nodes and item != node['tag']:
                    has_group_reference = True
                elif item not in _subgroup_tags_set:
                    has_real_node = True
        if has_group_reference and not has_real_node:
            temp_resolved_set = set(temp_resolved)
            for s_tag in _subgroup_tags_set:
                if s_tag not in temp_resolved_set and s_tag not in _wg_tags:
                    temp_resolved_append(s_tag)
        unique_tags = list(dict.fromkeys(temp_resolved))
        node['resolved'] = [t for t in unique_tags if t not in _dead_empty]
        for tag in node['resolved']:
            if tag in _nodes:
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
    _reverse_dep = reverse_dep
    _alive_status = alive_status
    while dead_queue:
        dead_tag = dead_queue.popleft()
        if dead_tag in all_dead_tags:
            continue
        all_dead_tags.add(dead_tag)
        for parent_tag in _reverse_dep.get(dead_tag, ()):
            if not _alive_status.get(parent_tag): continue
            p_node = nodes[parent_tag]
            has_alive_child = any(
                child not in all_dead_tags and child != dead_tag
                for child in p_node['resolved']
            )
            if not has_alive_child:
                _alive_status[parent_tag] = False
                dead_queue.append(parent_tag)

    out = []
    out_append = out.append
    _all_dead_tags = all_dead_tags
    for node in nodes.values():
        if _alive_status.get(node['tag']):
            obj = node['obj']
            if "outbounds" in obj or obj.get('type') in group_types:
                obj["outbounds"] = [t for t in node['resolved'] if t not in _all_dead_tags]
            obj.pop("filter", None)
            current_default = obj.get('default')
            if current_default:
                final_outbounds = obj.get("outbounds", [])
                if current_default not in set(final_outbounds):
                    obj.pop('default', None)
            out_append(obj)
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

def pro_node_template(data_nodes, config_outbound, group):
    if config_outbound.get('filter'):
        data_nodes = nodes_filter(data_nodes, config_outbound['filter'], group)
    return [node.get('tag') for node in data_nodes]

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