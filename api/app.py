from fastapi import FastAPI, Request, Response, BackgroundTasks
import os
import orjson

app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

_global_client = None
_templates = None
_template_list_cache = None
_config_logic_cache = None
DEFAULT_PROVIDERS_STRUCTURE = {
    "subscribes": [],
    # "auto_set_outbounds_dns": {"proxy": "", "direct": ""},
    # "save_config_path": "./config.json",
    # "auto_backup": False,
    "ex-node-name": "",
    "exclude_protocol": "",
    "config_template": "",
    "Only-nodes": False
}

def get_client():
    global _global_client
    if _global_client is None:
        import httpx
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=1)
        timeout = httpx.Timeout(5.0, connect=5.0)
        _global_client = httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            http2=False,
            limits=limits,
            timeout=timeout
        )
    return _global_client

def get_template_list_func():
    global _template_list_cache
    if _template_list_cache is None:
        from main import get_template_list
        _template_list_cache = get_template_list
    return _template_list_cache

def get_config_logic_func():
    global _config_logic_cache
    if _config_logic_cache is None:
        from main import generate_config_logic
        _config_logic_cache = generate_config_logic
    return _config_logic_cache

def normalize_scheme(u: str) -> str:
    if not u: return u
    u = u.strip()
    if u.startswith('http:/') and not u.startswith('http://'):
        return 'http://' + u[len('http:/'):]
    if u.startswith('https:/') and not u.startswith('https://'):
        return 'https://' + u[len('https:/'):]
    return u

def get_templates_engine():
    global _templates
    if _templates is None:
        from fastapi.templating import Jinja2Templates
        current_file = os.path.abspath(__file__)
        base_dir = os.path.dirname(os.path.dirname(current_file))
        template_dir = os.path.join(base_dir, "templates")
        print(f"Template directory: {template_dir}")
        _templates = Jinja2Templates(directory=template_dir)
    return _templates

def warmup_client():
    get_client()

@app.get("/")
def index(request: Request, background_tasks: BackgroundTasks):
    fetch_template_list = get_template_list_func()
    template_list = fetch_template_list()
    template_options = [f"{i + 1}、{t}" for i, t in enumerate(template_list)]
    templates = get_templates_engine()
    background_tasks.add_task(warmup_client)
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "template_options": template_options
        }
    )

@app.get("/config/{url:path}")
async def get_config(url: str, request: Request):
    client = get_client()
    generate_logic = get_config_logic_func()
    user_agent = request.headers.get('user-agent', "")
    rua_values = os.getenv('RUA')
    if rua_values and any(rua in user_agent for rua in rua_values.split(',')):
        error_msg = orjson.dumps({'status': 'error', 'message': 'block'}, option=orjson.OPT_INDENT_2)
        return Response(content=error_msg, status_code=403, media_type="application/json")

    params = request.query_params
    def get_p(name, default=''):
        return params.get(name, default)

    def split_p(name):
        val = get_p(name)
        return val.split('|') if val else []

    gh_proxy_param = get_p('gh', None)
    onlynodes_param = get_p('onlynodes')
    file_param = get_p('file')
    enn = get_p('enn')
    eps = get_p('eps')
    raw_url_field = params.get('url') or url
    full_url = raw_url_field.replace('%7C', '|').replace('%7c', '|')
    url_parts = full_url.split('|')

    emoji_list = split_p('emoji')
    tag_list = split_p('tag')
    ua_list = split_p('ua') or split_p('UA')
    prefix_list = split_p('prefix')
    suffix_list = split_p('suffix')
    subgroup_list = split_p('subgroup')

    new_subs = []
    for idx, part in enumerate(url_parts):
        if not part: continue
        sub = {
            "url": normalize_scheme(part),
            "tag": tag_list[idx] if idx < len(tag_list) else f"Sub-{idx+1}",
            "enabled": True,
            "emoji": emoji_list[idx] == "1" if idx < len(emoji_list) else True,
            "subgroup": subgroup_list[idx] if idx < len(subgroup_list) else "",
            "prefix": prefix_list[idx] if idx < len(prefix_list) else '',
            "suffix": suffix_list[idx] if idx < len(suffix_list) else '',
            "User-Agent": ua_list[idx] if (idx < len(ua_list) and ua_list[idx]) else 'singbox',
            "ex-node-name": enn
        }
        new_subs.append(sub)

    current_config = DEFAULT_PROVIDERS_STRUCTURE.copy()
    current_config.update({
        "subscribes": new_subs,
        "exclude_protocol": eps,
        "Only-nodes": onlynodes_param == '1'
    })

    try:
        selected_template_index = 0
        current_config['config_template'] = normalize_scheme(file_param) if file_param else ''
        if file_param and file_param.isdigit():
            selected_template_index = int(file_param)

        final_config = await generate_logic(
            current_config,
            client=client,
            template_index=selected_template_index,
            gh_proxy_index=gh_proxy_param
        )
        pretty_json = orjson.dumps(
            final_config,
            option=orjson.OPT_INDENT_2 | orjson.OPT_NON_STR_KEYS
        )
        return Response(
            content=pretty_json,
            media_type="application/json"
        )

    except Exception as e:
        err_content = orjson.dumps(
            {'status': 'error', 'msg': str(e)},
            option=orjson.OPT_INDENT_2
        )
        return Response(
            content=err_content,
            status_code=500,
            media_type="application/json"
        )