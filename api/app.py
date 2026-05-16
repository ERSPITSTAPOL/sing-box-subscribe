from fastapi import FastAPI
from fastapi import Request
from fastapi import Response
from fastapi import Query
from typing import List, Optional
# from fastapi import BackgroundTasks
import os
import orjson

app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

_global_client = None
# _templates = None
# _template_list_cache = None
_config_logic_cache = None
DEFAULT_PROVIDERS_STRUCTURE = {
    "subscribes": [],
    # "auto_set_outbounds_dns": {"proxy": "", "direct": ""},
    # "save_config_path": "./config.json",
    # "auto_backup": False,
    "config_template": "",
    "Only-nodes": False
}

def get_client():
    global _global_client
    if _global_client is None:
        import httpx
        _global_client = httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            http2=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=10),
            timeout=httpx.Timeout(5.0, connect=5.0)
        )
    return _global_client
'''
def get_template_list_func():
    global _template_list_cache
    if _template_list_cache is None:
        from main import get_template_list
        _template_list_cache = get_template_list
    return _template_list_cache
'''
def get_config_logic_func():
    global _config_logic_cache
    if _config_logic_cache is None:
        from main import generate_config_logic
        _config_logic_cache = generate_config_logic
    return _config_logic_cache

def normalize_scheme(u: str) -> str:
    if not u:
        return u
    u = u.strip()
    if u.startswith(('http://', 'https://')):
        return u
    if u.startswith('https:/'):
        return 'https://' + u[7:]
    if u.startswith('http:/'):
        return 'http://' + u[6:]
    return u
'''
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
'''
'''
def warmup_client():
    get_client()
'''
@app.get("/config/warmup")
def warmup():
    get_client()
'''
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
'''
@app.get("/config/{url:path}")
async def get_config(
    url: str,
    request: Request,
    url_query: List[str] = Query(default=[], alias="url"),
    gh: Optional[str] = None,
    onlynodes: Optional[str] = None,
    file: Optional[str] = None,
    enn: Optional[str] = None,
    eps: Optional[str] = None,
    emoji: Optional[str] = None,
    tag: Optional[str] = None,
    ua: Optional[str] = None,
    UA: Optional[str] = None,
    prefix: Optional[str] = None,
    suffix: Optional[str] = None,
    subgroup: Optional[str] = None,
):
    client = get_client()
    generate_logic = get_config_logic_func()
    user_agent = request.headers.get('user-agent', "")

    rua_values = os.getenv('RUA')
    if rua_values and any(rua in user_agent for rua in rua_values.split(',')):
        errormsg = orjson.dumps(
            {'status': 'error', 'message': 'block'},
            option=orjson.OPT_INDENT_2
        )
        return Response(
            content=errormsg,
            status_code=403,
            media_type="application/json"
        )

    url_parts = [p for p in url_query if p] or ([url] if url else [])
    MAX_SUBS = 10
    if len(url_parts) > MAX_SUBS:
        errormsg = orjson.dumps(
            {"status": "error", "message": f"Exceeding the subscription limit! MAX={MAX_SUBS}"},
            option=orjson.OPT_INDENT_2
        )
        return Response(
            content=errormsg,
            status_code=422,
            media_type="application/json"
        )

    def split_param_keep_positions(val: Optional[str]) -> list:
        if not val:
            return []
        normalized = val.replace('%7C', '|').replace('%7c', '|')
        return [p.strip() for p in normalized.split('|')]

    def pick_or_none(parts: list, idx: int):
        if idx < len(parts):
            return parts[idx] if parts[idx] != '' else None
        return None

    enn_list = split_param_keep_positions(enn)
    eps_list = split_param_keep_positions(eps)
    emoji_list = split_param_keep_positions(emoji)
    tag_list = split_param_keep_positions(tag)
    ua_list = split_param_keep_positions(ua) or split_param_keep_positions(UA)
    prefix_list = split_param_keep_positions(prefix)
    suffix_list = split_param_keep_positions(suffix)
    subgroup_list = split_param_keep_positions(subgroup)

    new_subs = []
    for idx, part in enumerate(url_parts):
        tag_val = pick_or_none(tag_list, idx)
        emoji_val = pick_or_none(emoji_list, idx)
        subgroup_val = pick_or_none(subgroup_list, idx)
        prefix_val = pick_or_none(prefix_list, idx)
        suffix_val = pick_or_none(suffix_list, idx)
        ua_val = pick_or_none(ua_list, idx)
        enn_val = pick_or_none(enn_list, idx)
        eps_val = pick_or_none(eps_list, idx)

        tag_final = tag_val if tag_val is not None else f"Sub-{idx+1}"
        emoji_final = True if emoji_val is None else (emoji_val == "1")
        ua_final = ua_val if ua_val is not None else 'singbox'

        new_subs.append({
            "url": normalize_scheme(part),
            "tag": tag_final,
            "enabled": True,
            "emoji": emoji_final,
            "subgroup": subgroup_val,
            "prefix": prefix_val,
            "suffix": suffix_val,
            "User-Agent": ua_final,
            "ex-node-name": enn_val,
            "exclude_protocol": eps_val
        })

    current_providers = DEFAULT_PROVIDERS_STRUCTURE.copy()
    current_providers.update({
        "subscribes": new_subs,
        "Only-nodes": onlynodes == '1'
    })
    if file and file.isdigit():
        current_providers['config_template'] = file
    else:
        current_providers['config_template'] = normalize_scheme(file) if file else ''

    try:
        final_config = await generate_logic(
            current_providers,
            client=client,
            gh_proxy_index=gh
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