from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from urllib.parse import unquote, parse_qs
import os
import re
import orjson
try:
    from main import get_template_list, generate_config_logic
except ImportError:
    from ..main import get_template_list, generate_config_logic

app = FastAPI()
_templates = None
DEFAULT_PROVIDERS_STRUCTURE = {
    "subscribes": [],
    # "auto_set_outbounds_dns": {"proxy": "", "direct": ""},
    # "save_config_path": "./config.json",
    # "auto_backup": False,
    "exclude_protocol": "",
    "config_template": "",
    "Only-nodes": False
}

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
        current_file = os.path.abspath(__file__)
        base_dir = os.path.dirname(os.path.dirname(current_file))
        template_dir = os.path.join(base_dir, "templates")
        print(f"Template directory: {template_dir}")
        _templates = Jinja2Templates(directory=template_dir)
    return _templates

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    template_list = get_template_list() 
    template_options = [f"{i + 1}、{t}" for i, t in enumerate(template_list)]
    templates = get_templates_engine()
    return templates.TemplateResponse(
        "index.html", 
        {
            "request": request, 
            "template_options": template_options
        }
    )

@app.get("/config/{url:path}")
async def get_config(url: str, request: Request):
    user_agent = request.headers.get('user-agent', "")
    rua_values = os.getenv('RUA')
    if rua_values and any(rua in user_agent for rua in rua_values.split(',')):
        return JSONResponse({'status': 'error', 'message': 'block'}, status_code=403)

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
    eps = get_p('eps', 'ssr')
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

        final_config = await generate_config_logic(
            current_config,
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
        return JSONResponse(
            status_code=500,
            content={'status': 'error', 'msg': str(e)}
        )