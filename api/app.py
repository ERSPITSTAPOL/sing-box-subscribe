from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from urllib.parse import quote, urlparse, unquote, unquote_plus, parse_qs, parse_qsl
import json
import os
import sys
import subprocess
import tempfile
import shutil
import tempfile  # 导入 tempfile 模块
from datetime import datetime, timedelta

app = Flask(__name__, template_folder='../templates')  # 指定模板文件夹的路径
# 环境变量设置Flask密钥
app.secret_key = os.environ.get("SECRET_KEY", "fallback-secret")

data_json = {}
os.environ['TEMP_JSON_DATA'] = '{"subscribes":[{"url":"URL","enabled":true,"emoji":1,"suffix":"","prefix":"","User-Agent":"","background":"","template":"","tag":"","subgroup":""},{"url":"URL","enabled":false,"emoji":1,"suffix":"","prefix":"","User-Agent":"","tag":"","subgroup":""}],"auto_set_outbounds_dns":{"proxy":"","direct":""},"save_config_path":"./config.json","auto_backup":false,"exclude_protocol":"ssr","config_template":"","Only-nodes":false}'
data_json['TEMP_JSON_DATA'] = '{"subscribes":[{"url":"URL","enabled":true,"emoji":1,"suffix":"","prefix":"","User-Agent":"","background":"","template":"","tag":"","subgroup":""},{"url":"URL","enabled":false,"emoji":1,"suffix":"","prefix":"","User-Agent":"","tag":"","subgroup":""}],"auto_set_outbounds_dns":{"proxy":"","direct":""},"save_config_path":"./config.json","auto_backup":false,"exclude_protocol":"ssr","config_template":"","Only-nodes":false}'

# 获取系统默认的临时目录路径
TEMP_DIR = tempfile.gettempdir()

"""
# 存储配置文件的过期时间（10分钟）
config_expiry_time = None
"""
def cleanup_temp_config():
    global config_expiry_time, config_file_path
    if config_expiry_time and datetime.now() > config_expiry_time:
        shutil.rmtree(os.path.dirname(config_file_path), ignore_errors=True)
        config_expiry_time = None
        config_file_path = None

# 获取临时 JSON 数据
def get_temp_json_data():
    temp_json_data = os.environ.get('TEMP_JSON_DATA')
    if temp_json_data:
        return json.loads(temp_json_data)
    return {}

# 获取config_template目录下的模板文件列表
def get_template_list():
    template_list = []
    config_template_dir = 'config_template'  # 配置模板文件夹路径
    template_files = os.listdir(config_template_dir)  # 获取文件夹中的所有文件
    template_list = [os.path.splitext(file)[0] for file in template_files if file.endswith('.json')]  # 移除扩展名并过滤出以.json结尾的文件
    template_list.sort()  # 对文件名进行排序
    return template_list

# 读取providers.json文件的内容，如果有临时 JSON 数据则使用它
def read_providers_json():
    temp_json_data = get_temp_json_data()
    if temp_json_data :
        return temp_json_data
    with open('providers.json', 'r', encoding='utf-8') as json_file:
        providers_data = json.load(json_file)
    return providers_data

# 写入providers.json文件的内容，如果有临时 JSON 数据则不写入
def write_providers_json(data):
    temp_json_data = get_temp_json_data()
    if not temp_json_data:
        with open('providers.json', 'w', encoding='utf-8') as json_file:
            json.dump(data, json_file, indent=4, ensure_ascii=False)

# 构造转换订阅
@app.route('/generate_url', methods=['POST'])
def generate_target_url():
    try:
        temp_json_data = os.environ.get('TEMP_JSON_DATA')
        if not temp_json_data:
            return Response("TEMP_JSON_DATA is missing", content_type="text/plain; charset=utf-8", status=400)
        providers_data = json.loads(temp_json_data)
        final_url = build_target_url(providers_data)
        if final_url:
            os.environ['TEMP_JSON_DATA'] = json.dumps(json.loads(data_json['TEMP_JSON_DATA']), indent=4, ensure_ascii=False)
            return Response(final_url, content_type="text/plain; charset=utf-8")
        else:
            os.environ['TEMP_JSON_DATA'] = json.dumps(json.loads(data_json['TEMP_JSON_DATA']), indent=4, ensure_ascii=False)
            return Response("No subscribes found", content_type="text/plain; charset=utf-8", status=400)
    except Exception as e:
        try:
            os.environ['TEMP_JSON_DATA'] = json.dumps(json.loads(data_json['TEMP_JSON_DATA']), indent=4, ensure_ascii=False)
        except Exception:
            pass
        return Response(f"Error: {str(e)}", content_type="text/plain; charset=utf-8", status=500)
def build_target_url(providers_data: dict) -> str:
    subscribes = providers_data.get("subscribes", [])
    if not subscribes:
        return ""
    background = subscribes[0].get("background", "").rstrip("/")
    if not background:
        background = "https://sub.erspit.qzz.io"
    template = subscribes[0].get("template", "")
    if not template:
        template = "https://raw.githubusercontent.com/ERSPITSTAPOL/sing-box-subscribe/refs/heads/main/config_template/config1.13.json"
    urls = [sub["url"] for sub in subscribes if sub.get("enabled", False) and sub.get("url")]
    if not urls:
        return ""
    if len(urls) > 1:
        joined_urls = "|".join(urls)
        encoded_urls = quote(joined_urls, safe="")
        final_url = f"{background}/config/{encoded_urls}&file={template}"
    else:
        final_url = f"{background}/config/{urls[0]}&file={template}"
    return final_url

# 默认路径显示index.html
@app.route('/')
def index():
    template_list = get_template_list()
    template_options = [f"{index + 1}、{template}" for index, template in enumerate(template_list)]
    providers_data = read_providers_json()
    temp_json_data = get_temp_json_data()
    return render_template('index.html', template_options=template_options, providers_data=json.dumps(providers_data, indent=4, ensure_ascii=False), temp_json_data=json.dumps(temp_json_data, indent=4, ensure_ascii=False))

@app.route('/update_providers', methods=['POST'])
def update_providers():
    try:
        # 获取表单提交的数据
        new_providers_data = json.loads(request.form.get('providers_data'))
        # 更新providers.json文件
        write_providers_json(new_providers_data)
        flash('Providers.json文件已更新', 'success')
    except Exception as e:
        flash(f'更新Providers.json文件时出错；{str(e)}', 'error')
    return redirect(url_for('index'))

@app.route('/edit_temp_json', methods=['GET', 'POST'])
def edit_temp_json():
    if request.method == 'POST':
        try:
            new_temp_json_data = request.form.get('temp_json_data')
            print (new_temp_json_data)
            if new_temp_json_data:
                temp_json_data = json.loads(new_temp_json_data)
                os.environ['TEMP_JSON_DATA'] = json.dumps(temp_json_data, indent=4, ensure_ascii=False)
                flash('TEMP_JSON_DATA 已更新', 'success')
                return jsonify({'status': 'success'})  # 返回成功状态
            else:
                return jsonify({'status': 'error', 'message': 'TEMP_JSON_DATA 不能为空'}, content_type='application/json; charset=utf-8')  # 返回错误状态和消息
        except Exception as e:
            flash('TEMP_JSON_DATA 不能为空', 'error')
            flash('TEMP_JSON_DATA 格式出错：注意订阅链接末尾不要有换行，要在双引号""里面！！！')
            flash('TEMP_JSON_DATA')
            flash('TEMP_JSON_DATA cannot be empty', 'error')
            flash(f'Error updating TEMP_JSON_DATA: note that the subscription link should not have a newline at the end, but should be inside double quotes ""')
            return jsonify({'status': 'error', 'message': str(e)})  # 返回错误状态和消息

@app.route('/config/<path:url>', methods=['GET'])
def config(url):
    user_agent = request.headers.get('User-Agent') or ""
    rua_values = os.getenv('RUA')
    if rua_values and any(rua_value in user_agent for rua_value in rua_values.split(',')):
        return Response(json.dumps({'status': 'error', 'message': 'block'}, indent=4, ensure_ascii=False),
                        content_type='application/json; charset=utf-8', status=403)
    substrings = os.getenv('STR')
    if substrings and any(substring in url for substring in substrings.split(',')):
        return Response(json.dumps({'status': 'error', 'message_CN': '填写参数不符合规范'}, indent=4, ensure_ascii=False),
                        content_type='application/json; charset=utf-8', status=403)

    temp_json_data = json.loads(data_json['TEMP_JSON_DATA'])

    subscribes = temp_json_data['subscribes']

    def normalize_scheme(u: str) -> str:
        if not u:
            return u
        if u.startswith('http:/') and not u.startswith('http://'):
            return 'http://' + u[len('http:/'):]
        if u.startswith('https:/') and not u.startswith('https://'):
            return 'https://' + u[len('https:/'):]
        return u

    def safe_unquote(value: str, max_rounds: int = 3) -> str:
        if not isinstance(value, str) or value == "":
            return value
        cur = value
        for _ in range(max_rounds):
            decoded = unquote_plus(cur)
            if decoded == cur:
                break
            cur = decoded
        return cur

    query_string = request.query_string.decode('utf-8')
    encoded_url = unquote(url)
    encoded_url = normalize_scheme(encoded_url)
    index_of_colon = encoded_url.find(":")

    if not query_string:
        if any(substring in encoded_url for substring in ['&emoji=', '&file=', '&eps=', '&enn=', '&prefix=', '&suffix=', '&tag=', '&ua=', '&UA=', '&gh=']):
            if '|' in encoded_url:
                param = urlparse(encoded_url.rsplit('&', 1)[-1])
            else:
                param = urlparse(encoded_url.split('&', 1)[-1])
            request.args = dict(item.split('=') for item in param.path.split('&'))
            for key in ['prefix','suffix','eps','enn','file','tag','ua','UA','emoji','gh']:
                if request.args.get(key):
                    request.args[key] = unquote(request.args[key])
            if request.args.get('file'):
                request.args['file'] = normalize_scheme(request.args['file'])
            if request.args.get('file'):
                index = request.args.get('file').find(":")
                next_index = index + 2
                if index != -1:
                    if next_index < len(request.args['file']) and request.args['file'][next_index] != "/":
                        request.args['file'] = request.args['file'][:next_index-1] + "/" + request.args['file'][next_index-1:]
    else:
        if any(substring in query_string for substring in ['&emoji=', '&file=', '&eps=', '&enn=', '&prefix=', '&suffix=', '&tag=', '&ua=', '&UA=', '&gh=']):
            param = urlparse(query_string.split('&', 1)[-1])
            request.args = dict(item.split('=') for item in param.path.split('&'))
            for key in ['prefix','suffix','eps','enn','file','tag','ua','UA','emoji','gh']:
                if request.args.get(key):
                    request.args[key] = unquote(request.args[key])
            if request.args.get('file'):
                request.args['file'] = normalize_scheme(request.args['file'])
            if request.args.get('file'):
                index = request.args.get('file').find(":")
                next_index = index + 2
                if index != -1:
                    if next_index < len(request.args['file']) and request.args['file'][next_index] != "/":
                        request.args['file'] = request.args['file'][:next_index-1] + "/" + request.args['file'][next_index-1:]
            elif 'file=' in query_string:
                index = query_string.find("file=")
                request.args['file'] = query_string.split('file=')[-1].split('&', 1)[0]
                request.args['file'] = normalize_scheme(request.args['file'])

    if index_of_colon != -1:
        next_char_index = index_of_colon + 2
        if next_char_index < len(encoded_url) and encoded_url[next_char_index] != "/":
            encoded_url = encoded_url[:next_char_index-1] + "/" + encoded_url[next_char_index-1:]
    if query_string:
        full_url = f"{encoded_url}?{query_string}"
    else:
        if any(substring in encoded_url for substring in ['&emoji=', '&file=', '&prefix=', '&suffix=', '&tag=', '&ua=', '&UA=', '&gh=']):
            full_url = f"{encoded_url.split('&')[0]}"
        else:
            full_url = f"{encoded_url}"

    param_string = ""
    if query_string:
        param_string = query_string
    else:
        if '?' in encoded_url:
            param_string = encoded_url.split('?', 1)[1]
        elif '&' in encoded_url:
            param_string = encoded_url.split('&', 1)[1]
        else:
            param_string = ""

    parsed = parse_qs(param_string, keep_blank_values=True)

    def get_param(name):
        vals = parsed.get(name)
        if not vals:
            return ''
        return safe_unquote(vals[0], max_rounds=3)

    emoji_param = get_param('emoji')
    file_param = get_param('file')
    tag_param = get_param('tag')
    ua_param = get_param('ua')
    UA_param = get_param('UA')
    pre_param = get_param('prefix')
    suf_param = get_param('suffix')
    eps_param = get_param('eps')
    enn_param = get_param('enn')
    gh_proxy_param = get_param('gh')


    file_param = normalize_scheme(file_param)

    # 支持多个值，用 | 分隔
    emoji_list = emoji_param.split('|') if emoji_param else []
    file_list = file_param.split('|') if file_param else []
    tag_list = tag_param.split('|') if tag_param else []
    ua_list = ua_param.split('|') if ua_param else []
    UA_list = UA_param.split('|') if UA_param else []
    prefix_list = pre_param.split('|') if pre_param else []
    suffix_list = suf_param.split('|') if suf_param else []
    eps_list = eps_param.split('|') if eps_param else []
    enn_list = enn_param.split('|') if enn_param else []

    # 构建要删除的字符串列表
    params_to_remove = [
        f'&prefix={quote(pre_param)}',
        f'&suffix={quote(suf_param)}',
        f'&ua={ua_param}',
        f'&UA={UA_param}',
        f'&file={file_param}',
        f'file={file_param}',
        f'&emoji={emoji_param}',
        f'&tag={tag_param}',
        f'&gh={gh_proxy_param}',
        f'&eps={quote(eps_param)}',
        f'&enn={quote(enn_param)}'
    ]
    full_url = full_url.replace(',', '%2C')
    for param in params_to_remove:
        if param in full_url:
            full_url = full_url.replace(param, '')
    if request.args.get('url'):
        full_url = full_url
    else:
        full_url = unquote(full_url)

    if '/api/v4/projects/' in full_url:
        parts = full_url.split('/api/v4/projects/')
        full_url = parts[0] + '/api/v4/projects/' + parts[1].replace('/', '%2F', 1)

    url_parts = full_url.split('|')
    existing_subs = temp_json_data.get('subscribes', [])
    first_template = existing_subs[0]

    if len(url_parts) > len(existing_subs):
        new_subs = []
        for i in range(len(url_parts)):
            if i < len(existing_subs):
                new_subs.append(existing_subs[i].copy())
            else:
                new_subs.append(first_template.copy())
        temp_json_data['subscribes'] = new_subs
        subscribes = temp_json_data['subscribes']
    else:
        subscribes = existing_subs

    for i, url_part in enumerate(url_parts):
        url_part = normalize_scheme(url_part)

        sub = subscribes[i]
        sub['url'] = url_part
        sub['prefix'] = prefix_list[i] if len(prefix_list) > i else ''
        sub['suffix'] = suffix_list[i] if len(suffix_list) > i else ''
        sub['tag'] = tag_list[i] if len(tag_list) > i else sub.get('tag','')
        sub['emoji'] = int(emoji_list[i]) if len(emoji_list) > i and emoji_list[i].isdigit() else sub.get('emoji',1)
        sub['User-Agent'] = ua_list[i] if len(ua_list) > i else 'v2rayng'
        sub['ex-node-name'] = enn_list[i] if len(enn_list) > i else ''
        sub['enabled'] = True
        sub['subgroup'] = ''

    temp_json_data['exclude_protocol'] = eps_param if eps_param else temp_json_data.get('exclude_protocol', '')
    temp_json_data['config_template'] = unquote(file_param) if file_param else temp_json_data.get('config_template', '')

    try:
        selected_template_index = '0'
        selected_gh_proxy_index = ''
        if file_param.isdigit():
            temp_json_data['config_template'] = ''
            selected_template_index = str(int(file_param) - 1)
        if gh_proxy_param:
            if gh_proxy_param.isdigit():
                selected_gh_proxy_index = str(int(gh_proxy_param) - 1)
            else:
                selected_gh_proxy_index = gh_proxy_param
        temp_json_data = json.dumps(json.dumps(temp_json_data, indent=4, ensure_ascii=False), indent=4, ensure_ascii=False)
        subprocess.check_call([sys.executable, 'main.py', '--template_index', selected_template_index, '--temp_json_data', temp_json_data, '--gh_proxy_index', selected_gh_proxy_index])
        CONFIG_FILE_NAME = json.loads(os.environ['TEMP_JSON_DATA']).get("save_config_path", "config.json")
        if CONFIG_FILE_NAME.startswith("./"):
            CONFIG_FILE_NAME = CONFIG_FILE_NAME[2:]
        # 设置配置文件的完整路径
        config_file_path = os.path.join('/tmp/', CONFIG_FILE_NAME) 
        if not os.path.exists(config_file_path):
            config_file_path = CONFIG_FILE_NAME  # 使用相对于当前工作目录的路径 
        os.environ['TEMP_JSON_DATA'] = json.dumps(json.loads(data_json['TEMP_JSON_DATA']), indent=4, ensure_ascii=False)
        # 读取配置文件内容
        with open(config_file_path, 'r', encoding='utf-8') as config_file:
            config_content = config_file.read()
            if config_content:
                flash('配置文件生成成功', 'success')
        config_data = json.loads(config_content)
        return Response(config_content, content_type='application/json; charset=utf-8')
    except subprocess.CalledProcessError as e:
        os.environ['TEMP_JSON_DATA'] = json.dumps(json.loads(data_json['TEMP_JSON_DATA']), indent=4, ensure_ascii=False)
        return Response(json.dumps({'status': 'error'}, indent=4,ensure_ascii=False), content_type='application/json; charset=utf-8', status=500)
    except Exception as e:
        return Response(json.dumps({'status': 'error'}, indent=4,ensure_ascii=False), content_type='application/json; charset=utf-8', status=500)

@app.route('/generate_config', methods=['POST'])
def generate_config():
    try:
        selected_template_index = request.form.get('template_index')
        if not selected_template_index:
            flash('请选择一个配置模板', 'error')
            return redirect(url_for('index'))
        temp_json_data = json.dumps(os.environ['TEMP_JSON_DATA'], indent=4, ensure_ascii=False)
        # 修改这里：执行main.py并传递模板序号作为命令行参数，如果未指定，则传递空字符串
        subprocess.check_call([sys.executable, 'main.py', '--template_index', selected_template_index, '--temp_json_data', temp_json_data])
        CONFIG_FILE_NAME = json.loads(os.environ['TEMP_JSON_DATA']).get("save_config_path", "config.json")
        if CONFIG_FILE_NAME.startswith("./"):
            CONFIG_FILE_NAME = CONFIG_FILE_NAME[2:]
        # 设置配置文件的完整路径
        config_file_path = os.path.join('/tmp/', CONFIG_FILE_NAME) 
        if not os.path.exists(config_file_path):
            config_file_path = CONFIG_FILE_NAME  # 使用相对于当前工作目录的路径 
        os.environ['TEMP_JSON_DATA'] = json.dumps(json.loads(data_json['TEMP_JSON_DATA']), indent=4, ensure_ascii=False)
        # 读取配置文件内容
        with open(config_file_path, 'r', encoding='utf-8') as config_file:
            config_content = config_file.read()
            if config_content:
                flash('配置文件生成成功', 'success')
        config_data = json.loads(config_content)
        return Response(config_content, content_type='application/json; charset=utf-8')
    except subprocess.CalledProcessError as e:
        os.environ['TEMP_JSON_DATA'] = json.dumps(json.loads(data_json['TEMP_JSON_DATA']), indent=4, ensure_ascii=False)
        return Response(json.dumps({'status': 'error'}, indent=4,ensure_ascii=False), content_type='application/json; charset=utf-8', status=500)
    except Exception as e:
        #flash(f'Error occurred while generating the configuration file: {str(e)}', 'error')
        return Response(json.dumps({'status': 'error'}, indent=4,ensure_ascii=False), content_type='application/json; charset=utf-8', status=500)
    #return redirect(url_for('index'))

@app.route('/clear_temp_json_data', methods=['POST'])
def clear_temp_json_data():
    try:
        os.environ['TEMP_JSON_DATA'] = json.dumps({}, indent=4, ensure_ascii=False)
        flash('TEMP_JSON_DATA 已清空', 'success')
    except Exception as e:
        flash(f'清空 TEMP_JSON_DATA 时出错：{str(e)}', 'error')
    return jsonify({'status': 'success'})

@app.route('/download_config', methods=['GET'])
def download_config():
    try:
        if config_file_path:
            # 清理临时配置文件
            cleanup_temp_config()
            # 使用send_file发送文件
            return send_file(config_file_path, as_attachment=True)
        else:
            flash('配置文件不存在或已过期', 'error')
            return redirect(url_for('index'))
    except Exception as e:
        return str(e)  # 或者适当处理异常，例如返回一个错误页面

# if __name__ == '__main__':
#    app.run(debug=True, host='0.0.0.0')