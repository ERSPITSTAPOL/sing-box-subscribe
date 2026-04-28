import os
from http.server import BaseHTTPRequestHandler

def _get_template_list() -> list[str]:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_dir = os.path.join(base_dir, "config_template")
    if not os.path.exists(template_dir):
        return []
    names: list[str] = []
    with os.scandir(template_dir) as it:
        for entry in it:
            if not entry.is_file():
                continue
            if not entry.name.endswith(".json"):
                continue
            names.append(os.path.splitext(entry.name)[0])
    names.sort()
    return names

def _get_html() -> str:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_path = os.path.join(base_dir, "templates", "index.html")
    with open(template_path, encoding="utf-8") as f:
        return f.read()

_JINJA_BLOCK_START = "{% for option in template_options %}"
_JINJA_BLOCK_END   = "{% endfor %}"

def _render(template_list: list[str]) -> bytes:
    html = _get_html()

    spans = "\n".join(
        f'        <span class="template-opt" data-index="{i+1}" data-label="{i+1}、{name}"></span>'
        for i, name in enumerate(template_list)
    )

    start = html.index(_JINJA_BLOCK_START)
    end = html.index(_JINJA_BLOCK_END) + len(_JINJA_BLOCK_END)
    html = html[:start] + spans + html[end:]

    return html.encode("utf-8")

_CACHED_HTML: bytes | None = None

def _get_cached_html() -> bytes:
    global _CACHED_HTML
    if _CACHED_HTML is None:
        _CACHED_HTML = _render(_get_template_list())
    return _CACHED_HTML

class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        body = _get_cached_html()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=60, s-maxage=300")
        self.end_headers()
        self.wfile.write(body)