import re

PROXY_METHODS = [
    ("gh-proxy", "https://gh-proxy.com", "common"),
    ("cnxiaobai", "https://github.cnxiaobai.com", "common"),
    ("ghfast", "https://ghfast.top", "common"),
    ("chenc", "https://github.chenc.dev", "common"),
    ("jsDelivr", "https://cdn.jsdelivr.net", "cdn"),
    ("jsDelivr-CF", "https://testingcf.jsdelivr.net", "cdn"),
    ("jsDelivr-Fastly", "https://fastly.jsdelivr.net", "cdn"),
    ("onmicrosoft", "https://jsd.onmicrosoft.cn", "cdn"),
]

RAW = re.compile(r'^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.*)')
CDN = re.compile(r'/gh/([^/]+)/([^/@]+)@([^/]+)/(.*)')

PREFIXES = [p + '/' for _, p, _ in PROXY_METHODS]

def _extract(line: str):
    m = RAW.match(line)
    if m:
        return m.groups()

    m = CDN.search(line)
    if m:
        return m.groups()

    for prefix in PREFIXES:
        if line.startswith(prefix):
            rest = line[len(prefix):]

            if "raw.githubusercontent.com" not in rest:
                return None

            if not rest.startswith("http"):
                rest = "https://" + rest

            m = RAW.match(rest)
            if m:
                return m.groups()
            return None

    return None

def set_gh_proxy(config, selected_index=0):
    if isinstance(selected_index, str):
        s = selected_index.strip()
        if s.isdigit():
            selected_index = int(s) - 1
        else:
            s = s.lower()
            selected_index = next(
                (i for i, (n, u, _) in enumerate(PROXY_METHODS)
                 if s in n.lower() or s in u.lower()),
                0
            )

    if not (0 <= selected_index < len(PROXY_METHODS)):
        selected_index = 0

    name, prefix, group = PROXY_METHODS[selected_index]
    prefix_slash = prefix + "/"

    def transform(line: str):
        parts = _extract(line)
        if not parts:
            return line

        owner, repo, branch, path = parts

        if group == "cdn":
            return f"{prefix}/gh/{owner}/{repo}@{branch}/{path}"
        else:
            return prefix_slash + f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"

    if isinstance(config, str):
        return transform(config)
    elif isinstance(config, list):
        t = transform
        return [t(x) for x in config]
    else:
        raise TypeError("config 应该是字符串或字符串列表")