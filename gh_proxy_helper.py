import re

def set_gh_proxy(config, selected_index=0):
    # 分组定义
    proxy_groups = {
        "common": [
            ("gh-proxy",   "https://gh-proxy.com/"),
            ("cnxiaobai",  "https://github.cnxiaobai.com/"),
            ("ghfast",     "https://ghfast.top/"),
            ("chenc",      "https://github.chenc.dev/"),
        ],
        "cdn": [
            ("jsDelivr",         "https://cdn.jsdelivr.net"),
            ("jsDelivr-CF",      "https://testingcf.jsdelivr.net"),
            ("jsDelivr-Fastly",  "https://fastly.jsdelivr.net"),
            ("onmicrosoft",      "https://jsd.onmicrosoft.cn"),
        ]
    }

    # 展开成线性列表，保持索引顺序
    proxy_methods = [item for group in proxy_groups.values() for item in group]

    # 选择索引或关键字
    if isinstance(selected_index, str):
        selected_index = selected_index.strip()
        if selected_index.isdigit():
            selected_index = int(selected_index) - 1
        else:
            keyword = selected_index.lower()
            found_idx = 0
            for i, (name, url) in enumerate(proxy_methods):
                if keyword in name.lower() or keyword in url.lower():
                    found_idx = i
                    break
            selected_index = found_idx

    if not isinstance(selected_index, int) or selected_index < 0 or selected_index >= len(proxy_methods):
        selected_index = 0

    target_name, target_prefix = proxy_methods[selected_index]

    # 判断属于哪个字典
    def get_group(name, prefix):
        for group_name, group_items in proxy_groups.items():
            for n, p in group_items:
                if name == n and prefix == p:
                    return group_name
        return "common"

    target_group = get_group(target_name, target_prefix)

    def restore_raw_url(line):
        if line.startswith("https://raw.githubusercontent.com/"):
            return line

        jsdelivr_pattern = (
            r'https://(?:cdn|testingcf|fastly)\.jsdelivr\.net'
            r'/gh/([^/]+)/([^@]+)@([^/]+)/(.*)'
        )
        match = re.match(jsdelivr_pattern, line)
        if match:
            user, repo, branch, path = match.groups()
            return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"

        for _, prefix in proxy_methods:
            check_prefix = prefix if prefix.endswith('/') else prefix + '/'
            if line.startswith(check_prefix):
                rest = line[len(check_prefix):]
                if rest.startswith("https://raw.githubusercontent.com/"):
                    return rest
                if rest.startswith("raw.githubusercontent.com/"):
                    return "https://" + rest
        return line

    def apply_proxy(line):
        original = restore_raw_url(line)

        if "raw.githubusercontent.com" not in original:
            return line

        if target_group == "cdn":
            match = re.match(r'https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.*)', original)
            if match:
                user, repo, branch, path = match.groups()
                clean_prefix = target_prefix.rstrip('/')
                return f"{clean_prefix}/gh/{user}/{repo}@{branch}/{path}"
            return original
        else:  # common
            return target_prefix + original

    if isinstance(config, str):
        return apply_proxy(config)
    elif isinstance(config, list):
        return [apply_proxy(line) for line in config]
    else:
        raise TypeError("config 应该是字符串或字符串列表")