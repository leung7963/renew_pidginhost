#!/usr/bin/env python3
"""
PidginHost 自动续期脚本（最终可靠版）
- 通过请求头反向提取 cookie，无需依赖 CookieJar
- 自动更新 GitHub Secret（需配置 GH_PAT 和 GITHUB_REPOSITORY）
- 支持 Telegram 通知
"""

import os
import sys
import re
import json
import requests
from urllib.parse import urljoin
from base64 import b64encode

# ---------- 环境变量 ----------
API_TOKEN        = os.getenv('PIDGINHOST_API_TOKEN')      # PidginHost API Token
PANEL_BASE       = 'https://www.pidginhost.com/panel'
PROXY            = os.getenv('PROXY_SERVER')
TG_TOKEN         = os.getenv('TG_BOT_TOKEN')
TG_CHAT          = os.getenv('TG_CHAT_ID')
PANEL_COOKIE_RAW = os.getenv('PANEL_COOKIE')              # 初始 cookie

# GitHub Secret 更新相关（可选）
GITHUB_TOKEN = os.getenv('GH_PAT')
GITHUB_REPO  = os.getenv('GITHUB_REPOSITORY')             # 格式: 用户名/仓库名
SECRET_NAME  = 'PANEL_COOKIE'

if not API_TOKEN:
    print('❌ 缺少 PIDGINHOST_API_TOKEN')
    sys.exit(1)
if not PANEL_COOKIE_RAW:
    print('❌ 缺少 PANEL_COOKIE')
    sys.exit(1)

proxies = {'http': PROXY, 'https': PROXY} if PROXY else None

# ---------- 创建两个 Session ----------
api_session = requests.Session()
api_session.headers.update({
    'Authorization': f'Token {API_TOKEN}',
    'Content-Type': 'application/json'
})
if proxies:
    api_session.proxies.update(proxies)

panel_session = requests.Session()
if proxies:
    panel_session.proxies.update(proxies)

# ---------- 解析并应用初始 Cookie ----------
def apply_cookies(session, cookie_dict):
    """将 cookie 字典设置到 session，使用统一的 domain 和 path"""
    session.cookies.clear()
    for name, value in cookie_dict.items():
        if value:
            session.cookies.set(name, value, domain='.pidginhost.com', path='/')

cookie_dict = {}
raw = PANEL_COOKIE_RAW.strip()

# 支持 JSON 数组、JSON 对象、标准 key=value 字符串
if raw.startswith('[') or raw.startswith('{'):
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            for item in data:
                if 'name' in item and 'value' in item:
                    cookie_dict[item['name']] = item['value']
        elif isinstance(data, dict):
            cookie_dict = data
    except json.JSONDecodeError:
        pass

if not cookie_dict:
    for pair in raw.split(';'):
        pair = pair.strip()
        if '=' in pair:
            k, v = pair.split('=', 1)
            cookie_dict[k.strip()] = v.strip()

# 记录初始解析结果
print(f'[INFO] 初始 Cookie 键: {list(cookie_dict.keys())}')
apply_cookies(panel_session, cookie_dict)

# ---------- 核心工具函数 ----------

def send_tg(text):
    """发送 Telegram 通知"""
    if TG_TOKEN and TG_CHAT:
        try:
            requests.post(
                f'https://api.telegram.org/bot{TG_TOKEN}/sendMessage',
                data={'chat_id': TG_CHAT, 'text': text[:4096]},
                timeout=10
            )
        except Exception as e:
            print(f'⚠️ Telegram 通知失败: {e}')


def extract_cookies_from_request(resp):
    """
    从响应对象对应的请求头中提取 sessionid 和 csrftoken
    这是最可靠的方式，因为请求头包含了实际发送的 Cookie
    """
    sid = tok = None
    # 获取发送请求时的 Cookie 头
    cookie_header = resp.request.headers.get('Cookie', '')
    if cookie_header:
        for item in cookie_header.split(';'):
            item = item.strip()
            if '=' not in item:
                continue
            k, v = item.split('=', 1)
            k = k.strip()
            v = v.strip()
            if k == 'sessionid':
                sid = v
            elif k == 'csrftoken':
                tok = v
    # 如果 cookie 头里没有，尝试从 resp.cookies 补充（极少数情况）
    if not sid:
        sid = resp.cookies.get('sessionid')
    if not tok:
        tok = resp.cookies.get('csrftoken')
    return {'sessionid': sid, 'csrftoken': tok}


def get_csrf_token(session, url):
    """获取 CSRF Token（用于表单提交）"""
    resp = session.get(url)
    if resp.status_code != 200:
        return None, resp

    # 优先从请求头中的 Cookie 提取 csrftoken
    cookies = extract_cookies_from_request(resp)
    csrf = cookies.get('csrftoken')

    # 备用方案：从 HTML 页面中提取
    if not csrf:
        match = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', resp.text)
        csrf = match.group(1) if match else None

    # 将 csrftoken 写回 session，确保后续请求使用正确值
    if csrf:
        session.cookies.set('csrftoken', csrf, domain='.pidginhost.com', path='/')
    return csrf, resp


def renew_server_via_panel(server_id):
    """
    续期单台服务器
    返回: (成功标志, 消息, 最新的 cookies 字典)
    """
    url = urljoin(PANEL_BASE, f'panel/cloud/servers/{server_id}/')
    csrf_token, resp = get_csrf_token(panel_session, url)
    if not csrf_token:
        if resp.status_code == 302:
            return False, "Cookie 已过期或无效", None
        return False, f"无法获取 CSRF token (状态码 {resp.status_code})", None

    # 记录续期前的 cookie（用于回退）
    pre_cookies = extract_cookies_from_request(resp)

    # 发送续期 POST 请求
    data = {
        'csrfmiddlewaretoken': csrf_token,
        'action': 'extend_renewal'
    }
    headers = {
        'Referer': url,
        'X-CSRFToken': csrf_token
    }
    post_resp = panel_session.post(url, data=data, headers=headers, allow_redirects=False)

    # 从 POST 请求头中提取续期后实际发送的 cookie
    post_cookies = extract_cookies_from_request(post_resp)

    # 合并：若某项在续期后为 None，则使用续期前的值
    final_cookies = {
        'sessionid': post_cookies['sessionid'] or pre_cookies['sessionid'],
        'csrftoken': post_cookies['csrftoken'] or pre_cookies['csrftoken']
    }

    success = post_resp.status_code == 302
    msg = "续期成功" if success else f"续期失败 (状态码 {post_resp.status_code})"
    return success, msg, final_cookies


def update_github_secret(cookie_data):
    """将 cookies 更新到 GitHub Actions Secret"""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        print('⚠️ 未配置 GitHub Token 或仓库，跳过 Secret 更新')
        return False

    try:
        from nacl import encoding, public
    except ImportError:
        print('❌ 需要安装 PyNaCl 库，请执行: pip install pynacl')
        return False

    # 构造 JSON 数组格式
    cookie_list = [
        {"name": "sessionid", "value": cookie_data['sessionid']},
        {"name": "csrftoken", "value": cookie_data['csrftoken']}
    ]
    new_value = json.dumps(cookie_list)

    try:
        # 获取仓库公钥
        pub_key_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/public-key"
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        key_resp = requests.get(pub_key_url, headers=headers)
        key_resp.raise_for_status()
        key_data = key_resp.json()
        key_id = key_data['key_id']
        pub_key = key_data['key']

        # 加密
        public_key = public.PublicKey(pub_key.encode("utf-8"), encoding.Base64Encoder())
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(new_value.encode("utf-8"))
        encrypted_value = b64encode(encrypted).decode("utf-8")

        # 更新 Secret
        api_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/{SECRET_NAME}"
        payload = {"encrypted_value": encrypted_value, "key_id": key_id}
        put_resp = requests.put(api_url, headers=headers, json=payload)
        put_resp.raise_for_status()
        print(f'✅ GitHub Secret {SECRET_NAME} 已更新')
        return True
    except Exception as e:
        print(f'❌ 更新 GitHub Secret 失败: {e}')
        return False


def fetch_all_servers():
    """通过 API 获取所有云服务器"""
    url = urljoin('https://www.pidginhost.com/api/', 'cloud/servers/')
    items = []
    while url:
        resp = api_session.get(url)
        resp.raise_for_status()
        data = resp.json()
        items.extend(data.get('results', []))
        url = data.get('next')
    return items


# ---------- 主流程 ----------
def main():
    try:
        # 1. 验证初始 Cookie 是否有效
        print('🔍 验证 Panel Cookie...')
        test_url = urljoin(PANEL_BASE, 'panel/')
        test_resp = panel_session.get(test_url)
        if test_resp.status_code != 200:
            print('❌ Cookie 无效或已过期')
            send_tg('❌ PidginHost 续期失败：Cookie 无效或过期')
            sys.exit(1)
        print('✅ Panel Cookie 有效')

        # 从验证请求中提取初始 cookie，作为最后的回退
        initial_cookies = extract_cookies_from_request(test_resp)
        print(f'[INFO] 初始实际发送的 sessionid={initial_cookies["sessionid"]}, csrftoken={initial_cookies["csrftoken"]}')

        # 2. 获取服务器列表
        print('📄 获取所有云服务器...')
        servers = fetch_all_servers()
        print(f'📋 找到 {len(servers)} 台服务器')

        renewed = 0
        failed = 0
        details = []
        latest_cookies = initial_cookies  # 初始值

        # 3. 逐台续期
        for server in servers:
            sid = server['id']
            name = server.get('name', '未命名')
            print(f'🔄 续期 {sid} ({name})')
            success, msg, new_cookies = renew_server_via_panel(sid)

            if new_cookies:
                latest_cookies = new_cookies

            if success:
                print(f'✅ {msg}')
                renewed += 1
                details.append(f'✅ {sid} ({name})')
            else:
                print(f'❌ {msg}')
                failed += 1
                details.append(f'❌ {sid} ({name}): {msg}')

        # 4. 输出最终 Cookie（用于调试）
        print(f'🔐 最终 Cookie: sessionid={latest_cookies["sessionid"]}, csrftoken={latest_cookies["csrftoken"]}')

        # 5. 更新 GitHub Secret（仅当续期至少成功一次且 cookie 完整）
        if renewed > 0 and latest_cookies['sessionid'] and latest_cookies['csrftoken']:
            update_github_secret(latest_cookies)
        elif renewed > 0:
            print('❌ Cookie 不完整，不更新 Secret，请手动处理')
            send_tg('⚠️ 续期成功但 cookie 提取失败，PANEL_COOKIE 未更新，请手动检查')

        # 6. 发送总结通知
        summary = f'续期完成：成功 {renewed} 台，失败 {failed} 台'
        print(f'🎉 {summary}')
        full_text = f"PidginHost 续期\n{summary}\n详情：\n" + '\n'.join(details[-5:])
        send_tg(('✅ ' if failed == 0 else '⚠️ ') + full_text)

        sys.exit(0 if failed == 0 else 1)

    except Exception as e:
        error_msg = f'❌ 脚本异常: {e}'
        print(error_msg)
        send_tg(f'❌ 续期脚本崩溃\n{error_msg}')
        sys.exit(1)


if __name__ == '__main__':
    main()