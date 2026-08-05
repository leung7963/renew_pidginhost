#!/usr/bin/env python3
import os
import sys
import re
import json
import requests
from urllib.parse import urljoin

# ---------- 配置 ----------
API_TOKEN = os.getenv('PIDGINHOST_API_TOKEN')
PANEL_BASE = 'https://www.pidginhost.com/'
PROXY = os.getenv('PROXY_SERVER')
TG_TOKEN = os.getenv('TG_BOT_TOKEN')
TG_CHAT = os.getenv('TG_CHAT_ID')
PANEL_COOKIE_RAW = os.getenv('PANEL_COOKIE')          # 初始 cookie

# GitHub 相关，仅当需要自动更新 secret 时设置
GITHUB_TOKEN = os.getenv('GH_PAT')                    # 具有 repo scope 的 PAT
GITHUB_REPO = os.getenv('GITHUB_REPOSITORY')          # 例如 "user/repo"
SECRET_NAME = 'PANEL_COOKIE'                          # 要更新的 secret 名

if not API_TOKEN:
    print('❌ 缺少 PIDGINHOST_API_TOKEN')
    sys.exit(1)
if not PANEL_COOKIE_RAW:
    print('❌ 缺少 PANEL_COOKIE')
    sys.exit(1)

proxies = {'http': PROXY, 'https': PROXY} if PROXY else None

# ---------- API session ----------
api_session = requests.Session()
api_session.headers.update({
    'Authorization': f'Token {API_TOKEN}',
    'Content-Type': 'application/json'
})
if proxies:
    api_session.proxies.update(proxies)

# ---------- Panel session ----------
panel_session = requests.Session()
if proxies:
    panel_session.proxies.update(proxies)

# 解析初始 PANEL_COOKIE
cookie_dict = {}
raw = PANEL_COOKIE_RAW.strip()
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
            cookie_dict[k] = v
panel_session.cookies.update(cookie_dict)

# ---------- 工具函数 ----------
def send_tg(text):
    if TG_TOKEN and TG_CHAT:
        try:
            requests.post(
                f'https://api.telegram.org/bot{TG_TOKEN}/sendMessage',
                data={'chat_id': TG_CHAT, 'text': text[:4096]},
                timeout=10
            )
        except Exception as e:
            print(f'⚠️ TG 通知失败: {e}')

def get_csrf_token(session, url):
    resp = session.get(url)
    if resp.status_code != 200:
        return None, resp
    # 从 cookies 获取 csrftoken
    csrf_cookie = session.cookies.get('csrftoken')
    if not csrf_cookie:
        # 从 HTML 中提取备用
        match = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', resp.text)
        csrf_cookie = match.group(1) if match else None
    return csrf_cookie, resp

def renew_server_via_panel(server_id):
    """续期单台服务器，返回 (成功标志, 消息, 更新后的cookies字典)"""
    url = urljoin(PANEL_BASE, f'panel/cloud/servers/{server_id}/')
    csrf_token, resp = get_csrf_token(panel_session, url)
    if not csrf_token:
        if resp.status_code == 302:
            return False, "Cookie 过期或无效", None
        return False, f"无法获取 CSRF token (状态码 {resp.status_code})", None

    data = {'csrfmiddlewaretoken': csrf_token, 'action': 'extend_renewal'}
    headers = {'Referer': url, 'X-CSRFToken': csrf_token}
    post_resp = panel_session.post(url, data=data, headers=headers, allow_redirects=False)

    if post_resp.status_code == 302:
        # 成功后续期，立即抓取最新 cookies
        latest_cookies = get_current_cookies()
        return True, "续期成功", latest_cookies
    else:
        # 失败也抓取一次（可能 cookie 被更新了，但不算续期成功）
        latest_cookies = get_current_cookies()
        return False, f"续期失败 (状态码 {post_resp.status_code})", latest_cookies

def get_current_cookies():
    """返回当前 panel_session 中 sessionid 和 csrftoken 组成的字典"""
    return {
        'sessionid': panel_session.cookies.get('sessionid', ''),
        'csrftoken': panel_session.cookies.get('csrftoken', '')
    }

def update_github_secret(cookie_data):
    """使用 GitHub API 更新 PANEL_COOKIE secret"""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        print('⚠️ 未配置 GitHub 信息，跳过 secret 更新')
        return False

    # 构造新 cookie 字符串（复用原格式：JSON 数组）
    cookie_list = [
        {"name": "sessionid", "value": cookie_data['sessionid']},
        {"name": "csrftoken", "value": cookie_data['csrftoken']}
    ]
    new_value = json.dumps(cookie_list)

    # 调用 GitHub API 更新 secret
    api_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/{SECRET_NAME}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    payload = {
        "encrypted_value": None,
        "key_id": None
    }
    # 先获取公钥
    pub_key_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/public-key"
    try:
        key_resp = requests.get(pub_key_url, headers=headers)
        key_resp.raise_for_status()
        key_data = key_resp.json()
        key_id = key_data['key_id']
        pub_key = key_data['key']

        # 加密 secret
        from base64 import b64encode
        from nacl import encoding, public  # 需要安装 PyNaCl: pip install pynacl
        public_key = public.PublicKey(pub_key.encode("utf-8"), encoding.Base64Encoder())
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(new_value.encode("utf-8"))
        encrypted_value = b64encode(encrypted).decode("utf-8")

        payload = {
            "encrypted_value": encrypted_value,
            "key_id": key_id
        }

        put_resp = requests.put(api_url, headers=headers, json=payload)
        put_resp.raise_for_status()
        print(f'✅ GitHub secret {SECRET_NAME} 已更新')
        return True
    except Exception as e:
        print(f'❌ 更新 GitHub secret 失败: {e}')
        return False

def fetch_all_servers():
    url = urljoin('https://www.pidginhost.com/api/', 'cloud/servers/')
    items = []
    while url:
        resp = api_session.get(url)
        resp.raise_for_status()
        data = resp.json()
        items.extend(data.get('results', []))
        url = data.get('next')
    return items

# ---------- 主逻辑 ----------
def main():
    try:
        # 验证 Cookie 是否有效
        test_url = urljoin(PANEL_BASE, 'panel/')
        test_resp = panel_session.get(test_url)
        if test_resp.status_code != 200:
            print('❌ Cookie 无效或已过期，请重新导出并更新 PANEL_COOKIE')
            send_tg('❌ PidginHost 续期失败：Cookie 无效或过期')
            sys.exit(1)
        print('✅ Panel Cookie 有效')

        print('📄 获取所有云服务器...')
        servers = fetch_all_servers()
        print(f'📋 找到 {len(servers)} 台服务器')

        renewed = 0
        failed = 0
        details = []
        latest_cookies = get_current_cookies()  # 初始状态

        for server in servers:
            sid = server['id']
            name = server.get('name', '未命名')
            print(f'🔄 尝试续期服务器 {sid} ({name})')

            success, msg, new_cookies = renew_server_via_panel(sid)
            if new_cookies:
                latest_cookies = new_cookies  # 保持最新

            if success:
                print(f'✅ {msg}')
                renewed += 1
                details.append(f'✅ 服务器 {sid} 续期成功')
            else:
                print(f'❌ {msg}')
                failed += 1
                details.append(f'❌ 服务器 {sid} 续期失败: {msg}')

        # 输出最新 cookie 信息（用于调试或手动更新）
        print(f'🔐 最新 Cookie: sessionid={latest_cookies["sessionid"]}, csrftoken={latest_cookies["csrftoken"]}')
        # 尝试自动更新 GitHub secret
        if renewed > 0:  # 只有成功续期后才更新，避免无效 cookie 覆盖有效 secret
            update_github_secret(latest_cookies)

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