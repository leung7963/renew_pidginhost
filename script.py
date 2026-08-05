#!/usr/bin/env python3
"""
PidginHost 自动续期脚本（最终修复版）
- 通过 API 获取所有云服务器
- 逐台调用面板续期接口
- 从 Session 中可靠提取 sessionid / csrftoken（不受 domain/path 限制）
- 自动更新 GitHub Secret（仅当 cookie 有效）
- 发送 Telegram 通知
"""

import os
import sys
import re
import json
import requests
from urllib.parse import urljoin
from base64 import b64encode

# ---------- 环境变量 ----------
API_TOKEN        = os.getenv('PIDGINHOST_API_TOKEN')
PANEL_BASE       = 'https://www.pidginhost.com/'
PROXY            = os.getenv('PROXY_SERVER')
TG_TOKEN         = os.getenv('TG_BOT_TOKEN')
TG_CHAT          = os.getenv('TG_CHAT_ID')
PANEL_COOKIE_RAW = os.getenv('PANEL_COOKIE')

GITHUB_TOKEN = os.getenv('GH_PAT')
GITHUB_REPO  = os.getenv('GITHUB_REPOSITORY')
SECRET_NAME  = 'PANEL_COOKIE'

if not API_TOKEN or not PANEL_COOKIE_RAW:
    print('❌ 缺少必需的环境变量 PIDGINHOST_API_TOKEN 或 PANEL_COOKIE')
    sys.exit(1)

proxies = {'http': PROXY, 'https': PROXY} if PROXY else None

# ---------- 初始化 session ----------
api_session = requests.Session()
api_session.headers.update({'Authorization': f'Token {API_TOKEN}', 'Content-Type': 'application/json'})
if proxies:
    api_session.proxies.update(proxies)

panel_session = requests.Session()
if proxies:
    panel_session.proxies.update(proxies)

def apply_cookies(session, cookie_dict):
    session.cookies.clear()
    for name, value in cookie_dict.items():
        # 不强制 domain/path，让 requests 自行推断
        session.cookies.set(name, value, domain='.pidginhost.com', path='/')

# 解析初始 cookie
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
        if '=' in pair:
            k, v = pair.split('=', 1)
            cookie_dict[k.strip()] = v.strip()

apply_cookies(panel_session, cookie_dict)

# ---------- 工具函数 ----------
def send_tg(text):
    if TG_TOKEN and TG_CHAT:
        try:
            requests.post(f'https://api.telegram.org/bot{TG_TOKEN}/sendMessage',
                          data={'chat_id': TG_CHAT, 'text': text[:4096]}, timeout=10)
        except Exception as e:
            print(f'⚠️ TG 通知失败: {e}')

def get_csrf_token(session, url):
    resp = session.get(url)
    if resp.status_code != 200:
        return None, resp
    # 从 cookie 获取 csrftoken（不限定 domain/path，先尝试宽松获取）
    csrf = None
    for c in session.cookies:
        if c.name == 'csrftoken':
            csrf = c.value
            break
    if not csrf:
        match = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', resp.text)
        csrf = match.group(1) if match else None
    # 统一写回，保证后续请求能带正确 token
    if csrf:
        session.cookies.set('csrftoken', csrf, domain='.pidginhost.com', path='/')
    return csrf, resp

def extract_cookies_from_session(session):
    """
    遍历 cookie jar，提取 sessionid 和 csrftoken。
    不依赖 domain/path 参数，适应性最强。
    """
    sid = None
    tok = None
    for c in session.cookies:
        if c.name == 'sessionid':
            sid = c.value
            print(f'[DEBUG] sessionid: {c.value} (domain={c.domain}, path={c.path})')
        elif c.name == 'csrftoken':
            tok = c.value
            print(f'[DEBUG] csrftoken: {c.value} (domain={c.domain}, path={c.path})')
    return {'sessionid': sid, 'csrftoken': tok}

def renew_server_via_panel(server_id):
    url = urljoin(PANEL_BASE, f'panel/cloud/servers/{server_id}/')
    csrf_token, resp = get_csrf_token(panel_session, url)
    if not csrf_token:
        return False, "无法获取 CSRF token", None

    data = {'csrfmiddlewaretoken': csrf_token, 'action': 'extend_renewal'}
    headers = {'Referer': url, 'X-CSRFToken': csrf_token}
    post_resp = panel_session.post(url, data=data, headers=headers, allow_redirects=False)

    # 强制合并响应 Set-Cookie
    for cookie in post_resp.cookies:
        panel_session.cookies.set(cookie.name, cookie.value,
                                  domain=cookie.domain or '.pidginhost.com',
                                  path=cookie.path or '/')

    # 提取最新 cookie（使用遍历法）
    latest = extract_cookies_from_session(panel_session)

    success = post_resp.status_code == 302
    msg = "续期成功" if success else f"续期失败 (状态码 {post_resp.status_code})"
    return success, msg, latest

def update_github_secret(cookie_data):
    if not GITHUB_TOKEN or not GITHUB_REPO:
        return False
    try:
        from nacl import encoding, public
    except ImportError:
        print('❌ 缺少 PyNaCl 库，请 pip install pynacl')
        return False

    cookie_list = [
        {"name": "sessionid", "value": cookie_data['sessionid']},
        {"name": "csrftoken", "value": cookie_data['csrftoken']}
    ]
    new_value = json.dumps(cookie_list)

    try:
        pub_key_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/public-key"
        headers = {"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
        key_resp = requests.get(pub_key_url, headers=headers)
        key_resp.raise_for_status()
        key_data = key_resp.json()
        key_id = key_data['key_id']
        pub_key = key_data['key']

        public_key = public.PublicKey(pub_key.encode("utf-8"), encoding.Base64Encoder())
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(new_value.encode("utf-8"))
        encrypted_value = b64encode(encrypted).decode("utf-8")

        api_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/{SECRET_NAME}"
        put_resp = requests.put(api_url, headers=headers, json={"encrypted_value": encrypted_value, "key_id": key_id})
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

# ---------- 主流程 ----------
def main():
    try:
        print('🔍 验证 Panel Cookie...')
        test_url = urljoin(PANEL_BASE, 'panel/')
        test_resp = panel_session.get(test_url)
        if test_resp.status_code != 200:
            print('❌ Cookie 无效或已过期')
            send_tg('❌ PidginHost 续期失败：Cookie 无效或过期')
            sys.exit(1)
        print('✅ Panel Cookie 有效')

        servers = fetch_all_servers()
        print(f'📋 找到 {len(servers)} 台服务器')

        renewed, failed = 0, 0
        details = []
        latest_cookies = extract_cookies_from_session(panel_session)

        for s in servers:
            sid, name = s['id'], s.get('name', '未命名')
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

        print(f'🔐 最新 Cookie: sessionid={latest_cookies["sessionid"]}, csrftoken={latest_cookies["csrftoken"]}')

        # 仅当 cookie 完整才更新 Secret
        if renewed > 0 and latest_cookies['sessionid'] and latest_cookies['csrftoken']:
            update_github_secret(latest_cookies)
        elif renewed > 0:
            print('⚠️ Cookie 不完整，不更新 Secret，请手动处理')
            send_tg('⚠️ 续期成功但 cookie 提取失败，PANEL_COOKIE 未更新')

        summary = f'续期完成：成功 {renewed} 台，失败 {failed} 台'
        print(f'🎉 {summary}')
        send_tg(('✅ ' if failed == 0 else '⚠️ ') + f"PidginHost 续期\n{summary}\n" + '\n'.join(details[-5:]))
        sys.exit(0 if failed == 0 else 1)

    except Exception as e:
        error_msg = f'❌ 脚本异常: {e}'
        print(error_msg)
        send_tg(f'❌ 续期脚本崩溃\n{error_msg}')
        sys.exit(1)

if __name__ == '__main__':
    main()