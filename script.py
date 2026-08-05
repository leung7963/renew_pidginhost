#!/usr/bin/env python3
"""
PidginHost 自动续期脚本（通用版 + CSRF 变化通知）
- 保留并自动更新 **所有** 面板相关 cookie
- 续期结束后通过 Telegram 发送旧/新 csrftoken
- 自动更新 GitHub Secret，支持 Telegram 通知
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
PANEL_BASE       = 'https://www.pidginhost.com'
PROXY            = os.getenv('PROXY_SERVER')
TG_TOKEN         = os.getenv('TG_BOT_TOKEN')
TG_CHAT          = os.getenv('TG_CHAT_ID')
PANEL_COOKIE_RAW = os.getenv('PANEL_COOKIE')          # 初始 cookie

GITHUB_TOKEN     = os.getenv('GH_PAT')
GITHUB_REPO      = os.getenv('GITHUB_REPOSITORY')
SECRET_NAME      = 'PANEL_COOKIE'

if not API_TOKEN or not PANEL_COOKIE_RAW:
    print('❌ 缺少必需的环境变量')
    sys.exit(1)

proxies = {'http': PROXY, 'https': PROXY} if PROXY else None

# ---------- Session 初始化 ----------
api_session = requests.Session()
api_session.headers.update({'Authorization': f'Token {API_TOKEN}', 'Content-Type': 'application/json'})
if proxies:
    api_session.proxies.update(proxies)

panel_session = requests.Session()
if proxies:
    panel_session.proxies.update(proxies)

# ---------- 解析初始 Cookie（支持多种格式） ----------
def parse_cookies(raw):
    """返回一个 name:value 字典"""
    cookies = {}
    raw = raw.strip()
    if raw.startswith('[') or raw.startswith('{'):
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                for item in data:
                    if 'name' in item and 'value' in item:
                        cookies[item['name']] = item['value']
            elif isinstance(data, dict):
                cookies = data
        except json.JSONDecodeError:
            pass
    if not cookies:
        for pair in raw.split(';'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                cookies[k.strip()] = v.strip()
    return cookies

cookie_dict = parse_cookies(PANEL_COOKIE_RAW)
print(f'[INFO] 初始 Cookie 共 {len(cookie_dict)} 个: {list(cookie_dict.keys())}')

# 应用到 session（统一 domain/path）
for name, value in cookie_dict.items():
    if value:
        panel_session.cookies.set(name, value, domain='.pidginhost.com', path='/')

# ---------- 工具函数 ----------
def send_tg(text):
    if TG_TOKEN and TG_CHAT:
        try:
            requests.post(f'https://api.telegram.org/bot{TG_TOKEN}/sendMessage',
                          data={'chat_id': TG_CHAT, 'text': text[:4096]}, timeout=10)
        except Exception as e:
            print(f'⚠️ TG 通知失败: {e}')

def get_all_cookies_from_session(session):
    """从 session 的 CookieJar 中提取所有 cookie，返回 {name: value}"""
    cookies = {}
    for cookie in session.cookies:
        cookies[cookie.name] = cookie.value
    return cookies

def get_all_cookies_from_request(resp):
    """从请求头 Cookie 中提取所有 cookie（更可靠）"""
    cookies = {}
    cookie_header = resp.request.headers.get('Cookie', '')
    if cookie_header:
        for item in cookie_header.split(';'):
            if '=' in item:
                k, v = item.split('=', 1)
                cookies[k.strip()] = v.strip()
    return cookies

def get_csrf_token(session, url):
    resp = session.get(url)
    if resp.status_code != 200:
        return None, resp
    req_cookies = get_all_cookies_from_request(resp)
    csrf = req_cookies.get('csrftoken') or req_cookies.get('csrfmiddlewaretoken')
    if not csrf:
        match = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', resp.text)
        csrf = match.group(1) if match else None
    if csrf:
        session.cookies.set('csrftoken', csrf, domain='.pidginhost.com', path='/')
    return csrf, resp

def renew_server_via_panel(server_id):
    url = urljoin(PANEL_BASE, f'panel/cloud/servers/{server_id}/')
    csrf_token, resp = get_csrf_token(panel_session, url)
    if not csrf_token:
        return False, "无法获取 CSRF token", None

    # 记录续期前的全部 cookie
    pre_all_cookies = get_all_cookies_from_request(resp) or get_all_cookies_from_session(panel_session)

    data = {'csrfmiddlewaretoken': csrf_token, 'action': 'extend_renewal'}
    headers = {'Referer': url, 'X-CSRFToken': csrf_token}
    post_resp = panel_session.post(url, data=data, headers=headers, allow_redirects=False)

    # 续期后的全部 cookie
    post_all_cookies = get_all_cookies_from_request(post_resp)
    if not post_all_cookies:
        post_all_cookies = get_all_cookies_from_session(panel_session)

    # 合并：优先使用续期后的值，无则用续期前的
    final_cookies = pre_all_cookies.copy()
    final_cookies.update(post_all_cookies)  # 新值覆盖旧值

    success = post_resp.status_code == 302
    msg = "续期成功" if success else f"续期失败 (状态码 {post_resp.status_code})"
    return success, msg, final_cookies

def update_github_secret(cookie_dict):
    """将整个 cookie 字典更新为 GitHub Secret"""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        return False
    try:
        from nacl import encoding, public
    except ImportError:
        print('❌ 缺少 PyNaCl，请 pip install pynacl')
        return False

    new_value = json.dumps(cookie_dict)

    try:
        pub_key_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/public-key"
        headers = {"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
        key_resp = requests.get(pub_key_url, headers=headers)
        key_resp.raise_for_status()
        key_data = key_resp.json()
        key_id, pub_key = key_data['key_id'], key_data['key']

        public_key = public.PublicKey(pub_key.encode("utf-8"), encoding.Base64Encoder())
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(new_value.encode("utf-8"))
        encrypted_value = b64encode(encrypted).decode("utf-8")

        api_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/{SECRET_NAME}"
        put_resp = requests.put(api_url, headers=headers, json={"encrypted_value": encrypted_value, "key_id": key_id})
        put_resp.raise_for_status()
        print(f'✅ GitHub Secret {SECRET_NAME} 已更新（含 {len(cookie_dict)} 个 cookie）')
        return True
    except Exception as e:
        print(f'❌ 更新 GitHub Secret 失败: {e}')
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

        # 初始全部 cookie
        initial_cookies = get_all_cookies_from_request(test_resp) or get_all_cookies_from_session(panel_session)
        old_csrf = initial_cookies.get('csrftoken', '无')
        print(f'[INFO] 初始 csrftoken: {old_csrf}')

        servers = fetch_all_servers()
        print(f'📋 找到 {len(servers)} 台服务器')

        renewed, failed = 0, 0
        details = []
        latest_cookies = initial_cookies.copy()

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

        new_csrf = latest_cookies.get('csrftoken', '无')
        print(f'[INFO] 最终 csrftoken: {new_csrf}')

        if renewed > 0 and latest_cookies:
            update_github_secret(latest_cookies)
        elif renewed > 0:
            print('❌ 没有提取到任何 Cookie，不更新 Secret')
            send_tg('⚠️ 续期成功但 cookie 完全丢失，请手动更新 PANEL_COOKIE')

        # 构建 Telegram 通知（包含 csrftoken 变化）
        summary = f'续期完成：成功 {renewed} 台，失败 {failed} 台'
        full_text = f"PidginHost 续期\n{summary}\n详情：\n" + '\n'.join(details[-5:])
        csrf_info = f"\n🔑 CSRF token 变化:\n旧值: {old_csrf}\n新值: {new_csrf}"
        send_tg(('✅ ' if failed == 0 else '⚠️ ') + full_text + csrf_info)

        print(f'🎉 {summary}')
        sys.exit(0 if failed == 0 else 1)

    except Exception as e:
        error_msg = f'❌ 脚本异常: {e}'
        print(error_msg)
        send_tg(f'❌ 续期脚本崩溃\n{error_msg}')
        sys.exit(1)

if __name__ == '__main__':
    main()