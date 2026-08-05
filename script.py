#!/usr/bin/env python3
import os
import sys
import re
import json
import subprocess
import requests
from urllib.parse import urljoin

# ---------- 配置 ----------
API_TOKEN = os.getenv('PIDGINHOST_API_TOKEN')
PANEL_BASE = 'https://www.pidginhost.com/'
PROXY = os.getenv('PROXY_SERVER')
TG_TOKEN = os.getenv('TG_BOT_TOKEN')
TG_CHAT = os.getenv('TG_CHAT_ID')
PANEL_COOKIE_RAW = os.getenv('PANEL_COOKIE')          # 从 Secrets 注入
GH_PAT = os.getenv('GH_PAT')                          # 用于更新 Secrets 的 Personal Access Token
GITHUB_REPOSITORY = os.getenv('GITHUB_REPOSITORY')    # 格式 owner/repo

if not API_TOKEN:
    print('❌ 缺少 PIDGINHOST_API_TOKEN')
    sys.exit(1)

if not PANEL_COOKIE_RAW:
    print('❌ 缺少 PANEL_COOKIE')
    sys.exit(1)

proxies = {'http': PROXY, 'https': PROXY} if PROXY else None

# API session
api_session = requests.Session()
api_session.headers.update({'Authorization': f'Token {API_TOKEN}', 'Content-Type': 'application/json'})
if proxies:
    api_session.proxies.update(proxies)

# Panel session
panel_session = requests.Session()
if proxies:
    panel_session.proxies.update(proxies)

panel_session.cookies.clear()

cookie_dict = {}
raw = PANEL_COOKIE_RAW.strip()

# 解析 Cookie
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
            requests.post(f'https://api.telegram.org/bot{TG_TOKEN}/sendMessage',
                          data={'chat_id': TG_CHAT, 'text': text[:4096]}, timeout=10)
        except Exception as e:
            print(f'⚠️ TG 通知失败: {e}')

def get_csrf_token(session, url):
    resp = session.get(url)
    if resp.status_code != 200:
        return None, resp
    csrf_cookie = None
    for c in session.cookies:
        if c.name == 'csrftoken':
            csrf_cookie = c.value
            break
    if not csrf_cookie:
        match = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', resp.text)
        csrf_cookie = match.group(1) if match else None
    return csrf_cookie, resp

def renew_server_via_panel(server_id):
    url = urljoin(PANEL_BASE, f'panel/cloud/servers/{server_id}/')
    csrf_token, resp = get_csrf_token(panel_session, url)
    if not csrf_token:
        if resp.status_code == 302:
            return False, "Cookie 过期或无效"
        return False, f"无法获取 CSRF token (状态码 {resp.status_code})"
    data = {'csrfmiddlewaretoken': csrf_token, 'action': 'extend_renewal'}
    headers = {'Referer': url, 'X-CSRFToken': csrf_token}
    post_resp = panel_session.post(url, data=data, headers=headers, allow_redirects=False)
    if post_resp.status_code == 302:
        return True, "续期成功"
    else:
        return False, f"续期失败 (状态码 {post_resp.status_code})"

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

def build_cookie_string(session):
    pairs = []
    for cookie in session.cookies:
        pairs.append(f"{cookie.name}={cookie.value}")
    return "; ".join(pairs)

def update_github_secret_via_gh(secret_name, secret_value):
    """使用 gh CLI 更新 GitHub Secret"""
    if not GH_PAT or not GITHUB_REPOSITORY:
        print("⚠️ 未提供 GH_PAT 或 GITHUB_REPOSITORY，无法自动更新 Secret")
        return False
    env = os.environ.copy()
    env['GH_TOKEN'] = GH_PAT
    cmd = [
        'gh', 'secret', 'set', secret_name,
        '--body', secret_value,
        '--repo', GITHUB_REPOSITORY
    ]
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"✅ Secret {secret_name} 更新成功")
        return True
    else:
        print(f"❌ 更新 Secret 失败: {result.stderr.strip()}")
        return False

# ---------- 主逻辑 ----------
def main():
    try:
        # 验证 Cookie 是否有效
        test_url = urljoin(PANEL_BASE, 'panel/')
        test_resp = panel_session.get(test_url)
        if test_resp.status_code != 200:
            print('❌ Cookie 无效或已过期')
            send_tg('❌ PidginHost 续期失败：Cookie 无效或过期')
            sys.exit(1)
        print('✅ Panel Cookie 有效')

        # 获取服务器列表
        print('📄 获取所有云服务器...')
        servers = fetch_all_servers()
        print(f'📋 找到 {len(servers)} 台服务器')

        renewed = 0
        failed = 0
        details = []

        for server in servers:
            sid = server['id']
            name = server.get('name', '未命名')
            print(f'🔄 尝试续期服务器 {sid} ({name})')

            success, msg = renew_server_via_panel(sid)
            if success:
                print(f'✅ {msg}')
                renewed += 1
                details.append(f'✅ 服务器 {sid} 续期成功')
            else:
                print(f'❌ {msg}')
                failed += 1
                details.append(f'❌ 服务器 {sid} 续期失败: {msg}')

        summary = f'续期完成：成功 {renewed} 台，失败 {failed} 台'
        print(f'🎉 {summary}')
        full_text = f"PidginHost 续期\n{summary}\n详情：\n" + '\n'.join(details[-5:])
        tg_status = '✅ ' if failed == 0 else '⚠️ '
        send_tg(tg_status + full_text)

        # 提取最新 Cookie 并更新 Secret
        new_cookie = build_cookie_string(panel_session)
        if update_github_secret_via_gh('PANEL_COOKIE', new_cookie):
            send_tg('🔄 已自动更新 GitHub Secret PANEL_COOKIE')
        else:
            send_tg(f'⚠️ 无法自动更新 Secret，请手动将以下内容更新到 PANEL_COOKIE:\n{new_cookie}')

        sys.exit(0 if failed == 0 else 1)

    except Exception as e:
        error_msg = f'❌ 脚本异常: {e}'
        print(error_msg)
        send_tg(f'❌ 续期脚本崩溃\n{error_msg}')
        sys.exit(1)

if __name__ == '__main__':
    main()