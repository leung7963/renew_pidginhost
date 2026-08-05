#!/usr/bin/env python3
"""
PidginHost 自动续期脚本
- 通过 API 获取所有云服务器
- 逐个调用面板续期接口
- 自动从响应中抓取最新的 sessionid 和 csrftoken
- 可选地将新 cookie 更新到 GitHub Secret 并发送 Telegram 通知
"""

import os
import sys
import re
import json
import requests
from urllib.parse import urljoin
from base64 import b64encode

# ---------- 环境变量配置 ----------
API_TOKEN        = os.getenv('PIDGINHOST_API_TOKEN')   # PidginHost API Token
PANEL_BASE       = 'https://www.pidginhost.com/'
PROXY            = os.getenv('PROXY_SERVER')
TG_TOKEN         = os.getenv('TG_BOT_TOKEN')
TG_CHAT          = os.getenv('TG_CHAT_ID')
PANEL_COOKIE_RAW = os.getenv('PANEL_COOKIE')           # 初始 cookie

# GitHub 相关（可选，不配置则只打印日志不更新）
GITHUB_TOKEN = os.getenv('GH_PAT')                     # GitHub Personal Access Token (repo scope)
GITHUB_REPO  = os.getenv('GITHUB_REPOSITORY')          # 格式: owner/repo
SECRET_NAME  = 'PANEL_COOKIE'                          # 要更新的 secret 名称

if not API_TOKEN:
    print('❌ 缺少 PIDGINHOST_API_TOKEN')
    sys.exit(1)
if not PANEL_COOKIE_RAW:
    print('❌ 缺少 PANEL_COOKIE')
    sys.exit(1)

# ---------- 代理配置 ----------
proxies = {'http': PROXY, 'https': PROXY} if PROXY else None

# ---------- 创建两个 session ----------
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

# ---------- 安全设置 Cookie，防止重复 ----------
def apply_cookies(session, cookie_dict):
    """将 cookie 字典应用到 session，统一 domain 和 path"""
    session.cookies.clear()
    domain = '.pidginhost.com'
    path = '/'
    for name, value in cookie_dict.items():
        session.cookies.set(name, value, domain=domain, path=path)

# 解析初始 PANEL_COOKIE（支持 JSON 数组、JSON 对象、标准 cookie 字符串）
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
if not cookie_dict:  # 传统格式
    for pair in raw.split(';'):
        pair = pair.strip()
        if '=' in pair:
            k, v = pair.split('=', 1)
            cookie_dict[k] = v

apply_cookies(panel_session, cookie_dict)

# ---------- 工具函数 ----------
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
            print(f'⚠️ TG 通知失败: {e}')

def get_csrf_token(session, url):
    """获取 CSRF Token，同时更新 session 中的 csrftoken"""
    resp = session.get(url)
    if resp.status_code != 200:
        return None, resp
    # 优先从 cookies 中读取
    csrf = session.cookies.get('csrftoken', domain='.pidginhost.com', path='/')
    if not csrf:
        # 备用：从 HTML 中提取
        match = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', resp.text)
        csrf = match.group(1) if match else None
    # 将提取到的 csrftoken 强制写回 session（防止旧值残留）
    if csrf:
        session.cookies.set('csrftoken', csrf, domain='.pidginhost.com', path='/')
    return csrf, resp

def renew_server_via_panel(server_id):
    """
    续期单台服务器
    返回: (成功标志, 消息, 最新 cookie 字典)
    """
    url = urljoin(PANEL_BASE, f'panel/cloud/servers/{server_id}/')
    csrf_token, resp = get_csrf_token(panel_session, url)
    if not csrf_token:
        if resp.status_code == 302:
            return False, "Cookie 过期或无效", None
        return False, f"无法获取 CSRF token (状态码 {resp.status_code})", None

    data = {
        'csrfmiddlewaretoken': csrf_token,
        'action': 'extend_renewal'
    }
    headers = {
        'Referer': url,
        'X-CSRFToken': csrf_token
    }

    # 发送续期 POST
    post_resp = panel_session.post(url, data=data, headers=headers, allow_redirects=False)

    # 🔑 关键步骤：将响应 Set-Cookie 强制合并到 session
    for cookie in post_resp.cookies:
        panel_session.cookies.set(
            cookie.name, cookie.value,
            domain=cookie.domain or '.pidginhost.com',
            path=cookie.path or '/'
        )

    # 提取最新的 cookie 值
    latest = {
        'sessionid': panel_session.cookies.get('sessionid', domain='.pidginhost.com', path='/'),
        'csrftoken': panel_session.cookies.get('csrftoken', domain='.pidginhost.com', path='/')
    }

    # 如果提取失败，打印调试信息
    if not latest['sessionid'] or not latest['csrftoken']:
        print('⚠️ 警告：未能提取到完整 cookie，当前 session 中的所有 cookies:')
        for c in panel_session.cookies:
            print(f'  {c.name}={c.value} (domain={c.domain}, path={c.path})')

    success = post_resp.status_code == 302
    msg = "续期成功" if success else f"续期失败 (状态码 {post_resp.status_code})"
    return success, msg, latest

def get_current_cookies():
    """获取当前 session 中的 sessionid 和 csrftoken"""
    return {
        'sessionid': panel_session.cookies.get('sessionid', domain='.pidginhost.com', path='/'),
        'csrftoken': panel_session.cookies.get('csrftoken', domain='.pidginhost.com', path='/')
    }

def update_github_secret(cookie_data):
    """将 cookie_data (dict) 更新为 GitHub Actions Secret"""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        print('⚠️ 未配置 GitHub 信息，跳过 secret 更新')
        return False

    # 尝试导入 pynacl（需要安装 pynacl）
    try:
        from nacl import encoding, public
    except ImportError:
        print('❌ 缺少 PyNaCl 库，无法加密 secret。请运行: pip install pynacl')
        return False

    # 构造 JSON 数组格式的 cookie
    cookie_list = [
        {"name": "sessionid", "value": cookie_data['sessionid']},
        {"name": "csrftoken", "value": cookie_data['csrftoken']}
    ]
    new_value = json.dumps(cookie_list)

    try:
        # 1. 获取仓库公钥
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

        # 2. 加密 secret
        public_key = public.PublicKey(pub_key.encode("utf-8"), encoding.Base64Encoder())
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(new_value.encode("utf-8"))
        encrypted_value = b64encode(encrypted).decode("utf-8")

        # 3. 更新 secret
        api_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/{SECRET_NAME}"
        payload = {"encrypted_value": encrypted_value, "key_id": key_id}
        put_resp = requests.put(api_url, headers=headers, json=payload)
        put_resp.raise_for_status()
        print(f'✅ GitHub secret {SECRET_NAME} 已更新')
        return True
    except Exception as e:
        print(f'❌ 更新 GitHub secret 失败: {e}')
        if hasattr(e, 'response') and e.response is not None:
            print(f'  状态码: {e.response.status_code}')
            print(f'  响应体: {e.response.text}')
        return False

def fetch_all_servers():
    """通过 PidginHost API 获取所有云服务器列表"""
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
        # 1. 验证初始 Cookie 是否有效
        print('🔍 验证 Panel Cookie...')
        test_url = urljoin(PANEL_BASE, 'panel/')
        test_resp = panel_session.get(test_url)
        if test_resp.status_code != 200:
            print('❌ Cookie 无效或已过期，请重新导出并更新 PANEL_COOKIE')
            send_tg('❌ PidginHost 续期失败：Cookie 无效或过期')
            sys.exit(1)
        print('✅ Panel Cookie 有效')

        # 2. 获取服务器列表
        print('📄 获取所有云服务器...')
        servers = fetch_all_servers()
        print(f'📋 找到 {len(servers)} 台服务器')

        renewed = 0
        failed = 0
        details = []
        latest_cookies = get_current_cookies()

        # 3. 逐台续期
        for server in servers:
            sid = server['id']
            name = server.get('name', '未命名')
            print(f'🔄 尝试续期服务器 {sid} ({name})')

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

        # 4. 输出最终 cookie 信息
        print(f'🔐 最新 Cookie: sessionid={latest_cookies["sessionid"]}, csrftoken={latest_cookies["csrftoken"]}')

        # 5. 更新 GitHub Secret（仅当 cookie 完整且续期成功至少一次）
        if renewed > 0 and latest_cookies['sessionid'] and latest_cookies['csrftoken']:
            update_github_secret(latest_cookies)
        elif renewed > 0:
            print('❌ Cookie 不完整，不更新 Secret，请手动处理')
            send_tg('⚠️ 续期成功但 cookie 提取失败，PANEL_COOKIE 未更新，请手动检查')

        # 6. 总结通知
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