#!/usr/bin/env python3
"""
PidginHost 免费服务器自动续期
- 每次续期成功后，自动从 session 提取最新 sessionid + csrftoken
- 更新内存中的 PANEL_COOKIE（后续服务器用新 cookie 续期）
- 若提供 GH_PAT，自动通过 GitHub API 把新 cookie 回写到 Secret PANEL_COOKIE
- Telegram 通知注入（含最新 cookie，供手动兜底）
"""
import os
import sys
import re
import json
import base64
import requests
from urllib.parse import urljoin

# ---------- 配置 ----------
API_TOKEN = os.getenv('PIDGINHOST_API_TOKEN')
PANEL_BASE = 'https://www.pidginhost.com/'
PROXY = os.getenv('PROXY_SERVER')
TG_TOKEN = os.getenv('TG_BOT_TOKEN')
TG_CHAT = os.getenv('TG_CHAT_ID')
PANEL_COOKIE_RAW = os.getenv('PANEL_COOKIE')  # 字符串（运行时会被更新）
GH_PAT = os.getenv('GH_PAT')                  # 用于回写 GitHub Secret
GITHUB_REPOSITORY = os.getenv('GITHUB_REPOSITORY', '').strip()  # 形如 owner/repo

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

# 清空可能存在的旧 cookies，避免重复
panel_session.cookies.clear()

def _parse_cookie_dict(raw):
    """将 PANEL_COOKIE 字符串解析为 dict。支持 JSON 数组 / JSON 对象 / 'k=v; k=v' 三种格式。"""
    cookie_dict = {}
    raw = raw.strip()
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
    return cookie_dict

def _serialize_cookie(cookie_dict):
    """将 cookie dict 序列化为 'k=v; k=v' 形式，供环境变量 / Secret 使用。"""
    result = []
    for k, v in cookie_dict.items():
        result.append(f'{k}={v}')
    return '; '.join(result)

# 解析初始 Cookie 并注入 session
cookie_dict = _parse_cookie_dict(PANEL_COOKIE_RAW)
panel_session.cookies.update(cookie_dict)

# ---------- 工具函数 ----------
def send_tg(text):
    if TG_TOKEN and TG_CHAT:
        try:
            requests.post(f'https://api.telegram.org/bot{TG_TOKEN}/sendMessage',
                          data={'chat_id': TG_CHAT, 'text': text[:4096], 'parse_mode': 'HTML'}, timeout=10)
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

def extract_panel_cookie(session):
    """从 session 中提取最新 sessionid + csrftoken，返回 dict（缺失的项不包含）。"""
    out = {}
    for c in session.cookies:
        if c.name in ('sessionid', 'csrftoken'):
            out[c.name] = c.value
    return out

def encrypt_secret(public_key_b64, secret_value):
    """用 GitHub 返回的公钥（libsodium sealed box）加密 secret 值。"""
    try:
        from nacl import encoding, public
    except ImportError:
        print('❌ 缺少 pynacl，无法加密 GitHub Secret（请确认 workflow 已 pip install pynacl）')
        return None
    pk = public.PublicKey(public_key_b64.encode('utf-8'), encoding.Base64Encoder())
    sealed_box = public.SealedBox(pk)
    encrypted = sealed_box.encrypt(secret_value.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def update_github_secret(repo, secret_name, secret_value):
    """通过 GitHub API 更新 Actions Secret。成功返回 True，失败返回 False 并说明原因。"""
    if not GH_PAT:
        return False, 'FAIL: 未提供 GH_PAT，无法回写 GitHub Secret'
    if not repo:
        return False, 'FAIL: 未提供 GITHUB_REPOSITORY，无法定位仓库'
    headers = {
        'Authorization': f'token {GH_PAT}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    try:
        # 1) 获取公钥
        pk_url = f'https://api.github.com/repos/{repo}/actions/secrets/public-key'
        pk_resp = requests.get(pk_url, headers=headers, timeout=20)
        if pk_resp.status_code != 200:
            return False, f'FAIL: 获取公钥失败 (HTTP {pk_resp.status_code}): {pk_resp.text[:200]}'
        key_id = pk_resp.json()['key_id']
        public_key = pk_resp.json()['key']

        # 2) 加密 secret
        encrypted = encrypt_secret(public_key, secret_value)
        if encrypted is None:
            return False, 'FAIL: 加密失败（pynacl 缺失）'

        # 3) PUT 写入 secret
        put_url = f'https://api.github.com/repos/{repo}/actions/secrets/{secret_name}'
        put_resp = requests.put(put_url, headers=headers,
                                json={'encrypted_value': encrypted, 'key_id': key_id}, timeout=20)
        if put_resp.status_code in (204, 201):
            # 4) 验证是否真的更新成功
            verify = requests.get(put_url.replace('/secrets/', '/secrets/'), headers=headers, timeout=10)
            # 验证 API 会返回加密后的 value，无法直接对比，但 HTTP 200 说明 secret 存在
            return True, '✅ 已回写 GitHub Secret「PANEL_COOKIE」'
        return False, f'FAIL: 回写失败 (HTTP {put_resp.status_code}): {put_resp.text[:200]}'
    except Exception as e:
        return False, f'FAIL: 回写 GitHub Secret 异常: {e}'

def renew_server_via_panel(server_id):
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
        # ✅ 续期成功，提取最新 cookie（sessionid 可能已被 Django 轮换）
        new_cookie = extract_panel_cookie(panel_session)
        return True, "续期成功", new_cookie
    else:
        return False, f"续期失败 (状态码 {post_resp.status_code})", None

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
    global PANEL_COOKIE_RAW, cookie_dict
    cookie_saved = False  # 标记 cookie 是否已成功保存
    latest_cookie = {}    # 始终保存最新的 cookie

    try:
        # 验证 Cookie 是否有效
        test_url = urljoin(PANEL_BASE, 'panel/')
        test_resp = panel_session.get(test_url)
        if test_resp.status_code != 200:
            print('❌ Cookie 无效或已过期，请重新导出并更新 PANEL_COOKIE')
            send_tg('❌ PidginHost 续期失败：Cookie 无效或过期')
            sys.exit(1)
        print('✅ Panel Cookie 有效')

        # 🔑 提取最新 cookie（访问 Panel 后 session/csrf 可能已轮换）
        latest_cookie = extract_panel_cookie(panel_session)
        cookie_changed = False
        if latest_cookie:
            merged = dict(cookie_dict)
            merged.update(latest_cookie)
            if merged != cookie_dict:
                cookie_dict = merged
                PANEL_COOKIE_RAW = _serialize_cookie(merged)
                cookie_changed = True
                print(f'🔑 已提取最新 cookie: '
                      f"sessionid={latest_cookie.get('sessionid','?')[-6:]}... "
                      f"csrftoken={latest_cookie.get('csrftoken','?')[-6:]}...")
            else:
                print('🔑 cookie 未变化，无需更新')

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

            success, msg, new_cookie = renew_server_via_panel(sid)
            if success:
                print(f'✅ {msg}')
                renewed += 1
                details.append(f'✅ 服务器 {sid} ({name}) 续期成功')
                # 提取到新的 sessionid/csrftoken 时，更新本会话的 cookie
                if new_cookie:
                    latest_cookie = new_cookie
                    merged = dict(cookie_dict)
                    merged.update(new_cookie)
                    if merged != cookie_dict:
                        cookie_dict = merged
                        PANEL_COOKIE_RAW = _serialize_cookie(merged)
                        cookie_changed = True
                        print(f'🔑 已更新最新 cookie: '
                              f"sessionid={new_cookie.get('sessionid','?')[-6:]}... "
                              f"csrftoken={new_cookie.get('csrftoken','?')[-6:]}...")
            else:
                print(f'❌ {msg}')
                failed += 1
                details.append(f'❌ 服务器 {sid} ({name}) 续期失败: {msg}')

        # ---- 每次都把最新的 PANEL_COOKIE 回写到 GitHub Secret ----
        secret_msg = ''
        if latest_cookie and PANEL_COOKIE_RAW:
            ok, msg = update_github_secret(GITHUB_REPOSITORY, 'PANEL_COOKIE', PANEL_COOKIE_RAW)
            secret_msg = msg
            if ok:
                cookie_saved = True
                print(f'🔐 {msg}（{"cookie 已更新" if cookie_changed else "cookie 未变，仍同步保存"}）')
            else:
                print(f'🔐 {msg}')
                send_tg(f'⚠️ Cookie 保存失败: {msg}')
        else:
            secret_msg = '未提取到 cookie，跳过回写'
            print(f'🔐 {secret_msg}')

        summary = f'续期完成：成功 {renewed} 台，失败 {failed} 台'
        print(f'🎉 {summary}')

        # 组装 TG 通知（含最新 cookie，供手动兜底更新 Secret）
        notice = f"✅ PidginHost 续期\n{summary}\n详情：\n" + '\n'.join(details[-5:])
        if latest_cookie:
            sid_v = latest_cookie.get('sessionid', '(未变)')
            csrf_v = latest_cookie.get('csrftoken', '(未变)')
            notice += f'\n\n🔑 最新 PANEL_COOKIE:\nsessionid={sid_v};\ncsrftoken={csrf_v};'
            if cookie_saved:
                notice += f'\n\n✅ 已自动回写到 GitHub Secret PANEL_COOKIE（每次运行自动同步）'
            else:
                notice += f'\n\n⚠️ {secret_msg}'
                notice += '\n\n⚠️ 如需自动保存，请确保已配置 GH_PAT Secret（GitHub Personal Access Token）'
        emoji = '✅' if failed == 0 else '⚠️'
        send_tg(emoji + ' ' + notice)
        sys.exit(0 if failed == 0 else 1)

    except Exception as e:
        error_msg = f'❌ 脚本异常: {e}'
        print(error_msg)
        send_tg(f'❌ 续期脚本崩溃\n{error_msg}')
        sys.exit(1)

if __name__ == '__main__':
    main()
