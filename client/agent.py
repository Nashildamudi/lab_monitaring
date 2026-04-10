import ctypes
import json
import os
import platform
import socket
import sys
import time
from typing import Any, Dict, List, Optional

import psutil
import requests
try:
    import win32gui
    import win32process
except ImportError:
    win32gui = None
    win32process = None


DEFAULT_CONFIG = {
    "server_url": "http://127.0.0.1:8001",
    "name": "",
    "token": "",
    "banned_process_names": ["chrome.exe", "msedge.exe", "firefox.exe"],
    "heartbeat_interval_seconds": 5,
}


BASE_DIR = os.path.dirname(__file__)
TOKEN_PATH = os.path.join(BASE_DIR, "token.txt")
SERVER_URL_PATH = os.path.join(BASE_DIR, "server_url.txt")
NAME_PATH = os.path.join(BASE_DIR, "name.txt")
ENROLLMENT_KEY_PATH = os.path.join(BASE_DIR, "enrollment_key.txt")
BLOCKED_URLS_PATH = os.path.join(BASE_DIR, "blocked_urls.txt")


def load_config(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return dict(DEFAULT_CONFIG)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = dict(DEFAULT_CONFIG)
    out.update(data)
    return out


def save_config(path: str, cfg: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return (f.read() or "").strip()
    except Exception:
        return ""


def write_text(path: str, value: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write((value or "").strip() + "\n")


def hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return platform.node() or "unknown"


def list_process_names() -> List[str]:
    names: List[str] = []
    for p in psutil.process_iter(attrs=["name"]):
        try:
            n = p.info.get("name")
            if n:
                names.append(str(n))
        except Exception:
            continue
    return names


def list_removable_mounts() -> List[str]:
    if os.name != "nt":
        return []
    mounts: List[str] = []
    try:
        for part in psutil.disk_partitions(all=True):
            opts = (part.opts or "").lower()
            if "removable" in opts:
                mounts.append(str(part.mountpoint))
    except Exception:
        return []
    mounts = sorted(set(mounts))
    return mounts


def is_windows() -> bool:
    return os.name == "nt"


def lock_workstation() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.user32.LockWorkStation())
    except Exception:
        return False


def enroll(server_url: str, enrollment_code: str, host: str) -> Dict[str, Any]:
    r = requests.post(
        f"{server_url}/api/client/enroll",
        json={"enrollment_code": enrollment_code, "hostname": host},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()


def register(server_url: str, name: str, host: str) -> Dict[str, Any]:
    enrollment_key = read_text(ENROLLMENT_KEY_PATH)
    env_key = (os.environ.get("LABMON_ENROLLMENT_KEY") or "").strip()
    if env_key:
        enrollment_key = env_key

    headers = {}
    if enrollment_key:
        headers["X-Enrollment-Key"] = enrollment_key

    r = requests.post(
        f"{server_url}/api/client/register",
        headers=headers,
        json={"name": name, "hostname": host},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()


def ensure_server_url() -> str:
    server_url = read_text(SERVER_URL_PATH)
    if server_url:
        return server_url.rstrip("/")

    env_url = (os.environ.get("LABMON_SERVER_URL") or "").strip()
    if env_url:
        server_url = env_url
        write_text(SERVER_URL_PATH, server_url)
        return server_url.rstrip("/")

    try:
        server_url = input("Enter server URL (example: http://192.168.1.10:8000): ").strip()
    except Exception:
        server_url = ""

    if not server_url:
        server_url = DEFAULT_CONFIG["server_url"]
    write_text(SERVER_URL_PATH, server_url)
    return server_url.rstrip("/")


def ensure_name(host: str) -> str:
    name = read_text(NAME_PATH)
    if name:
        return name

    env_name = (os.environ.get("LABMON_CLIENT_NAME") or "").strip()
    if env_name:
        name = env_name
        write_text(NAME_PATH, name)
        return name

    return host


def read_token() -> str:
    return read_text(TOKEN_PATH)


def write_token(token: str) -> None:
    write_text(TOKEN_PATH, token)


def migrate_from_config_json() -> None:
    config_path = os.path.join(BASE_DIR, "config.json")
    if not os.path.exists(config_path):
        return
    try:
        cfg = load_config(config_path)
        if not read_text(SERVER_URL_PATH) and cfg.get("server_url"):
            write_text(SERVER_URL_PATH, str(cfg.get("server_url")))
        if not read_text(NAME_PATH) and cfg.get("name"):
            write_text(NAME_PATH, str(cfg.get("name")))
        if not read_text(TOKEN_PATH) and cfg.get("token"):
            write_text(TOKEN_PATH, str(cfg.get("token")))
    except Exception:
        return


def post_heartbeat(server_url: str, token: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    r = requests.post(
        f"{server_url}/api/client/heartbeat",
        headers={"X-Client-Token": token},
        json=payload,
        timeout=10,
    )
    r.raise_for_status()
    return r.json()


def poll_commands(server_url: str, token: str) -> List[Dict[str, Any]]:
    r = requests.get(
        f"{server_url}/api/client/commands/poll",
        headers={"X-Client-Token": token},
        timeout=10,
    )
    r.raise_for_status()
    return r.json().get("commands", [])


def mark_executed(server_url: str, token: str, command_id: int) -> None:
    r = requests.post(
        f"{server_url}/api/client/commands/{command_id}/executed",
        headers={"X-Client-Token": token},
        timeout=10,
    )
    r.raise_for_status()


def main() -> int:
    migrate_from_config_json()

    server_url = ensure_server_url()
    host = hostname()

    name = ensure_name(host)

    token = read_token()
    if not token:
        data = register(server_url, name, host)
        token = str(data["token"])
        write_token(token)
        print(f"Enrolled as client_id={data['client_id']}")

    cfg = load_config(os.path.join(BASE_DIR, "config.json"))
    banned = {p.lower() for p in (cfg.get("banned_process_names") or [])}
    interval = int(cfg.get("heartbeat_interval_seconds") or DEFAULT_CONFIG["heartbeat_interval_seconds"])
    interval = max(2, min(60, interval))

    exam_mode_enabled = False

    last_usb = set(list_removable_mounts())
    
    # Load blocked patterns from persistence
    blocked_patterns = []
    try:
        if os.path.exists(BLOCKED_URLS_PATH):
            with open(BLOCKED_URLS_PATH, "r", encoding="utf-8") as f:
                blocked_patterns = [line.strip() for line in f if line.strip()]
    except Exception:
        pass

    def get_browser_window_titles():
        if not win32gui: return []
        titles = []
        browsers = {'chrome.exe', 'msedge.exe', 'firefox.exe', 'browser.exe'}
        def enum_handler(hwnd, _):
            if win32gui.IsWindowVisible(hwnd):
                text = win32gui.GetWindowText(hwnd)
                if text:
                    try:
                        _, pid = win32process.GetWindowThreadProcessId(hwnd)
                        proc = psutil.Process(pid)
                        if proc.name().lower() in browsers:
                            titles.append(text.lower())
                    except: pass
            return True
        try: win32gui.EnumWindows(enum_handler, None)
        except: pass
        return titles

    while True:
        procs = list_process_names()
        proc_lower = [p.lower() for p in procs]
        alerts: List[Dict[str, Any]] = []

        usb_now = set(list_removable_mounts())
        for m in sorted(usb_now - last_usb):
            alerts.append({"event_type": "usb_inserted", "mount": m})
        for m in sorted(last_usb - usb_now):
            alerts.append({"event_type": "usb_removed", "mount": m})
        last_usb = usb_now

        for bp in banned:
            if bp in proc_lower:
                alerts.append({"event_type": "banned_app", "process": bp})
        
        # Collect system resources
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            ram = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent
        except Exception:
            cpu, ram, disk = None, None, None

        # URL violation check
        url_violations = []
        if blocked_patterns:
            titles = get_browser_window_titles()
            violation_found = False
            for title in titles:
                for pattern in blocked_patterns:
                    # Enhanced matching: remove domain suffixes for title matching
                    # e.g. github.com -> github
                    # e.g. chatgpt.com -> chatgpt
                    clean_pattern = pattern.replace('*.', '').lower()
                    match_term = clean_pattern.split('.')[0] if '.' in clean_pattern else clean_pattern
                    
                    if clean_pattern in title or match_term in title:
                        url_violations.append(pattern)
                        violation_found = True
            
            if violation_found:
                # Enterprise Level: Active blocking
                print(f"URL VIOLATION DETECTED: {url_violations}. Closing browsers...")
                browsers_to_kill = {'chrome.exe', 'msedge.exe', 'firefox.exe', 'browser.exe'}
                for p in psutil.process_iter(attrs=["name"]):
                    try:
                        if p.info['name'].lower() in browsers_to_kill:
                            p.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        url_violations = list(set(url_violations))

        payload = {
            "hostname": host,
            "processes": procs,
            "alerts": alerts,
            "cpu_percent": cpu,
            "ram_percent": ram,
            "disk_percent": disk,
            "url_violations": url_violations
        }

        try:
            res = post_heartbeat(server_url, token, payload)
            # Sync blocked patterns from heartbeat response
            new_patterns = res.get("blocked_patterns", [])
            if new_patterns != blocked_patterns:
                blocked_patterns = new_patterns
                with open(BLOCKED_URLS_PATH, "w", encoding="utf-8") as f:
                    f.write("\n".join(blocked_patterns))
                print(f"Synced {len(blocked_patterns)} blocked URL patterns from server")
        except requests.HTTPError as e:
            try:
                status = int(getattr(getattr(e, "response", None), "status_code", 0) or 0)
            except Exception:
                status = 0
            if status == 401:
                try:
                    data = register(server_url, name, host)
                    token = str(data["token"])
                    write_token(token)
                    print(f"Re-enrolled as client_id={data['client_id']}")
                except Exception as ee:
                    print(f"heartbeat auth error; re-enroll failed: {ee}")
            else:
                print(f"heartbeat error: {e}")
        except Exception as e:
            print(f"heartbeat error: {e}")

        try:
            cmds = poll_commands(server_url, token)
        except requests.HTTPError as e:
            try:
                status = int(getattr(getattr(e, "response", None), "status_code", 0) or 0)
            except Exception:
                status = 0
            if status == 401:
                try:
                    data = register(server_url, name, host)
                    token = str(data["token"])
                    write_token(token)
                    print(f"Re-enrolled as client_id={data['client_id']}")
                    cmds = []
                except Exception as ee:
                    print(f"poll auth error; re-enroll failed: {ee}")
                    cmds = []
            else:
                print(f"poll error: {e}")
                cmds = []
        except Exception as e:
            print(f"poll error: {e}")
            cmds = []

        for cmd in cmds:
            cid = int(cmd.get("id"))
            ctype = cmd.get("command_type")
            payload = cmd.get("payload") or {}

            ok = True
            if ctype == "lock_screen":
                ok = lock_workstation()
            elif ctype == "exam_mode":
                exam_mode_enabled = bool(payload.get("enabled"))
            elif ctype == "capture_screenshot":
                try:
                    from PIL import Image, ImageGrab
                    import base64
                    from io import BytesIO
                    
                    print(f"Starting screenshot capture for command {cid}...")
                    # Use ImageGrab for more reliable Windows capture
                    img = ImageGrab.grab()
                    
                    if img is None:
                        raise Exception("ImageGrab returned None")
                        
                    # Resize to 1280x720 for better performance (Enterprise standard)
                    img.thumbnail((1280, 720), Image.Resampling.LANCZOS)
                    
                    # Save as JPEG with 80% quality
                    buffer = BytesIO()
                    img.save(buffer, format="JPEG", quality=80)
                    buffer.seek(0)
                    img_base64 = base64.b64encode(buffer.read()).decode('utf-8')
                    
                    print(f"Uploading screenshot ({len(img_base64) // 1024} KB)...")
                    # Upload screenshot
                    r = requests.post(
                        f"{server_url}/api/client/screenshot",
                        headers={"X-Client-Token": token},
                        json={"image_data": img_base64, "format": "jpg"},
                        timeout=30,
                    )
                    r.raise_for_status()
                    print(f"Screenshot {cid} captured and uploaded successfully")
                except Exception as e:
                    print(f"Screenshot error for command {cid}: {e}")
                    import traceback
                    traceback.print_exc()
                    ok = False
            elif ctype == "update_blocked_urls":
                # Store blocked URLs locally
                blocked_patterns = payload.get("patterns", [])
                print(f"Updated blocked URLs: {len(blocked_patterns)} patterns")
            else:
                ok = False

            try:
                mark_executed(server_url, token, cid)
            except Exception as e:
                print(f"mark executed error: {e}")

            if not ok:
                print(f"command not executed: {ctype}")

        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
