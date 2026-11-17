"""GUI(HTTPS/HTTP) ログイン共通処理 + FortiGate / Palo Alto ログイン。

ブラウザ方式（settings.yaml の reuse_browser）
  true (既定): リモートデバッグ付き Edge に接続し、新しいタブでログインする。
               Edge が未起動なら専用プロファイルで起動し、以後は同じ Edge を再利用。
  false      : 従来どおり毎回ブラウザを新規起動（既定ブラウザに合わせる）

操作中にタブ/ブラウザが閉じられたら TabClosedError で即座に処理を中止する。
"""
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from config_editor import load_settings

BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "configs"
DEBUG_DIR = BASE_DIR / "debug"

# 既定の待ち時間（秒）。settings.yaml の page_load_timeout / login_timeout /
# download_timeout で変更できる
PAGE_TIMEOUT = 15      # ページ読み込み（LAN内機器なら十分）
LOGIN_TIMEOUT = 15     # ログイン完了待ち
DOWNLOAD_TIMEOUT = 30  # コンフィグのダウンロード待ち

PASSWORD_CSS = "input[type='password']"
USER_CSS = "input[name='username'], input[name='user'], input[type='text']"
SUBMIT_CSS = "button.login-button, button[type='submit'], input[type='submit']"

# タブが閉じられたとき、実行中の残り機器も全て中止する(True) / その機器だけ(False)
STOP_ALL_ON_TAB_CLOSE = True
CANCEL = threading.Event()


class TabClosedError(Exception):
    """操作対象のタブ（またはブラウザ）が閉じられた"""


class OperationCancelled(Exception):
    """ユーザーの中止要求（中止ボタン）"""


class DownloadError(Exception):
    """ダウンロードが始まらず、ブラウザにエラーページが表示された"""


# ---------------------------------------------------------
# 小物
# ---------------------------------------------------------
def safe(s) -> str:
    return re.sub(r"[^\w.-]", "_", str(s))


def get_timeout(key, default):
    try:
        return float((load_settings() or {}).get(key, default))
    except (TypeError, ValueError):
        return default


def is_reuse_mode() -> bool:
    return bool((load_settings() or {}).get("reuse_browser", True))


def get_default_browser() -> str:
    """既定ブラウザの ProgId（Windows 以外/取得失敗は空文字）"""
    if sys.platform != "win32":
        return ""
    import winreg
    for proto in ("https", "http"):
        path = rf"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\{proto}\UserChoice"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                return winreg.QueryValueEx(key, "ProgId")[0]
        except OSError:
            continue
    return ""


# ---------------------------------------------------------
# タブ生存確認 / 中断対応の待機
# ---------------------------------------------------------
def _check_tab(driver):
    """タブ/ブラウザが閉じられていれば TabClosedError"""
    handle = getattr(driver, "tab_handle", None)
    try:
        handles = driver.window_handles
    except Exception as e:
        raise TabClosedError("ブラウザとの接続が切れました") from e
    if handle is not None and handle not in handles:
        raise TabClosedError("操作対象のタブが閉じられました")


def check_alive(driver):
    """中止要求・タブ/ブラウザの消失を検知して例外を投げる"""
    if CANCEL.is_set():
        raise OperationCancelled("中止が要求されました")
    _check_tab(driver)


def tab_closed(driver) -> bool:
    if driver is None:
        return False
    try:
        _check_tab(driver)
        return False
    except TabClosedError:
        return True


def is_alive(driver) -> bool:
    return driver is not None and not tab_closed(driver)


def sleep_alive(driver, seconds):
    """time.sleep の代わり。待機中もタブの生存を確認する"""
    end = time.time() + seconds
    while True:
        check_alive(driver)
        remaining = end - time.time()
        if remaining <= 0:
            return
        time.sleep(min(0.25, remaining))


def wait_until(driver, predicate, timeout, poll=0.5):
    """WebDriverWait の代わり。ポーリングごとにタブの生存を確認する"""
    end = time.time() + timeout
    while True:
        check_alive(driver)
        try:
            value = predicate(driver)
        except WebDriverException:
            check_alive(driver)      # 閉じられていれば TabClosedError
            value = False
        if value:
            return value
        if time.time() >= end:
            raise TimeoutException("wait_until timeout")
        time.sleep(poll)


def abort_message(driver, name, exc):
    """タブが閉じられた/中止された場合の通知文を返す（それ以外は None）"""
    if isinstance(exc, TabClosedError) or tab_closed(driver):
        if STOP_ALL_ON_TAB_CLOSE:
            CANCEL.set()
        return f"[STOPPED] {name}: タブ（ブラウザ）が閉じられたため処理を中止しました"
    if isinstance(exc, OperationCancelled) or CANCEL.is_set():
        return f"[STOPPED] {name}: 中止されました"
    return None


def find_visible(driver, by, selector, last=False):
    """表示中の最初（last=True なら最後）の要素。無ければ None"""
    found = None
    for e in driver.find_elements(by, selector):
        try:
            if e.is_displayed():
                if not last:
                    return e
                found = e
        except WebDriverException:
            pass
    return found


def wait_visible_any(driver, candidates, timeout=None, last=False):
    """candidates = [(By.XXX, selector), ...] のどれかが表示されるまで待つ"""
    if timeout is None:
        timeout = get_timeout("login_timeout", LOGIN_TIMEOUT)
    def check(d):
        for by, sel in candidates:
            e = find_visible(d, by, sel, last)
            if e:
                return e
        return False
    return wait_until(driver, check, timeout)


def js_click(driver, element):
    driver.execute_script("arguments[0].click();", element)


# ---------------------------------------------------------
# Edge（リモートデバッグ）再利用
# ---------------------------------------------------------
_EDGE_LOCK = threading.Lock()


def find_edge_exe(settings):
    p = settings.get("edge_path")
    if p and Path(p).exists():
        return p
    for cand in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                 r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"):
        if Path(cand).exists():
            return cand
    found = shutil.which("msedge")
    if found:
        return found
    raise FileNotFoundError("msedge.exe が見つかりません。settings.yaml に edge_path を指定してください。")


def debug_port_alive(port) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1):
            return True
    except Exception:
        return False


def ensure_edge(settings):
    """デバッグポート付き Edge を用意する。戻り値: (port, 今回起動したか)"""
    port = int(settings.get("edge_debug_port", 9222))
    with _EDGE_LOCK:
        if debug_port_alive(port):
            return port, False

        profile = Path(settings.get("edge_profile_dir") or (BASE_DIR / "edge_profile"))
        profile.mkdir(parents=True, exist_ok=True)
        subprocess.Popen([
            find_edge_exe(settings),
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "--ignore-certificate-errors",
        ])
        for _ in range(40):                      # 最大20秒
            time.sleep(0.5)
            if debug_port_alive(port):
                return port, True
        raise RuntimeError(f"Edge のデバッグポート {port} に接続できません")


def _attach_edge():
    settings = load_settings() or {}
    port, launched = ensure_edge(settings)
    dl_dir = tempfile.mkdtemp(prefix="gui_dl_")
    driver = None
    try:
        opts = webdriver.EdgeOptions()
        opts.add_experimental_option("debuggerAddress", f"127.0.0.1:{port}")
        driver = webdriver.Edge(options=opts)

        if launched and len(driver.window_handles) == 1:
            driver.switch_to.window(driver.window_handles[0])   # 起動直後の空タブを使う
        else:
            driver.switch_to.new_window("tab")                  # 既存の Edge に新しいタブを追加

        driver.attached = True
        driver.tab_handle = driver.current_window_handle
        driver.download_dir = dl_dir
        driver.set_page_load_timeout(get_timeout("page_load_timeout", PAGE_TIMEOUT))
        try:
            driver.execute_cdp_cmd("Security.setIgnoreCertificateErrors", {"ignore": True})
        except Exception:
            pass
        return driver
    except Exception:
        try:
            if driver:
                driver.quit()
        except Exception:
            pass
        shutil.rmtree(dl_dir, ignore_errors=True)
        raise


# ---------------------------------------------------------
# 従来方式：ブラウザを新規起動
# ---------------------------------------------------------
def _launch_browser(keep_open):
    dl_dir = tempfile.mkdtemp(prefix="gui_dl_")
    prog_id = get_default_browser()
    try:
        if "Firefox" in prog_id:
            opts = webdriver.FirefoxOptions()
            opts.accept_insecure_certs = True
            prefs = {
                "browser.download.folderList": 2,
                "browser.download.dir": dl_dir,
                "browser.download.useDownloadDir": True,
                "browser.helperApps.neverAsk.saveToDisk":
                    "application/octet-stream,application/xml,text/xml,"
                    "text/plain,application/x-gzip,application/force-download",
            }
            for k, v in prefs.items():
                opts.set_preference(k, v)
            driver = webdriver.Firefox(options=opts)
        else:
            use_chrome = "Chrome" in prog_id
            opts = webdriver.ChromeOptions() if use_chrome else webdriver.EdgeOptions()
            opts.accept_insecure_certs = True
            opts.add_argument("--ignore-certificate-errors")
            opts.add_experimental_option("prefs", {
                "download.default_directory": dl_dir,
                "download.prompt_for_download": False,
                "download.directory_upgrade": True,
                "safebrowsing.enabled": True,
                "safebrowsing.disable_download_protection": True,
                "profile.default_content_setting_values.automatic_downloads": 1,
            })
            if keep_open:
                opts.add_experimental_option("detach", True)
            driver = (webdriver.Chrome if use_chrome else webdriver.Edge)(options=opts)
    except Exception:
        shutil.rmtree(dl_dir, ignore_errors=True)
        raise

    driver.attached = False
    driver.tab_handle = driver.current_window_handle
    driver.download_dir = dl_dir
    driver.set_page_load_timeout(get_timeout("page_load_timeout", PAGE_TIMEOUT))
    return driver


def create_driver(keep_open=False):
    return _attach_edge() if is_reuse_mode() else _launch_browser(keep_open)


def close_driver(driver):
    """再利用モードでは自分が開いたタブだけ閉じる（Edge 本体は閉じない）"""
    if driver is None:
        return
    dl_dir = getattr(driver, "download_dir", None)
    try:
        if getattr(driver, "attached", False):
            try:
                driver.execute_cdp_cmd("Browser.setDownloadBehavior", {"behavior": "default"})
            except Exception:
                pass
            handle = getattr(driver, "tab_handle", None)
            handles = driver.window_handles
            if handle in handles:
                driver.switch_to.window(handle)
                if len(handles) > 1:
                    driver.close()                 # 他にタブがあれば閉じる
                else:
                    driver.get("about:blank")      # 最後の1枚はブラウザごと終了しないよう残す
    except Exception:
        pass
    try:
        driver.quit()
    except Exception:
        pass
    if dl_dir:
        shutil.rmtree(dl_dir, ignore_errors=True)


# ---------------------------------------------------------
# ダウンロード（専用一時フォルダ）
# ---------------------------------------------------------
_PARTIAL = (".crdownload", ".part", ".tmp")


def prepare_download(driver):
    """このドライバのダウンロード先を専用一時フォルダへ向ける（Chromium系。Firefox は起動時設定済み）"""
    if not hasattr(driver, "execute_cdp_cmd"):
        return
    params = {"behavior": "allow", "downloadPath": driver.download_dir}
    for method in ("Browser.setDownloadBehavior", "Page.setDownloadBehavior"):
        try:
            driver.execute_cdp_cmd(method, params)
            return
        except WebDriverException:
            continue


def quick_get(driver, url, timeout=5):
    """ダウンロード応答のURLを開く。ページ遷移が完了しないため短いタイムアウトで打ち切る"""
    driver.set_page_load_timeout(timeout)
    try:
        driver.get(url)
    except TimeoutException:
        pass
    finally:
        try:
            driver.set_page_load_timeout(get_timeout("page_load_timeout", PAGE_TIMEOUT))
        except WebDriverException:
            pass


def detect_error_page(driver):
    """ブラウザがエラーページ/エラーJSONを表示していれば、その要約を返す"""
    try:
        text = driver.find_element(By.TAG_NAME, "body").text
    except WebDriverException:
        return None
    m = (re.search(r"HTTP ERROR\s*(\d{3})", text)
         or re.search(r'"http_status"\s*:\s*(\d{3})', text))
    if m:
        return f"HTTP {m.group(1)}"
    m = re.search(r"ERR_[A-Z_]+", text)
    return m.group(0) if m else None


def wait_for_download(driver, timeout=60, error_check=detect_error_page):
    """専用フォルダに完成したファイルが現れ、サイズが安定するまで待つ。
    ブラウザがエラーページを表示したら待たずに DownloadError。"""
    dl = Path(driver.download_dir)
    end = time.time() + timeout
    while time.time() < end:
        check_alive(driver)
        files = [p for p in dl.iterdir()
                 if p.is_file() and p.suffix.lower() not in _PARTIAL
                 and not p.name.startswith(".com.google")
                 and not p.name.startswith(".org.chromium")]
        if files:
            f = max(files, key=lambda p: p.stat().st_mtime)
            size = f.stat().st_size
            sleep_alive(driver, 1)
            if size > 0 and size == f.stat().st_size:
                return f
        elif error_check:
            msg = error_check(driver)
            if msg:
                raise DownloadError(f"ブラウザにエラーが表示されました（{msg}）")
        time.sleep(0.5)
    return None


def save_download(driver, device, dev_type, timeout=60, default_ext=""):
    """ダウンロードされたファイルを configs/ へ移動（バイナリのまま）"""
    src = wait_for_download(driver, timeout)
    if src is None:
        return None
    CONFIG_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    ext = src.suffix or default_ext
    dest = CONFIG_DIR / f"{dev_type}_{safe(device['name'])}_{safe(device['host'])}_{stamp}{ext}"
    shutil.move(str(src), str(dest))
    return dest


def save_debug(driver, tag):
    try:
        DEBUG_DIR.mkdir(exist_ok=True)
        stem = DEBUG_DIR / f"{safe(tag)}_{datetime.now():%Y%m%d-%H%M%S}"
        driver.save_screenshot(str(stem) + ".png")
        Path(str(stem) + ".html").write_text(driver.page_source, encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------
# ログイン共通  戻り値: (driver or None, メッセージ)
# ---------------------------------------------------------
def _open_gui(device, url, protocol, keep_open, post_login=None):
    name = device.get("name", device["host"])
    user = device["username"].strip()
    password = device["password"].strip()
    driver = None
    try:
        driver = create_driver(keep_open)
        driver.get(url)
        err = detect_error_page(driver)       # 接続拒否/プロトコル違いなどを待たずに検知
        if err:
            raise ConnectionError(f"接続できません: {err}（{protocol.upper()} で合っているか確認）")

        user_el = wait_visible_any(driver, [(By.CSS_SELECTOR, USER_CSS)])
        pass_el = wait_visible_any(driver, [(By.CSS_SELECTOR, PASSWORD_CSS)])
        user_el.clear()
        user_el.send_keys(user)
        pass_el.clear()
        pass_el.send_keys(password)

        btn = find_visible(driver, By.CSS_SELECTOR, SUBMIT_CSS)
        if btn:
            btn.click()
        else:
            pass_el.send_keys(Keys.ENTER)

        # 成功判定：パスワード欄が消える（失敗時は残るのでタイムアウト）
        wait_until(driver, lambda d: find_visible(d, By.CSS_SELECTOR, PASSWORD_CSS) is None,
                   get_timeout("login_timeout", LOGIN_TIMEOUT))
        sleep_alive(driver, 1)
        if post_login:
            post_login(driver)

        return driver, f"[SUCCESS] {name}: GUIログイン完了 ({protocol.upper()})"

    except Exception as e:
        stop = abort_message(driver, name, e)
        if stop:
            close_driver(driver)
            return None, stop

        if isinstance(e, TimeoutException):
            reason = "接続または認証がタイムアウトしました（ID/パスワード/URLを確認）"
        else:
            reason = (str(e).splitlines() or [repr(e)])[0]
        if driver:
            save_debug(driver, f"{name}_login")
            close_driver(driver)
        return None, f"[ERROR] {name}: GUIログイン失敗: {reason}"


# ---------------------------------------------------------
# FortiGate
# ---------------------------------------------------------
# ログイン直後に出る案内画面（/prompt/fortigate-setup 等）の「後で」ボタンを、
# Shadow DOM の中も含めて探してクリックする
_JS_CLICK_LATER = """
const labels = arguments[0];
function walk(root) {
  for (const el of root.querySelectorAll('*')) {
    if (el.shadowRoot && walk(el.shadowRoot)) return true;
    const t = (el.innerText || el.textContent || '').trim();
    const clickable = el.tagName === 'BUTTON' || el.tagName === 'A' ||
                      el.getAttribute('role') === 'button';
    if (clickable && labels.includes(t)) { el.click(); return true; }
  }
  return false;
}
return walk(document);
"""
_LATER_LABELS = ["後で", "Later", "スキップ", "Skip"]


def dismiss_fortigate_prompts(driver, protocol, host, timeout=10):
    """ログイン後の案内画面（FortiCare登録・初期設定など）を「後で」で閉じる。
    連続して出る場合も繰り返し閉じる。閉じられなければ URL を書き換えて抜ける。"""
    end = time.time() + timeout
    quiet_since = None
    while time.time() < end:
        check_alive(driver)
        if "/prompt/" in driver.current_url:
            quiet_since = None
            try:
                if driver.execute_script(_JS_CLICK_LATER, _LATER_LABELS):
                    sleep_alive(driver, 1)
                    continue
            except WebDriverException:
                pass
        else:
            if quiet_since is None:
                quiet_since = time.time()
            elif time.time() - quiet_since >= 2:      # 2秒間案内が出なければ完了
                return
        sleep_alive(driver, 0.5)

    if "/prompt/" in driver.current_url:               # 閉じられなかった → URL を上書き
        driver.get(f"{protocol}://{host}/ng")
        sleep_alive(driver, 1)


def open_fortigate_gui(device, protocol="https", keep_open=False):
    host = device["host"].strip()
    url = f"{protocol}://{host}/login"
    return _open_gui(device, url, protocol, keep_open,
                     post_login=lambda d: dismiss_fortigate_prompts(d, protocol, host))


# ---------------------------------------------------------
# Palo Alto
# ---------------------------------------------------------
def _close_palo_popups(driver):
    """ログイン後のテレメトリ等のポップアップを閉じる（無ければ何もしない）"""
    sleep_alive(driver, 2)
    for text in ("閉じる", "Close"):
        for e in driver.find_elements(By.XPATH, f"//*[normalize-space(text())='{text}']"):
            try:
                if e.is_displayed():
                    js_click(driver, e)
            except WebDriverException:
                pass


def open_paloalto_gui(device, protocol="https", keep_open=False):
    url = f"{protocol}://{device['host'].strip()}/"
    return _open_gui(device, url, protocol, keep_open, post_login=_close_palo_popups)
