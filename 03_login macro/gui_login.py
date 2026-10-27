import winreg
import time
from selenium import webdriver
from selenium.webdriver.common.by import By

def get_default_browser():
    registry_paths = [
        r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice",
        r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\http\UserChoice",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\https\UserChoice",
    ]
    for path in registry_paths:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
            prog_id, _ = winreg.QueryValueEx(key, "ProgId")
            return prog_id
        except Exception:
            continue
    return "MSEdgeHTM"


def open_fortigate_gui(device, protocol="https"):
    host = device["host"].strip()
    user = device["username"].strip()
    password = device["password"].strip()

    # ★ 修正：protocol を使って URL を生成
    url = f"{protocol}://{host}/login"

    prog_id = get_default_browser()
    driver = None

    try:
        # ---------------------------------------------------------
        # ブラウザ起動
        # ---------------------------------------------------------
        if "Chrome" in prog_id:
            options = webdriver.ChromeOptions()
            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--allow-insecure-localhost")
            driver = webdriver.Chrome(options=options)
        elif "Firefox" in prog_id:
            options = webdriver.FirefoxOptions()
            options.set_preference("network.stricttransportsecurity.preloadlist", False)
            options.set_preference("security.ssl.enable_ocsp_stapling", False)
            driver = webdriver.Firefox(options=options)
        else:
            options = webdriver.EdgeOptions()
            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--allow-insecure-localhost")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-features=IsolateOrigins,site-per-process")
            options.add_argument("--disable-blink-features=AutomationControlled")
            driver = webdriver.Edge(options=options)

        driver.set_page_load_timeout(10)
        driver.get(url)
        time.sleep(2)

        # ---------------------------------------------------------
        # ★ FortiGate v7.6.6 の Angularフォーム対応
        # ---------------------------------------------------------
        inputs = driver.find_elements(By.TAG_NAME, "input")
        user_field = None
        pass_field = None

        for inp in inputs:
            t = inp.get_attribute("type")
            if t == "text":
                user_field = inp
            elif t == "password":
                pass_field = inp

        if not user_field or not pass_field:
            print("[ERROR] ログインフォームが見つかりません")
            driver.quit()
            return None

        user_field.send_keys(user)
        pass_field.send_keys(password)

        # ---------------------------------------------------------
        # ★ ログインボタンを直接クリック
        # ---------------------------------------------------------
        login_button = driver.find_element(By.CSS_SELECTOR, "button.primary.login-button")
        login_button.click()

        time.sleep(3)
        print(f"[INFO] FortiGate GUIログイン成功 ({protocol.upper()})")
        return driver

    except Exception as e:
        print(f"[ERROR] GUIログイン中に例外発生: {e}")
        try:
            if driver:
                driver.quit()
        except:
            pass
        return None
