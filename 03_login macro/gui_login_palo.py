import winreg
import time
from selenium import webdriver
from selenium.webdriver.common.by import By


# ---------------------------------------------------------
# Windows の既定ブラウザを取得（FortiGate版と同じ）
# ---------------------------------------------------------
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

    return "MSEdgeHTM"  # fallback


# ---------------------------------------------------------
# Palo Alto GUI 自動ログイン
# ---------------------------------------------------------
def open_paloalto_gui(device):
    host = device["host"].strip()
    user = device["username"].strip()
    password = device["password"].strip()
    url = f"https://{host}/"

    prog_id = get_default_browser()
    driver = None

    try:
        # ブラウザ起動
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
            driver = webdriver.Edge(options=options)

        # ページアクセス
        driver.set_page_load_timeout(10)  # ★ タイムアウト設定（秒）
        driver.get(url)
        time.sleep(2)

        # ログインフォーム探索
        username_field = driver.find_element(By.XPATH, "//input[@type='text']")
        password_field = driver.find_element(By.XPATH, "//input[@type='password']")
        login_button = driver.find_element(By.XPATH, "//button")

        username_field.send_keys(user)
        password_field.send_keys(password)
        login_button.click()

        return "[SUCCESS] FortiGate GUI に自動ログインしました"

    except Exception as e:
        print(f"[ERROR] GUIログイン中に例外発生: {e}")

        # ★ タイムアウト・接続失敗・ウィンドウ消失時も確実に閉じる
        try:
            if driver is not None:
                driver.quit()
        except:
            pass

        return "[ERROR] FortiGate GUIログイン失敗（ブラウザを閉じました）"