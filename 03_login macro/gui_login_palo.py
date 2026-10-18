import winreg
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


# ---------------------------------------------------------
# Windows の既定ブラウザを取得
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
        except:
            pass

    return "MSEdgeHTM"


# ---------------------------------------------------------
# 証明書警告スキップ
# ---------------------------------------------------------
def bypass_certificate_warning(driver):
    try:
        driver.find_element(By.ID, "details-button").click()
        time.sleep(1)
        driver.find_element(By.ID, "proceed-link").click()
        time.sleep(3)
        print("[INFO] 証明書警告をスキップ")
    except:
        pass


# ---------------------------------------------------------
# 表示されている要素取得
# ---------------------------------------------------------
def get_visible_element(driver, xpaths):
    for xpath in xpaths:
        try:
            elements = driver.find_elements(By.XPATH, xpath)
            for elem in elements:
                try:
                    if elem.is_displayed() and elem.is_enabled():
                        print(f"[INFO] Visible element found : {xpath}")
                        return elem
                except:
                    pass
        except:
            pass
    return None


# ---------------------------------------------------------
# Palo Alto GUI 自動ログイン（★ driver を返す版）
# ---------------------------------------------------------
def open_paloalto_gui(device):

    host = device["host"].strip()
    user = device["username"].strip()
    password = device["password"].strip()
    url = f"https://{host}/"

    driver = None

    try:
        prog_id = get_default_browser()

        # ブラウザ起動
        if "Chrome" in prog_id:
            options = webdriver.ChromeOptions()
            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--allow-insecure-localhost")
            driver = webdriver.Chrome(options=options)

        elif "Firefox" in prog_id:
            options = webdriver.FirefoxOptions()
            options.set_preference("security.enterprise_roots.enabled", True)
            driver = webdriver.Firefox(options=options)

        else:
            options = webdriver.EdgeOptions()
            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--allow-insecure-localhost")
            driver = webdriver.Edge(options=options)

        driver.maximize_window()
        driver.set_page_load_timeout(30)

        print(f"[INFO] Accessing {url}")
        driver.get(url)
        time.sleep(3)

        bypass_certificate_warning(driver)

        wait = WebDriverWait(driver, 10)
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))

        print(f"[INFO] TITLE = {driver.title}")
        print(f"[INFO] URL = {driver.current_url}")

        # ユーザー名
        username_field = get_visible_element(driver, [
            "//input[@id='user']",
            "//input[@name='user']",
            "//input[@name='username']",
            "//input[@type='text']",
        ])
        if username_field is None:
            raise Exception("username field not found")

        # パスワード
        password_field = get_visible_element(driver, [
            "//input[@id='password']",
            "//input[@name='password']",
            "//input[@type='password']",
        ])
        if password_field is None:
            raise Exception("password field not found")

        # 入力
        username_field.click()
        username_field.clear()
        username_field.send_keys(user)

        password_field.click()
        password_field.clear()
        password_field.send_keys(password)

        print("[INFO] Credentials entered")

        # ログインボタン
        login_button = get_visible_element(driver, [
            "//input[@type='submit']",
            "//button",
            "//*[contains(text(),'Log In')]",
            "//*[contains(text(),'Login')]"
        ])
        if login_button is None:
            driver.save_screenshot(f"{host}_button_error.png")
            raise Exception("login button not found")

        login_button.click()
        print("[SUCCESS] Login button clicked")

        # ★ 成功 → driver を返す
        return driver

    except Exception as e:
        print(f"[ERROR] GUIログイン中に例外発生: {e}")

        try:
            if driver:
                driver.save_screenshot(f"{host}_login_error.png")
                with open(f"{host}_login_error.html", "w", encoding="utf-8") as f:
                    f.write(driver.page_source)
        except:
            pass

        try:
            if driver:
                driver.quit()
        except:
            pass

        return None
