import winreg
import time

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

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
        WebDriverWait(driver,3).until(
            EC.presence_of_element_located((By.ID,"detail-button"))
        )

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
# Palo Alto GUI Login
# ---------------------------------------------------------
def open_paloalto_gui(device):

    host = device["host"].strip()
    user = device["username"].strip()
    password = device["password"].strip()
    url = f"{protocol}://{host}/"

    driver = None

    try:
        prog_id = get_default_browser()

        # ブラウザ起動
        if "Chrome" in prog_id:

            options = webdriver.ChromeOptions()

            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--allow-insecure-localhost")
            options.add_argument("--disable-web-security")

            driver = webdriver.Chrome(options=options)

        elif "Firefox" in prog_id:

            options = webdriver.FirefoxOptions()
            options.set_preference(
                "security.enterprise_roots.enabled", 
                True
            )

            driver = webdriver.Firefox(options=options)

        else:
            options = webdriver.EdgeOptions()

            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--allow-insecure-localhost")
            options.add_argument("--disable-web-security")

            options.add_argument("--disable-gpu")
            options.add_argument("--no-sandbox")

            driver = webdriver.Edge(options=options)

            driver.set_page_load_timeout(15)


        try:
            driver.get(url)
            time.sleep(3)
        except Exception as e:
            print("GET ERROR:",e)
            print("CURRENT URL:",driver.current_url)

        bypass_certificate_warning(driver)

        WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )

        print(f"[INFO] TITLE = {driver.title}")
        print(f"[INFO] URL = {driver.current_url}")

        # ユーザー名
        username_field = get_visible_element(driver, [

            "//input[@id='user']",
            "//input[@name='user']",
            "//input[@name='username']",
            "//input[@autocomplete='username']",
            "//input[@contains(@aria-label,'User')]",
            "//input[@contains(@aplaceholder,'User')]",
            "//input[@type='text']",
        ])

        if username_field is None:

            raise Exception("username field not found")

        # password
        password_field = get_visible_element(driver, [

            "//input[@id='password']",
            "//input[@name='password']",
            "//input[@autocomplete='current-password')]",
            "//input[@contains(@aria-label,'Password')]",
            "//input[@type='password']",
        ])
        
        if password_field is None:
            raise Exception("password field not found")

        # 入力
        username_field.clear()
        username_field.send_keys(user)

        password_field.clear()
        password_field.send_keys(password)

        print("[INFO] Credentials entered")

        # Login Buttons

        login_button = get_visible_element(driver, [
            "//button[@type='submit']",
            "//input[@type='submit']",

            "//button[contains(.,'Log In')]",
            "//button[contains(.,'Login')]",
            "//button[contains(.,'Sign In')]",

            "//*[contains(text(),'Log In')]",
            "//*[contains(text(),'Login')]",
            "//*[contains(text(),'Sign In')]",
        ])

        if login_button is None:

            print("[WARN] Login button not found.")
            print("[INFO] Try Enter Key.")

            password_field.send_keys(Keys.ENTER)

        else:

            login_button.click()
            
        print("[INFO] Login Submitted")

        # ---------------------------------------------------------
        # popup close
        # ---------------------------------------------------------
        def close_telemetry_popup(driver):

            try:

                time.sleep(2)

                close_button = driver.find_element(
                    By.XPATH,
                    "//*[text()='閉じる']"
                )

                driver.execute_script(
                    "arguments[0].click()",
                    close_button
                )

            except Exception as e:
                print(f"[ERROR] ポップアップなし: {e}")

        # ----------------------------
        # ログイン成功判定
        # ----------------------------
        try:
            WebDriverWait(driver,30).until(
                lambda d:(
                    "login" not in d.current_url.lower()
                    and "signin" not in d.current_url.lower()
                )
            )
        except TimeoutException:
            raise Exception(
                f"login timeout. current url = {driver.current_url}"
            )
        time.sleep(3)
        print(f"[SUCESS] Login Success")
        print(f"[SUCESS] TITLE = {driver.title}")
        print(f"[SUCESS] URL = {driver.current_url}")
        close_telemetry_popup(driver)
        return driver

    except Exception as e:
        
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
