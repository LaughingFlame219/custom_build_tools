import time
from selenium.webdriver.common.by import By

def paloalto_get_config(driver, host):
    try:
        # Device → Setup → Operations ページへ遷移
        driver.get(f"https://{host}/?#device::vsys1::device/setup")
        time.sleep(3)

        # Export Configuration ボタンを探す
        buttons = driver.find_elements(By.TAG_NAME, "button")
        export_btn = None

        for b in buttons:
            text = b.text.strip().lower()
            if "export" in text and "configuration" in text:
                export_btn = b
                break

        if not export_btn:
            print("[ERROR] Export Configuration ボタンが見つかりません")
            return None

        # ボタン押下
        export_btn.click()
        print("[INFO] Palo Alto コンフィグバックアップ開始")

        # ダウンロード待ち
        time.sleep(5)
        print("[INFO] Palo Alto コンフィグ取得完了")

        return "[SUCCESS] Palo Alto コンフィグ取得完了"

    except Exception as e:
        print(f"[ERROR] Palo Alto バックアップ中に例外発生: {e}")
        return None
