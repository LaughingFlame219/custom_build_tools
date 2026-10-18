import time
import os
from selenium.webdriver.common.by import By

def fortigate_get_config(driver, host):
    """
    FortiGate v7.6.6 GUIから設定バックアップをダウンロードする。
    Shadow DOM対応版（OKボタン強制クリック）。
    """

    try:
        # ---------------------------------------------------------
        # ① バックアップ画面へ移動（global設定のみ）
        # ---------------------------------------------------------
        url = f"https://{host}/ng/system/config/backup"
        driver.get(url)
        time.sleep(3)

        # ---------------------------------------------------------
        # ② Local PC / FortiOS 選択（必要ならクリック）
        # ---------------------------------------------------------
        try:
            local_btn = driver.find_element(By.XPATH, "//button[contains(text(),'Local PC')]")
            driver.execute_script("arguments[0].click();", local_btn)
            print("[INFO] Local PC を選択しました")
        except:
            pass

        try:
            fortios_btn = driver.find_element(By.XPATH, "//button[contains(text(),'FortiOS')]")
            driver.execute_script("arguments[0].click();", fortios_btn)
            print("[INFO] FortiOS フォーマットを選択しました")
        except:
            pass

        # ---------------------------------------------------------
        # ③ Shadow DOM 内の OK ボタンを強制クリック（最強版）
        # ---------------------------------------------------------
        driver.execute_script("""
            const all = document.querySelectorAll('*');
            for (const el of all) {
                const t = (el.innerText || '').trim();
                if (t === 'OK') {
                    el.click();
                    return;
                }
            }
        """)
        print("[INFO] 強制的に OK ボタンをクリックしました")

        # ---------------------------------------------------------
        # ④ ダウンロード完了を待つ
        # ---------------------------------------------------------
        download_dir = os.path.expanduser("~/Downloads")
        time.sleep(5)

        files = os.listdir(download_dir)
        files = [f for f in files if f.endswith(".conf") or f.endswith(".cfg")]

        if not files:
            return "[ERROR] ダウンロードされたコンフィグファイルが見つかりません"

        latest = max(
            [os.path.join(download_dir, f) for f in files],
            key=os.path.getctime
        )

        # ---------------------------------------------------------
        # ⑤ 保存先へコピー
        # ---------------------------------------------------------
        save_name = f"fortigate_config_{host}.conf"
        os.makedirs("configs", exist_ok=True)
        save_path = os.path.join("configs", save_name)

        with open(latest, "r", encoding="utf-8", errors="ignore") as src:
            with open(save_path, "w", encoding="utf-8") as dst:
                dst.write(src.read())

        return f"[SUCCESS] GUIバックアップ取得完了 → {save_path}"

    except Exception as e:
        return f"[ERROR] GUIバックアップ取得中に例外発生: {e}"
