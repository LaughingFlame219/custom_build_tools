"""FortiGate: GUIログイン済みブラウザでバックアップURLを開いて取得する。

画面のボタン操作（Shadow DOM 等）に依存せず、ログイン済みセッションの
Cookie でバックアップ API(GET) を開く。APIトークンは不要。

動作確認: ログイン後の同じブラウザで下記URLを開き、ファイルが
ダウンロードされれば本処理も動作する。
  {protocol}://{host}/api/v2/monitor/system/config/backup?scope=global

タブが閉じられた場合は [STOPPED] を返して即中止する。
"""
from urllib.parse import urlencode

from selenium.webdriver.common.by import By

from gui_login import (
    DOWNLOAD_TIMEOUT, DownloadError, abort_message, dismiss_fortigate_prompts,
    get_timeout, prepare_download, quick_get, save_debug, save_download,
)


def fortigate_get_config(driver, device, protocol="https"):
    name = device["name"]
    host = device["host"].strip()

    # 既定は global（全体）。VDOM 単位で取りたい場合は devices.yaml に
    #   backup_scope: vdom  と  vdom: <名前>  を指定
    params = {"scope": "global"}
    if device.get("backup_scope") == "vdom" and device.get("vdom"):
        params = {"scope": "vdom", "vdom": device["vdom"]}

    url = f"{protocol}://{host}/api/v2/monitor/system/config/backup?{urlencode(params)}"

    try:
        if "/prompt/" in driver.current_url:          # 案内画面が出ていれば先に閉じる
            dismiss_fortigate_prompts(driver, protocol, host)
        prepare_download(driver)
        quick_get(driver, url)

        path = save_download(driver, device, "fortigate",
                             timeout=get_timeout("download_timeout", DOWNLOAD_TIMEOUT),
                             default_ext=".conf")
        if path:
            return f"[SUCCESS] {name}: コンフィグ取得完了 → {path}"

        hint = ""
        try:
            hint = driver.find_element(By.TAG_NAME, "body").text.strip()[:200]
        except Exception:
            pass
        save_debug(driver, f"{name}_backup")
        return f"[ERROR] {name}: ダウンロードされませんでした {hint}"

    except Exception as e:
        stop = abort_message(driver, name, e)
        if stop:
            return stop
        save_debug(driver, f"{name}_backup")
        if isinstance(e, DownloadError):
            hint = ""
            if "401" in str(e) or "403" in str(e):
                hint = "（ログイン済みセッションではバックアップAPIが使えない可能性。同URLを手動で開いて確認）"
            return f"[ERROR] {name}: {e}{hint}"
        return f"[ERROR] {name}: コンフィグ取得中に例外: {(str(e).splitlines() or [repr(e)])[0]}"
