"""Palo Alto: Device > Setup > Operations > Export named configuration snapshot。

画面文言/構造は PAN-OS のバージョンや表示言語で異なるため、
探索用の XPath は下の定数にまとめている。動かない場合は
debug/ に保存されるスクリーンショットとHTMLを見て調整する。

タブが閉じられた場合は [STOPPED] を返して即中止する。
"""
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By

from gui_login import (
    DOWNLOAD_TIMEOUT, abort_message, find_visible, get_timeout, js_click,
    prepare_download, save_debug, save_download, sleep_alive, wait_visible_any,
)

SETUP_HASH = "#device::vsys1::device/setup"

OPERATIONS_TAB = [
    (By.XPATH, "//*[normalize-space(text())='Operations']"),
    (By.XPATH, "//*[normalize-space(text())='オペレーション']"),
    (By.XPATH, "//*[normalize-space(text())='操作']"),
]
EXPORT_LINK = [
    (By.XPATH, "//*[self::a or self::span][contains(normalize-space(.),'Export named configuration snapshot')]"),
    (By.XPATH, "//*[self::a or self::span][contains(.,'スナップショット') and contains(.,'エクスポート')]"),
]
OK_BUTTON = [
    (By.XPATH, "//span[normalize-space(.)='OK']"),
    (By.XPATH, "//span[normalize-space(.)='はい']"),
]


def _select_running_config(driver):
    """ダイアログのドロップダウンが空なら running-config.xml を選ぶ（ベストエフォート）"""
    try:
        combo = find_visible(driver, By.XPATH,
                             "//div[contains(@class,'x-window')]//input[@type='text']")
        if combo and "running-config" not in (combo.get_attribute("value") or ""):
            js_click(driver, combo)
            sleep_alive(driver, 0.5)
            item = find_visible(driver, By.XPATH,
                                "//li[normalize-space(.)='running-config.xml']"
                                " | //div[normalize-space(.)='running-config.xml']")
            if item:
                js_click(driver, item)
    except WebDriverException:
        pass


def paloalto_get_config(driver, device, protocol="https"):
    name = device["name"]
    host = device["host"].strip()
    try:
        prepare_download(driver)
        driver.get(f"{protocol}://{host}/{SETUP_HASH}")
        sleep_alive(driver, 3)

        js_click(driver, wait_visible_any(driver, OPERATIONS_TAB, timeout=15))
        sleep_alive(driver, 1)

        js_click(driver, wait_visible_any(driver, EXPORT_LINK, timeout=15))
        sleep_alive(driver, 1)

        _select_running_config(driver)

        # ダイアログが複数あっても最前面（最後）の OK を押す
        js_click(driver, wait_visible_any(driver, OK_BUTTON, timeout=10, last=True))

        path = save_download(driver, device, "paloalto",
                             timeout=get_timeout("download_timeout", DOWNLOAD_TIMEOUT),
                             default_ext=".xml")
        if path:
            return f"[SUCCESS] {name}: コンフィグ取得完了 → {path}"

        save_debug(driver, f"{name}_export")
        return f"[ERROR] {name}: ダウンロードされませんでした（debug/ を確認）"

    except Exception as e:
        stop = abort_message(driver, name, e)
        if stop:
            return stop
        save_debug(driver, f"{name}_export")
        return f"[ERROR] {name}: コンフィグ取得中に例外: {(str(e).splitlines() or [repr(e)])[0]}"
