from concurrent.futures import ThreadPoolExecutor

from gui_login import (
    CANCEL, close_driver, is_reuse_mode,
    open_fortigate_gui, open_paloalto_gui,
)
from fortigate_get_config import fortigate_get_config
from paloalto_get_config import paloalto_get_config

MAX_GUI_WORKERS = 3
GUI_TYPES = ("fortigate", "paloalto")


def _workers():
    # 1つの Edge を共有する場合、複数タブを同時操作するとフォーカス競合で不安定なため
    # 1台ずつ順番に処理する。ブラウザを個別起動する場合のみ並列。
    return 1 if is_reuse_mode() else MAX_GUI_WORKERS


def _open(device, keep_open):
    """戻り値: (driver or None, メッセージ)"""
    protocol = device.get("protocol", "https")
    if device.get("type") == "fortigate":
        return open_fortigate_gui(device, protocol, keep_open)
    if device.get("type") == "paloalto":
        return open_paloalto_gui(device, protocol, keep_open)
    return None, f"[INFO] {device.get('name', '?')}: GUI非対応の機器種別です"


# ---------------------------------------------------------
# GUIログイン（タブは開いたまま返す）
# 戻り値: [(name, driver or None, メッセージ), ...]（入力と同じ順）
# ---------------------------------------------------------
def run_parallel_gui_login(devices, keep_open=True):
    CANCEL.clear()

    def worker(dev):
        name = dev.get("name", "?")
        if CANCEL.is_set():
            return name, None, f"[SKIP] {name}: 中止されたためスキップしました"
        try:                                   # 1台の失敗が他の機器・画面に波及しないよう隔離
            driver, msg = _open(dev, keep_open)
            return name, driver, msg
        except Exception as e:
            return name, None, f"[ERROR] {name}: {type(e).__name__}: {e}"

    with ThreadPoolExecutor(max_workers=_workers()) as ex:
        return list(ex.map(worker, devices))


# ---------------------------------------------------------
# コンフィグ取得（ログイン → 取得 → タブ/ブラウザを閉じる）
# 戻り値: [(name, メッセージ), ...]（入力と同じ順）
# ---------------------------------------------------------
def _get_config_worker(device):
    name = device.get("name", "?")
    protocol = device.get("protocol", "https")

    if CANCEL.is_set():
        return name, f"[SKIP] {name}: 中止されたためスキップしました"
    if device.get("type") not in GUI_TYPES:
        return name, f"[INFO] {name}: コンフィグ取得未対応の機器種別です"

    driver = None
    try:
        driver, msg = _open(device, keep_open=False)
        if not driver:
            return name, msg

        if device["type"] == "fortigate":
            return name, fortigate_get_config(driver, device, protocol)
        return name, paloalto_get_config(driver, device, protocol)
    except Exception as e:
        return name, f"[ERROR] {name}: {type(e).__name__}: {e}"
    finally:
        close_driver(driver)


def run_parallel_get_config(devices):
    CANCEL.clear()
    with ThreadPoolExecutor(max_workers=_workers()) as ex:
        return list(ex.map(_get_config_worker, devices))
