import time

try:
    import FreeSimpleGUI as sg      # pip install FreeSimpleGUI
except ImportError:
    import PySimpleGUI as sg

from config_editor import load_devices
from ssh_core import try_login_only, try_login_and_execute
from gui import device_editor_gui
from command_editor import command_editor_gui
from parallel_gui_login import (
    GUI_TYPES, run_parallel_gui_login, run_parallel_get_config,
)
from gui_login import CANCEL, close_driver, is_alive

# GUIログイン後の driver を保持 { "device_name": driver }
gui_drivers = {}

# 中止を押してもこの秒数たっても終わらない処理は「応答なし」とみなし、新しい処理を許可する
STALE_AFTER_CANCEL = 45


def prune_drivers():
    """閉じられたタブの driver を片付ける"""
    for name in list(gui_drivers):
        if not is_alive(gui_drivers[name]):
            close_driver(gui_drivers.pop(name))


def guarded(run_id, fn, targets):
    """バックグラウンド処理で例外が出ても必ず完了イベントを返す
    （例外で完了イベントが出ないと、画面が「実行中」のまま固まるため）"""
    try:
        return run_id, "ok", fn(targets)
    except Exception as e:
        return run_id, "error", f"{type(e).__name__}: {e}"


def main_gui():
    sg.theme("SystemDefault")

    devices = load_devices()
    names = [d["name"] for d in devices]

    layout = [
        [sg.Text("機器一覧（複数選択可）")],
        [sg.Listbox(names, size=(40, 8), key="target_devices", select_mode="extended")],
        [sg.Text("ログイン方式")],
        [sg.Radio("CLI（SSH / TeraTerm）", "LOGIN_TYPE", default=True, key="login_cli"),
         sg.Radio("GUI（HTTPS / HTTP）", "LOGIN_TYPE", key="login_gui")],
        [sg.Button("ログイン"), sg.Button("コマンド実行"), sg.Button("コンフィグ取得"),
         sg.Button("中止", disabled=True),
         sg.Button("機器編集"), sg.Button("コマンド編集"), sg.Button("終了")],
        [sg.Multiline(size=(90, 16), key="log", autoscroll=True, disabled=True)],
    ]

    window = sg.Window("Network Automation Tool", layout, finalize=True)
    state = {"busy": False, "run_id": 0, "cancel_at": None}

    def log(text):
        window["log"].update(text + "\n", append=True)

    def can_start_gui_op():
        """GUI処理は同時に1つだけ（共有Edgeのタブ操作が競合するため）。
        CLIログイン/コマンド実行はいつでも実行できる。"""
        if not state["busy"]:
            return True
        cancel_at = state["cancel_at"]
        if cancel_at and time.time() - cancel_at > STALE_AFTER_CANCEL:
            log("[WARN] 前の処理が応答しないため、新しい処理を開始します")
            return True
        log("[WARN] GUI処理を実行中です。終わるまで待つか『中止』を押してください")
        return False

    def start(fn, targets, end_key):
        state["busy"] = True
        state["run_id"] += 1
        state["cancel_at"] = None
        window["中止"].update(disabled=False)
        run_id = state["run_id"]
        window.perform_long_operation(lambda: guarded(run_id, fn, targets), end_key)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "終了"):
            if state["busy"]:
                CANCEL.set()
            break

        # ---------------- 編集 ----------------
        if event == "機器編集":
            device_editor_gui()
            devices = load_devices()
            names = [d["name"] for d in devices]
            window["target_devices"].update(names)
            continue

        if event == "コマンド編集":
            command_editor_gui()
            continue

        # ---------------- 中止 ----------------
        if event == "中止":
            if state["busy"]:
                CANCEL.set()
                state["cancel_at"] = time.time()
                log("[INFO] 中止を要求しました（実行中の機器から順に止まります）")
            continue

        # ---------------- 実行系 ----------------
        if event in ("ログイン", "コマンド実行", "コンフィグ取得"):
            targets = [d for d in devices if d["name"] in values["target_devices"]]
            if not targets:
                log("[WARN] 実行対象の機器が選択されていません")
                continue

            if event == "ログイン":
                if values["login_cli"]:
                    for dev in targets:
                        log(f"===== {dev['name']} =====")
                        log(try_login_only(dev))
                else:
                    if not can_start_gui_op():
                        continue
                    prune_drivers()
                    gui_targets = []
                    for d in targets:
                        if d.get("type") not in GUI_TYPES:
                            log(f"[INFO] {d['name']}: GUIログイン非対応の機器です")
                        elif d["name"] in gui_drivers:
                            log(f"[INFO] {d['name']}: ログイン済みのタブがあります（再ログインはタブを閉じてから）")
                        else:
                            gui_targets.append(d)
                    if gui_targets:
                        log("[INFO] GUIログイン中...（操作中のタブを閉じる/中止で停止）")
                        start(run_parallel_gui_login, gui_targets, "-LOGIN_DONE-")

            elif event == "コマンド実行":
                for dev in targets:
                    log(f"===== {dev['name']} =====")
                    log(try_login_and_execute(dev))

            elif event == "コンフィグ取得":
                if not can_start_gui_op():
                    continue
                log("[INFO] コンフィグ取得中...（操作中のタブを閉じる/中止で停止）")
                start(run_parallel_get_config, targets, "-CFG_DONE-")

        # ---------------- バックグラウンド完了 ----------------
        elif event in ("-LOGIN_DONE-", "-CFG_DONE-"):
            run_id, status, data = values[event]

            if status == "error":
                log(f"[ERROR] 処理中に予期しないエラー: {data}")
            elif event == "-LOGIN_DONE-":
                for name, driver, message in data:
                    if driver:
                        gui_drivers[name] = driver
                    log(message)
            else:
                for _, message in data:
                    log(message)

            # 古い（応答なし扱いにした）処理の完了では、新しい処理の状態を壊さない
            if run_id == state["run_id"]:
                state["busy"] = False
                window["中止"].update(disabled=True)

    window.close()


if __name__ == "__main__":
    main_gui()
