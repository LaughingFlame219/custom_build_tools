import PySimpleGUI as sg
from config_editor import load_devices
from ssh_core import try_login_only, try_login_and_execute
from gui import device_editor_gui
from command_editor import command_editor_gui
from parallel_gui_login import run_parallel_gui_login
from fortigate_get_config import fortigate_get_config
from paloalto_get_config import paloalto_get_config
from gui_login import open_fortigate_gui
from gui_login_palo import open_paloalto_gui


# ★ GUIログイン後の driver を保持する辞書
gui_drivers = {}   # { "device_name": driver }


def main_gui():
    sg.theme("SystemDefault")

    devices = load_devices()
    names = [d["name"] for d in devices]

    layout = [
        [sg.Text("機器一覧")],
        [sg.Listbox(names, size=(30, 10), key="target_devices", select_mode="extended")],
        [sg.Text("ログイン方式")],
        [sg.Radio("CLI（SSH / TeraTerm）", "LOGIN_TYPE", default=True, key="login_cli")],
        [sg.Radio("GUI（HTTPS / Web）", "LOGIN_TYPE", key="login_gui")],

        [
            sg.Button("ログイン"),
            sg.Button("コマンド実行"),
            sg.Button("機器編集"),
            sg.Button("コマンド編集"),
            sg.Button("コンフィグ取得"),
            sg.Button("終了")
        ]
    ]

    window = sg.Window("Network Automation Tool", layout)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "終了"):
            break

        # ---------------------------------------------------------
        # 機器編集
        # ---------------------------------------------------------
        if event == "機器編集":
            device_editor_gui()
            devices = load_devices()
            names = [d["name"] for d in devices]
            window["target_devices"].update(names)

        # ---------------------------------------------------------
        # コマンド編集
        # ---------------------------------------------------------
        if event == "コマンド編集":
            command_editor_gui()

        # ---------------------------------------------------------
        # ログイン
        # ---------------------------------------------------------
        if event == "ログイン":
            selected = values["target_devices"]
            if not selected:
                print("[WARN] 実行対象の機器が選択されていません")
                continue

            targets = [d for d in devices if d["name"] in selected]

            # CLIログイン
            if values["login_cli"]:
                for dev in targets:
                    print(f"\n===== {dev['name']} =====")
                    print(try_login_only(dev))

            # GUIログイン（並列）
            elif values["login_gui"]:
                results = run_parallel_gui_login(targets)
            
                # results は [(name, driver)] の形式
                if not results or len(results) == 0:
                    print("[ERROR] GUIログインに失敗しました")
                    continue
            
                dev_name, driver = results[0]
            
                if not driver:
                    print("[ERROR] GUIログインに失敗しました")
                    continue
            
                # ★ driver を保存する
                gui_drivers[dev_name] = driver


        # ---------------------------------------------------------
        # コマンド実行
        # ---------------------------------------------------------
        if event == "コマンド実行":
            selected = values["target_devices"]
            if not selected:
                print("[WARN] 実行対象の機器が選択されていません")
                continue

            targets = [d for d in devices if d["name"] in selected]

            for dev in targets:
                print(f"\n===== {dev['name']} =====")
                print(try_login_and_execute(dev))

        
# ---------------------------------------------------------
# コンフィグ取得（コンフィグ取得ボタン押下 → GUIログイン → バックアップ）
# ---------------------------------------------------------
        if event == "コンフィグ取得":
            selected = values["target_devices"]
            if not selected:
                print("[WARN] 実行対象の機器が選択されていません")
                continue
        
            targets = [d for d in devices if d["name"] in selected]
        
            for dev in targets:
                print(f"\n===== {dev['name']} =====")
        
                if dev["type"] == "fortigate":
                    # ★ コンフィグ取得用に、その場で GUIログイン
                    driver = open_fortigate_gui(dev)
                    if not driver:
                        print("[ERROR] GUIログインに失敗しました")
                        continue

                    # ★ コンフィグ取得
                    result = fortigate_get_config(driver, dev["host"])
                    print(result)

                if dev["type"] == "paloalto":
                    driver = open_paloalto_gui(dev)   # FortiGate と同じ構造で作る
                    if not driver:
                        print("[ERROR] GUIログインに失敗しました")
                        continue

                    result = paloalto_get_config(driver, dev["host"])
                    print(result)
                
                    try:
                        driver.quit()
                    except:
                        pass

                else:
                    print(f"[INFO] {dev['name']} はコンフィグ取得未対応です")
                
    window.close()


if __name__ == "__main__":
    main_gui()
