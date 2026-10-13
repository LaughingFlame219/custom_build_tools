import PySimpleGUI as sg
from config_editor import load_devices
from ssh_core import try_login_only, try_login_and_execute
from gui import device_editor_gui
from command_editor import command_editor_gui

def main_gui():
    sg.theme("SystemDefault")

    devices = load_devices()
    names = [d["name"] for d in devices]

    layout = [
        [sg.Text("機器一覧")],
        [sg.Listbox(names, size=(30, 10), key="target_devices")],
        [
            sg.Button("ログインのみ"),
            sg.Button("実行"),
            sg.Button("機器編集"),
            sg.Button("コマンド編集"),
            sg.Button("終了")
        ]
    ]

    window = sg.Window("Network Automation Tool", layout)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "終了"):
            break

        if event == "機器編集":
            device_editor_gui()
            devices = load_devices()
            names = [d["name"] for d in devices]
            window["target_devices"].update(names)

        if event == "コマンド編集":
            command_editor_gui()

        if event == "ログインのみ":
            selected = values["target_devices"]
            if not selected:
                print("[WARN] 実行対象の機器が選択されていません")
                continue

            targets = [d for d in devices if d["name"] in selected]

            for dev in targets:
                print(f"\n===== {dev['name']} =====")
                print(try_login_only(dev))

        if event == "実行":
            selected = values["target_devices"]
            if not selected:
                print("[WARN] 実行対象の機器が選択されていません")
                continue

            targets = [d for d in devices if d["name"] in selected]

            for dev in targets:
                print(f"\n===== {dev['name']} =====")
                print(try_login_and_execute(dev))

    window.close()


if __name__ == "__main__":
    main_gui()
