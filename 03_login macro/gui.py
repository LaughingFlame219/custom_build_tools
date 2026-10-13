import PySimpleGUI as sg
from config_editor import load_devices, save_devices, load_settings, save_settings


# ---------------------------------------------------------
# 設定画面（ログ保存 ON/OFF ＋ ログのタイムスタンプ ON/OFF）
# ---------------------------------------------------------
def settings_editor_gui():
    sg.theme("SystemDefault")

    settings = load_settings()

    layout = [
        [sg.Text("設定")],
        [sg.Checkbox("ログ保存を有効にする", default=settings.get("log_enabled", True), key="log_enabled")],
        [sg.Checkbox("ログにタイムスタンプを付ける", default=settings.get("log_timestamp", True), key="log_timestamp")],
        [sg.Button("保存"), sg.Button("キャンセル")]
    ]

    win = sg.Window("Settings Editor", layout)

    while True:
        event, values = win.read()
        if event in (sg.WIN_CLOSED, "キャンセル"):
            break

        if event == "保存":
            new_settings = {
                "log_enabled": values["log_enabled"],
                "log_timestamp": values["log_timestamp"],
            }
            save_settings(new_settings)
            break

    win.close()


# ---------------------------------------------------------
# デバイス一覧画面
# ---------------------------------------------------------
def device_editor_gui():
    sg.theme("SystemDefault")

    devices = load_devices()
    names = [d["name"] for d in devices]

    layout = [
        [sg.Text("機器一覧")],
        [sg.Listbox(names, size=(30, 10), key="device_list")],
        [sg.Button("追加"), sg.Button("編集"), sg.Button("削除"), sg.Button("設定"), sg.Button("終了")]
    ]

    window = sg.Window("Device Editor", layout)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "終了"):
            break

        if event == "追加":
            open_device_edit_window(None, devices)

        if event == "編集":
            selected = values["device_list"]
            if selected:
                idx = names.index(selected[0])
                open_device_edit_window(idx, devices)

        if event == "削除":
            selected = values["device_list"]
            if selected:
                idx = names.index(selected[0])
                devices.pop(idx)
                save_devices(devices)
                names = [d["name"] for d in devices]
                window["device_list"].update(names)

        if event == "設定":
            settings_editor_gui()

    window.close()


# ---------------------------------------------------------
# デバイス編集画面
# ---------------------------------------------------------
def open_device_edit_window(index, devices):
    if index is None:
        device = {
            "name": "",
            "host": "",
            "username": "",
            "password": "",
            "enable_password": "",
            "type": "cisco",
            "vdom": ""
        }
    else:
        device = devices[index]

    layout = [
        [sg.Text("名前"), sg.Input(device["name"], key="name")],
        [sg.Text("ホスト"), sg.Input(device["host"], key="host")],
        [sg.Text("ユーザ"), sg.Input(device["username"], key="username")],
        [sg.Text("パスワード"), sg.Input(device["password"], key="password")],
        [sg.Text("Enable Password"), sg.Input(device.get("enable_password", ""), key="enable_password")],
        [sg.Text("種別"), sg.Combo(["cisco", "fortigate", "paloalto"], default_value=device["type"], key="type")],
        [sg.Text("VDOM (FortiGate)"), sg.Input(device.get("vdom", ""), key="vdom")],
        [sg.Button("保存"), sg.Button("キャンセル")]
    ]

    win = sg.Window("Device Editor - Edit", layout)

    while True:
        event, values = win.read()
        if event in (sg.WIN_CLOSED, "キャンセル"):
            break

        if event == "保存":
            new_device = {
                "name": values["name"],
                "host": values["host"],
                "username": values["username"],
                "password": values["password"],
                "enable_password": values["enable_password"],
                "type": values["type"],
                "vdom": values["vdom"]
            }

            if index is None:
                devices.append(new_device)
            else:
                devices[index] = new_device

            save_devices(devices)
            break

    win.close()
