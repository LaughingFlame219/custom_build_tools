"""機器編集 / 設定編集画面（ログイン・コンフィグ取得は main.py に統合）"""
try:
    import FreeSimpleGUI as sg
except ImportError:
    import PySimpleGUI as sg

from config_editor import load_devices, save_devices, load_settings, save_settings


# ---------------------------------------------------------
# 設定画面
# ---------------------------------------------------------
def settings_editor_gui():
    sg.theme("SystemDefault")
    settings = load_settings() or {}

    layout = [
        [sg.Text("設定")],
        [sg.Checkbox("ログ保存を有効にする", default=settings.get("log_enabled", True), key="log_enabled")],
        [sg.Checkbox("ログにタイムスタンプを付ける", default=settings.get("log_timestamp", True), key="log_timestamp")],
        [sg.Checkbox("GUIログインで起動済みの Edge を再利用する（新しいタブで開く）",
                     default=settings.get("reuse_browser", True), key="reuse_browser")],
        [sg.Button("保存"), sg.Button("キャンセル")],
    ]
    win = sg.Window("Settings Editor", layout)

    while True:
        event, values = win.read()
        if event in (sg.WIN_CLOSED, "キャンセル"):
            break
        if event == "保存":
            # 他のキー（tterm_pro_path など）を消さないよう更新のみ
            settings["log_enabled"] = values["log_enabled"]
            settings["log_timestamp"] = values["log_timestamp"]
            settings["reuse_browser"] = values["reuse_browser"]
            save_settings(settings)
            break

    win.close()


# ---------------------------------------------------------
# 機器一覧画面
# ---------------------------------------------------------
def device_editor_gui():
    sg.theme("SystemDefault")
    devices = load_devices()

    def names():
        return [d["name"] for d in devices]

    layout = [
        [sg.Text("機器一覧")],
        [sg.Listbox(names(), size=(30, 10), key="device_list")],
        [sg.Button("追加"), sg.Button("編集"), sg.Button("削除"),
         sg.Button("設定"), sg.Button("閉じる")],
    ]
    window = sg.Window("Device Editor", layout)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "閉じる"):
            break

        selected = values["device_list"]

        if event == "追加":
            open_device_edit_window(None, devices)
        elif event == "編集" and selected:
            open_device_edit_window(names().index(selected[0]), devices)
        elif event == "削除" and selected:
            if sg.popup_yes_no(f"{selected[0]} を削除しますか？") == "Yes":
                devices.pop(names().index(selected[0]))
                save_devices(devices)
        elif event == "設定":
            settings_editor_gui()

        window["device_list"].update(names())   # 追加/編集/削除の結果を毎回反映

    window.close()


# ---------------------------------------------------------
# 機器編集画面
# ---------------------------------------------------------
def open_device_edit_window(index, devices):
    if index is None:
        device = {"name": "", "host": "", "username": "", "password": "",
                  "enable_password": "", "type": "cisco", "vdom": "", "protocol": "https"}
    else:
        device = devices[index]

    layout = [
        [sg.Text("名前", size=(16, 1)), sg.Input(device.get("name", ""), key="name")],
        [sg.Text("ホスト", size=(16, 1)), sg.Input(device.get("host", ""), key="host")],
        [sg.Text("ユーザ", size=(16, 1)), sg.Input(device.get("username", ""), key="username")],
        [sg.Text("パスワード", size=(16, 1)),
         sg.Input(device.get("password", ""), key="password", password_char="*")],
        [sg.Text("Enable Password", size=(16, 1)),
         sg.Input(device.get("enable_password", ""), key="enable_password", password_char="*")],
        [sg.Text("種別", size=(16, 1)),
         sg.Combo(["cisco", "fortigate", "paloalto"], default_value=device.get("type", "cisco"),
                  key="type", readonly=True)],
        [sg.Text("VDOM (FortiGate)", size=(16, 1)), sg.Input(device.get("vdom", ""), key="vdom")],
        [sg.Text("プロトコル", size=(16, 1)),
         sg.Combo(["https", "http"], default_value=device.get("protocol", "https"),
                  key="protocol", readonly=True)],
        [sg.Button("保存"), sg.Button("キャンセル")],
    ]
    win = sg.Window("Device Editor - Edit", layout)

    while True:
        event, values = win.read()
        if event in (sg.WIN_CLOSED, "キャンセル"):
            break

        if event == "保存":
            name = values["name"].strip()
            host = values["host"].strip()
            if not name or not host:
                sg.popup("名前とホストは必須です")
                continue
            others = [d["name"] for i, d in enumerate(devices) if i != index]
            if name in others:
                sg.popup("同じ名前の機器が既にあります")
                continue

            new_device = dict(device)           # backup_scope など未表示のキーを維持
            new_device.update({
                "name": name,
                "host": host,
                "username": values["username"],
                "password": values["password"],
                "enable_password": values["enable_password"],
                "type": values["type"],
                "vdom": values["vdom"],
                "protocol": values["protocol"],
            })

            if index is None:
                devices.append(new_device)
            else:
                devices[index] = new_device
            save_devices(devices)
            break

    win.close()
