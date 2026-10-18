import PySimpleGUI as sg
from config_editor import load_all_command_sets, save_all_command_sets

def command_editor_gui():
    sg.theme("SystemDefault")

    cmdsets = load_all_command_sets()
    types = list(cmdsets.keys())

    layout = [
        [sg.Text("コマンドセット一覧")],
        [sg.Listbox(types, size=(30, 10), key="type_list")],

        [
            sg.Button("追加"),
            sg.Button("削除"),
            sg.Button("編集"),
            sg.Button("終了")
        ]
    ]

    window = sg.Window("Command Editor", layout)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "終了"):
            break

        # ---------------------------------------------------------
        # ★ 追加
        # ---------------------------------------------------------
        if event == "追加":
            new_type = sg.popup_get_text("新しいコマンドセット名を入力してください")
            if new_type:
                if new_type in cmdsets:
                    sg.popup("既に存在します")
                else:
                    cmdsets[new_type] = {
                        "enable": False,
                        "vdom_required": False,
                        "commands": []
                    }
                    save_all_command_sets(cmdsets)
                    window["type_list"].update(list(cmdsets.keys()))

        # ---------------------------------------------------------
        # ★ 削除
        # ---------------------------------------------------------
        if event == "削除":
            selected = values["type_list"]
            if not selected:
                sg.popup("削除する項目を選択してください")
                continue

            dtype = selected[0]
            if sg.popup_yes_no(f"{dtype} を削除しますか？") == "Yes":
                del cmdsets[dtype]
                save_all_command_sets(cmdsets)
                window["type_list"].update(list(cmdsets.keys()))

        # ---------------------------------------------------------
        # ★ 編集（既存機能）
        # ---------------------------------------------------------
        if event == "編集":
            selected = values["type_list"]
            if selected:
                dtype = selected[0]
                open_command_edit_window(dtype, cmdsets)
                save_all_command_sets(cmdsets)
                window["type_list"].update(list(cmdsets.keys()))

    window.close()


def open_command_edit_window(dtype, cmdsets):
    data = cmdsets[dtype]

    enable_flag = data.get("enable", False)
    vdom_flag = data.get("vdom_required", False)
    commands_text = "\n".join(data.get("commands", []))

    layout = [
        [sg.Text(f"種別: {dtype}")],
        [sg.Checkbox("enable 必要 (Cisco)", default=enable_flag, key="enable")],
        [sg.Checkbox("VDOM 必要 (FortiGate)", default=vdom_flag, key="vdom_required")],
        [sg.Text("コマンド（改行区切り）")],
        [sg.Multiline(commands_text, size=(60, 10), key="commands")],
        [sg.Button("保存"), sg.Button("キャンセル")]
    ]

    win = sg.Window("Command Editor - Edit", layout)

    while True:
        event, values = win.read()
        if event in (sg.WIN_CLOSED, "キャンセル"):
            break

        if event == "保存":
            cmdsets[dtype] = {
                "enable": values["enable"],
                "vdom_required": values["vdom_required"],
                "commands": values["commands"].splitlines()
            }
            break

    win.close()
