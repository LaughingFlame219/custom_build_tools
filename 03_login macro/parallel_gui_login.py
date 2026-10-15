from concurrent.futures import ThreadPoolExecutor, as_completed
from gui_login import open_fortigate_gui
from gui_login_palo import open_paloalto_gui

MAX_GUI_WORKERS = 3   # ★ 同時起動ブラウザ数（PCスペックに応じて調整）

def gui_login_worker(device):
    dev_type = device["type"]

    if dev_type == "fortigate":
        return device["name"], open_fortigate_gui(device)

    elif dev_type == "paloalto":
        return device["name"], open_paloalto_gui(device)

    else:
        return device["name"], f"[WARN] {device['name']} は GUIログイン非対応です"


def run_parallel_gui_login(devices):
    results = []

    with ThreadPoolExecutor(max_workers=MAX_GUI_WORKERS) as executor:
        futures = [executor.submit(gui_login_worker, dev) for dev in devices]

        for future in as_completed(futures):
            name, result = future.result()
            results.append((name, result))

    return results
