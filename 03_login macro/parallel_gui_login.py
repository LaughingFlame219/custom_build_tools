from concurrent.futures import ThreadPoolExecutor, as_completed
from gui_login import open_fortigate_gui
from gui_login_palo import open_paloalto_gui

MAX_GUI_WORKERS = 3

def gui_login_worker(device):
    dev_type = device["type"]
    protocol = device.get("protocol", "https") 

    if dev_type == "fortigate":
         return device["name"], open_fortigate_gui(device, protocol)

    elif dev_type == "paloalto":
        return device["name"], open_paloalto_gui(device, protocol)

    else:
         return device["name"], None


def run_parallel_gui_login(devices):
    results = []

    with ThreadPoolExecutor(max_workers=MAX_GUI_WORKERS) as executor:
        futures = [executor.submit(gui_login_worker, dev) for dev in devices]

        for future in as_completed(futures):
            name, result = future.result()
            results.append((name, result))

    return results
