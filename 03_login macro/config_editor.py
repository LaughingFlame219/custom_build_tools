import yaml
import os

DEVICES_PATH = "config/devices.yaml"
COMMANDS_PATH = "config/commands.yaml"
SETTINGS_PATH = "config/settings.yaml"


# -------------------------
# devices.yaml 読み書き
# -------------------------
def load_devices():
    if not os.path.exists(DEVICES_PATH):
        return []

    with open(DEVICES_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("devices", [])


def save_devices(devices):
    data = {"devices": devices}
    with open(DEVICES_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True)


def add_device(device):
    devices = load_devices()
    devices.append(device)
    save_devices(devices)


def update_device(index, new_device):
    devices = load_devices()
    devices[index] = new_device
    save_devices(devices)


def delete_device(index):
    devices = load_devices()
    devices.pop(index)
    save_devices(devices)


# -------------------------
# commands.yaml 読み書き
# -------------------------
def load_all_command_sets():
    with open(COMMANDS_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def save_all_command_sets(data):
    with open(COMMANDS_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True)


def load_command_set(device_type):
    data = load_all_command_sets()
    return data.get(device_type, {})


# -------------------------
# settings.yaml 読み書き（追加）
# -------------------------
def load_settings():
    if not os.path.exists(SETTINGS_PATH):
        return {"log_timestamp": True}

    with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def save_settings(settings):
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(settings, f, allow_unicode=True)
