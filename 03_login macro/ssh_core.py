import subprocess
from datetime import datetime
import os
import yaml
from config_editor import load_settings

# ---------------------------------------------------------
# TeraTerm のパス自動検出
# ---------------------------------------------------------
def find_teraterm_path():
    candidates = [
        r"C:\Program Files (x86)\teraterm5",
        r"C:\Program Files\teraterm5",
        r"C:\Program Files (x86)\Tera Term",
        r"C:\Program Files\Tera Term",
    ]

    for base in candidates:
        exe = os.path.join(base, "ttermpro.exe")
        macro = os.path.join(base, "ttpmacro.exe")
        if os.path.exists(exe) and os.path.exists(macro):
            return exe, macro

    # settings.yaml にユーザー指定があれば優先
    settings = load_settings()
    exe = settings.get("tterm_pro_path")
    macro = settings.get("tterm_macro_path")
    if exe and macro and os.path.exists(exe) and os.path.exists(macro):
        return exe, macro

    raise FileNotFoundError("TeraTerm の実行ファイルが見つかりません。settings.yaml にパスを指定してください。")


# ---------------------------------------------------------
# パス取得
# ---------------------------------------------------------
try:
    TTERM_PRO, TTERM_MACRO = find_teraterm_path()
except FileNotFoundError as e:
    print(f"[ERROR] {e}")
    TTERM_PRO = ""
    TTERM_MACRO = ""

# ---------------------------------------------------------
# ログファイル名生成（name_host_取得日時.log）
# ---------------------------------------------------------
def build_log_filename(device: dict, settings: dict) -> str:
    log_enabled = settings.get("log_enabled", True)
    if not log_enabled:
        return ""

    os.makedirs("logs", exist_ok=True)

    name = device["name"]
    host = device["host"]
    now = datetime.now().strftime("%Y%m%d-%H%M%S")

    return f"logs/{name}_{host}_{now}.log"


# ---------------------------------------------------------
# TeraTerm を SSHログインだけ起動する（ログインのみ）
# ---------------------------------------------------------
def open_teraterm(device):
    settings = load_settings()
    log_enabled = settings.get("log_enabled", True)

    host = device["host"].strip()
    user = device["username"].strip()
    password = device["password"].strip()

    log_option = ""
    if log_enabled:
        filename = build_log_filename(device, settings)
        log_option = "/log=" + filename

    subprocess.Popen([
        TTERM_PRO,
        f"{host}:22",
        "/ssh",
        "/auth=password",
        f"/user={user}",
        f"/passwd={password}",
        log_option,
        "/W=" + device["name"]
    ])

    return log_option


# ---------------------------------------------------------
# ログインのみ（TeraTermだけ起動）
# ---------------------------------------------------------
def try_login_only(device):
    try:
        open_teraterm(device)
        return "[SUCCESS] TeraTerm を起動しました（ログインのみ）"
    except Exception as e:
        return f"[ERROR] TeraTerm 起動失敗: {e}"


# ---------------------------------------------------------
# commands.yaml を読み込む
# ---------------------------------------------------------
def load_command_set(device_type):
    with open("config/commands.yaml", "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get(device_type, {})


# ---------------------------------------------------------
# TeraTerm 内でコマンド実行（TTLマクロ方式）
# ---------------------------------------------------------
def try_login_and_execute(device):
    settings = load_settings()
    log_enabled = settings.get("log_enabled", True)
    log_timestamp = settings.get("log_timestamp", True)

    host = device["host"].strip()
    user = device["username"].strip()
    password = device["password"].strip()
    dev_type = device["type"]
    enable_pw = device.get("enable_password", "")

    # ログファイル名（絶対パス → TTL用に \\ エスケープ）
    log_filename = ""
    if log_enabled:
        raw_path = build_log_filename(device, settings)
        abs_path = os.path.abspath(raw_path)
        log_filename = abs_path.replace("\\", "\\\\").replace("\n", "")

    ttl_path = "execute_commands.ttl"

    with open(ttl_path, "w", encoding="shift_jis") as f:

        f.write(f"connect '{host}:22 /ssh /auth=password /user={user} /passwd={password}'\n")
        # ---------------------------------------------------------
        # logopen の 0/1/0/1 方式
        # 第2引数が timestamp の ON/OFF
        # ---------------------------------------------------------
        if log_enabled:
            if log_timestamp:
                f.write(f'logopen "{log_filename}" 0 1 0 1\n')  # timestamp ON
            else:
                f.write(f'logopen "{log_filename}" 0 0 0 1\n')  # timestamp OFF

        # Cisco / Palo Alto の初期プロンプト待ち
        if dev_type == "cisco":
            # Cisco: ユーザモード '>' → enable → 特権モード '#'
            f.write("wait '>'\n")
            f.write("sendln 'enable'\n")
            if enable_pw:
                f.write("wait 'Password:'\n")
                f.write(f"sendln '{enable_pw}'\n")
            f.write("wait '#'\n")

        elif dev_type == "paloalto":
            # Palo Alto: 通常モード '>' → configure → コンフィグモード '#'
            f.write("wait '>'\n")

        elif dev_type == "fortigate":
            f.write("wait '#'\n")

        else:
            # その他機器（汎用）
            f.write("wait '#'\n")

        for cmd in load_command_set(dev_type).get("commands", []):
            f.write(f"sendln '{cmd}'\n")
            f.write("wait '#'\n")

        if log_enabled:
            f.write("logclose\n")

        f.write("sendln 'exit'\n")
        f.write("end\n")

    try:
        subprocess.Popen([TTERM_MACRO, ttl_path])
        return "[SUCCESS] commands.yaml のコマンドを実行しました（ログ保存あり）"
    except Exception as e:
        return f"[ERROR] TTL マクロ実行失敗: {e}"
