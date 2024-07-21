import os
import json
import base64
import sys
import msvcrt
import logging
import string
import binascii
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

try:
    import win32wnet
    import win32netcon
    import win32net
    import win32api
except ImportError as e:
    print(f"Import error: {e}")

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Paths to JSON files
USERS_FILE = "users.json"
CONFIG_FILE = "servers_credentials.json"
DEFAULT_PRESET_FILE = "mappings.json"


def disconnect_all_smb_shares():
    print("Disconnecting all SMB shares")
    os.system("net use * /d /y")


def add_user_directory(username):
    print(f"Adding user directory for {username}")
    user_dir = os.path.join("users", username)
    os.makedirs(user_dir, exist_ok=True)
    # Create default JSON files for the user if they do not already exist
    servers_credentials_path = os.path.join(user_dir, "servers_credentials.json")
    mappings_path = os.path.join(user_dir, "mappings.json")

    if not os.path.exists(servers_credentials_path):
        print(f"Creating default servers_credentials.json for {username}")
        write_config(servers_credentials_path, [], is_absolute_path=True)

    if not os.path.exists(mappings_path):
        print(f"Creating default mappings.json for {username}")
        write_config(
            mappings_path,
            [{"preset_name": "default", "mappings": []}],
            is_absolute_path=True,
        )


@app.route("/create_user", methods=["GET", "POST"])
def create_user():
    print("Accessing /create_user endpoint")
    if request.method == "POST":
        data = request.json
        username = data.get("username")
        password = data.get("password")
        print(f"Creating user: {username}")

        # Ensure the global USERS_FILE path is used
        users = read_config(USERS_FILE, is_absolute_path=True)
        if next((u for u in users if u["username"] == username), None):
            print(f"User {username} already exists")
            return jsonify({"status": "error", "message": "User already exists"})

        users.append({"username": username, "password": password})
        write_config(USERS_FILE, users, is_absolute_path=True)

        # Create a directory for the new user
        add_user_directory(username)

        return jsonify({"status": "success"})
    return render_template("create_user.html")


def get_user_directory():
    username = session.get("username")
    if username:
        print(f"Getting directory for user: {username}")
        return os.path.join("users", username)
    print("No user in session")
    return None


def read_config(file_name, is_absolute_path=False):
    print(f"Reading config from {file_name}, is_absolute_path={is_absolute_path}")
    if not is_absolute_path:
        user_dir = get_user_directory()
        if user_dir:
            file_path = os.path.join(user_dir, file_name)
        else:
            file_path = file_name  # Use global path if no user is logged in
    else:
        file_path = file_name

    if not os.path.exists(file_path):
        print(f"Config file {file_path} does not exist")
        return []
    with open(file_path, "r") as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            print(f"Error decoding JSON from {file_path}")
            return []


def write_config(file_path, config, is_absolute_path=False):
    print(f"Writing config to {file_path}, is_absolute_path={is_absolute_path}")
    if not is_absolute_path:
        user_dir = get_user_directory()
        if user_dir:
            file_path = os.path.join(user_dir, file_path)

    with open(file_path, "w") as file:
        json.dump(config, file)


@app.route("/")
def index():
    print("Accessing / endpoint")
    if "username" in session:
        print("User in session, redirecting to /list_shares")
        return redirect(url_for("list_shares"))
    print("No user in session, redirecting to /login")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    print("Accessing /login endpoint")
    if request.method == "POST":
        data = request.json
        username = data.get("username")
        password_b64 = data.get("password")
        print(f"Attempting login for user: {username}")

        try:
            if len(password_b64) % 4 != 0:
                raise ValueError("Invalid password length")
            password = base64.b64decode(password_b64).decode()
        except (TypeError, binascii.Error, UnicodeDecodeError, ValueError) as e:
            print(f"Error decoding password: {e}")
            return jsonify({"status": "error", "message": "Invalid password format"})

        users = read_config(USERS_FILE)

        user = next((u for u in users if u["username"] == username), None)
        if user:
            try:
                stored_password = base64.b64decode(user["password"]).decode()
                if stored_password == password:
                    print(f"Login successful for user: {username}")
                    session["username"] = username
                    add_user_directory(username)
                    disconnect_all_smb_shares()
                    mount_disks_for_user()
                    return jsonify({"status": "success"})
                else:
                    print("Invalid credentials")
                    return jsonify(
                        {"status": "error", "message": "Invalid credentials"}
                    )
            except (TypeError, binascii.Error, UnicodeDecodeError) as e:
                print(f"Error decoding stored password: {e}")
                return jsonify(
                    {
                        "status": "error",
                        "message": "Invalid password format in stored data",
                    }
                )

        print("Invalid credentials")
        return jsonify({"status": "error", "message": "Invalid credentials"})

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    print("Logging out user")
    disconnect_all_smb_shares()
    session.pop("username", None)
    return jsonify({"status": "success"})


@app.route("/list_shares")
def list_shares():
    print("Accessing /list_shares endpoint")
    if "username" not in session:
        print("No user in session, redirecting to /login")
        return redirect(url_for("login"))
    return render_template("list_shares.html")


@app.route("/config_servers")
def config_servers():
    print("Accessing /config_servers endpoint")
    if "username" not in session:
        print("No user in session, redirecting to /login")
        return redirect(url_for("login"))
    return render_template("config_servers.html")


@app.route("/get_users", methods=["GET"])
def get_users():
    print("Accessing /get_users endpoint")
    users = read_config(USERS_FILE)
    return jsonify({"status": "success", "users": users})


@app.route("/delete_user", methods=["POST"])
def delete_user():
    print("Accessing /delete_user endpoint")
    data = request.json
    username = data.get("username")
    print(f"Deleting user: {username}")

    users = read_config(USERS_FILE)
    users = [u for u in users if u["username"] != username]
    write_config(USERS_FILE, users)
    return jsonify({"status": "success"})


@app.route("/get_servers", methods=["GET"])
def get_servers():
    print("Accessing /get_servers endpoint")
    config = read_config("servers_credentials.json")
    return jsonify(config)


@app.route("/add_server", methods=["POST"])
def add_server():
    print("Accessing /add_server endpoint")
    data = request.json
    username = data.get("username")
    password = data.get("password")
    encoded_password = base64.b64encode(password.encode()).decode()
    server_ip = data.get("server_ip")
    nickname = data.get("nickname")
    print(f"Adding server: {server_ip} for user: {username}")

    response = os.system(f"ping -n 1 {server_ip}")
    if response != 0:
        print(f"Server {server_ip} is not reachable")
        return jsonify(
            {"status": "error", "message": "Server is not reachable on the network"}
        )

    try:
        net_resource = win32wnet.NETRESOURCE()
        net_resource.lpRemoteName = f"\\\\{server_ip}"
        net_resource.lpProvider = None
        net_resource.dwType = win32netcon.RESOURCETYPE_DISK

        win32wnet.WNetAddConnection2(net_resource, password, username)
    except Exception as e:
        print(f"Error adding server connection: {e}")
        return jsonify({"status": "error", "message": str(e)})

    config = read_config("servers_credentials.json")
    config.append(
        {
            "username": username,
            "password": encoded_password,
            "server_ip": server_ip,
            "nickname": nickname,
        }
    )
    write_config("servers_credentials.json", config)
    return jsonify({"status": "success"})


@app.route("/delete_server", methods=["POST"])
def delete_server():
    print("Accessing /delete_server endpoint")
    data = request.json
    server_ip = data.get("server_ip")
    print(f"Deleting server: {server_ip}")

    config = read_config("servers_credentials.json")
    config = [server for server in config if server["server_ip"] != server_ip]
    write_config("servers_credentials.json", config)
    return jsonify({"status": "success"})


@app.route("/list_all_shares", methods=["GET"])
def list_all_shares():
    print("Accessing /list_all_shares endpoint")
    if "username" not in session:
        print("User not authenticated")
        return jsonify({"status": "error", "message": "User not authenticated"}), 401

    config = read_config(CONFIG_FILE)
    all_shares = []
    for server in config:
        server_ip = server["server_ip"]
        username = server["username"]
        password = base64.b64decode(server["password"]).decode()
        nickname = server.get("nickname", "")  # Ensure nickname is included

        try:
            net_resource = win32wnet.NETRESOURCE()
            net_resource.lpRemoteName = f"\\\\{server_ip}"
            net_resource.lpProvider = None
            net_resource.dwType = win32netcon.RESOURCETYPE_DISK

            win32wnet.WNetAddConnection2(net_resource, password, username)
        except Exception as e:
            print(f"Error connecting to server {server_ip}: {e}")
            continue

        try:
            shares, _, _ = win32net.NetShareEnum(server_ip, 1)
            for share in shares:
                if share["netname"].upper() != "IPC$":  # Exclude IPC$ shares
                    all_shares.append(
                        {
                            "server_ip": server_ip,
                            "nickname": nickname,
                            "name": share["netname"],
                            "type": share["type"],
                            "remark": share["remark"],
                        }
                    )
        except Exception as e:
            print(f"Error enumerating shares on server {server_ip}: {e}")
            continue

    return jsonify({"status": "success", "shares": all_shares})


@app.route("/list_mounted_shares", methods=["GET"])
def list_mounted_shares():
    print("Accessing /list_mounted_shares endpoint")
    config = read_config(CONFIG_FILE)
    mounted_shares = []
    drive_mappings = get_drive_mappings()
    for server in config:
        server_ip = server["server_ip"]
        nickname = server["nickname"]
        for remote_name, drive_letter in drive_mappings.items():
            if remote_name.lower().startswith(f"\\\\{server_ip.lower()}\\"):
                share_name = remote_name.split(f"\\\\{server_ip}\\")[1]
                mounted_shares.append(
                    {
                        "server_ip": server_ip,
                        "nickname": nickname,
                        "name": share_name,
                        "drive_letter": drive_letter.upper(),  # Ensure drive letter is in upper case
                    }
                )
    return jsonify(mounted_shares)


@app.route("/mount_share", methods=["POST"])
def mount_share():
    print("Accessing /mount_share endpoint")
    data = request.json
    username = data.get("username")
    password = base64.b64decode(data.get("password")).decode()
    server_ip = data.get("server_ip")
    share_name = data.get("share_name")
    new_drive_letter = data.get("drive_letter")
    print(f"Mounting share {share_name} on server {server_ip} for user {username}")

    try:
        network_path = f"\\\\{server_ip}\\{share_name}"

        # Check if the share is already mounted
        drive_mappings = get_drive_mappings()
        current_drive_letter = None
        for remote_name, drive_letter in drive_mappings.items():
            if remote_name.lower() == network_path.lower():
                current_drive_letter = drive_letter
                break

        if current_drive_letter:
            print(
                f"Share {network_path} already mounted, unmounting {current_drive_letter}"
            )
            win32wnet.WNetCancelConnection2(f"{current_drive_letter}", 0, 0)

        net_resource = win32wnet.NETRESOURCE()
        net_resource.lpRemoteName = network_path
        net_resource.lpLocalName = f"{new_drive_letter}:"
        net_resource.lpProvider = None
        net_resource.dwType = win32netcon.RESOURCETYPE_DISK

        win32wnet.WNetAddConnection2(net_resource, password, username)
        response = {"status": "success"}
    except Exception as e:
        print(f"Error mounting share: {e}")
        response = {"output": str(e), "status": "error"}
    return jsonify(response)


@app.route("/unmount_share", methods=["POST"])
def unmount_share():
    print("Accessing /unmount_share endpoint")
    data = request.json
    drive_letter = data.get(
        "drive_letter"
    ).upper()  # Ensure drive letter is in upper case
    print(f"Unmounting share on drive {drive_letter}")

    try:
        win32wnet.WNetCancelConnection2(f"{drive_letter}", 0, 0)
        response = {"status": "success"}
    except win32wnet.error as e:
        error_code, _, error_message = e.args
        print(f"Error unmounting share: {error_message}")
        response = {
            "output": f"({error_code}, 'WNetCancelConnection2', '{error_message}')",
            "status": "error",
        }
    return jsonify(response)


@app.route("/available_drive_letters", methods=["GET"])
def available_drive_letters():
    print("Accessing /available_drive_letters endpoint")
    try:
        all_drive_letters = set(string.ascii_uppercase)
        used_drive_letters = set(
            [
                drive[0].upper()
                for drive in win32api.GetLogicalDriveStrings().split("\x00")[:-1]
            ]
        )
        available_drive_letters = sorted(list(all_drive_letters - used_drive_letters))

        response = {"letters": available_drive_letters, "status": "success"}
    except Exception as e:
        print(f"Error getting available drive letters: {e}")
        response = {"output": str(e), "status": "error"}
    return jsonify(response)


@app.route("/save_mapping_preset", methods=["POST"])
def save_mapping_preset():
    print("Accessing /save_mapping_preset endpoint")
    drive_mappings = get_drive_mappings()
    new_mappings = []
    for remote_name, drive_letter in drive_mappings.items():
        parts = remote_name.split("\\")
        if len(parts) >= 4:
            server_ip = parts[2]
            share_name = parts[3]
            new_mappings.append(
                {
                    "server_ip": server_ip,
                    "share_name": share_name,
                    "drive_letter": drive_letter.rstrip(":"),
                }
            )

    write_config(
        DEFAULT_PRESET_FILE, [{"preset_name": "default", "mappings": new_mappings}]
    )
    return jsonify({"status": "success"})


def get_drive_mappings():
    print("Getting drive mappings")
    drive_mappings = {}
    drives = win32api.GetLogicalDriveStrings().split("\x00")[:-1]
    for drive in drives:
        try:
            remote_name = win32wnet.WNetGetConnection(drive)
            if remote_name:
                drive_mappings[remote_name.lower()] = (
                    drive.upper()
                )  # Ensure drive letter is in upper case
        except win32wnet.error as e:
            print(f"Error getting connection for drive {drive}: {e}")
            continue

    try:
        resume = 0
        while True:
            use_info, _, resume = win32net.NetUseEnum(None, 1, resume)
            for info in use_info:
                remote_name = info["remote"]
                local_name = info["local"]
                if local_name:
                    drive_mappings[remote_name.lower()] = (
                        local_name.upper()
                    )  # Ensure drive letter is in upper case
            if resume == 0:
                break
    except win32net.error as e:
        print(f"Error enumerating network uses: {e}")
        pass

    return drive_mappings


@app.route("/load_default", methods=["POST"])
def mount_disks():
    print("Accessing /load_default endpoint")
    return mount_disks_for_user()


def mount_disks_for_user():
    print("Mounting disks for user")
    try:
        user_dir = get_user_directory()
        print(f"User directory: {user_dir}")
        if not user_dir:
            print("No user directory found")
            return jsonify({"status": "error", "message": "No user directory found"})

        mappings_file = os.path.join(user_dir, "mappings.json")
        print(f"Mappings file path: {mappings_file}")
        if not os.path.exists(mappings_file):
            print("Mappings file not found")
            return jsonify({"status": "error", "message": "Mappings file not found"})

        config_file = os.path.join(user_dir, "servers_credentials.json")
        print(f"Config file path: {config_file}")
        if not os.path.exists(config_file):
            print("Server credentials file not found")
            return jsonify(
                {"status": "error", "message": "Server credentials file not found"}
            )

        mappings = read_config(mappings_file, is_absolute_path=True)
        print(f"Mappings content: {mappings}")
        if not mappings or not mappings[0].get("mappings"):
            print("Mappings file is empty or invalid")
            return jsonify(
                {"status": "error", "message": "Mappings file is empty or invalid"}
            )

        mappings_list = mappings[0].get("mappings", [])
        print(f"Mappings list: {mappings_list}")
        servers = read_config(config_file, is_absolute_path=True)
        print(f"Servers content: {servers}")

        all_results = []

        for mapping in mappings_list:
            server_ip = mapping["server_ip"]
            share_name = mapping["share_name"]
            drive_letter = mapping["drive_letter"]
            print(
                f"Processing mapping: server_ip={server_ip}, share_name={share_name}, drive_letter={drive_letter}"
            )

            # Find server credentials
            server = next((s for s in servers if s["server_ip"] == server_ip), None)
            print(f"Server found: {server}")
            if not server:
                all_results.append(
                    {
                        "server_ip": server_ip,
                        "status": "error",
                        "message": "Server not found in configuration",
                    }
                )
                continue

            username = server["username"]
            password = base64.b64decode(server["password"]).decode()
            print(f"Credentials: username={username}, password={password}")

            # Attempt to mount the share
            result = mount_share_with_args(
                server_ip, share_name, username, password, drive_letter
            )
            print(f"Mount result: {result}")
            all_results.append(result)

        print(f"All results: {all_results}")
        return jsonify({"status": "success", "results": all_results})
    except Exception as e:
        print(f"Exception occurred: {e}")
        return jsonify({"status": "error", "message": str(e)})


def mount_share_with_args(server_ip, share_name, username, password, new_drive_letter):
    try:
        network_path = f"\\\\{server_ip}\\{share_name}"
        print(f"Network path: {network_path}")

        # Check if the share is already mounted
        drive_mappings = get_drive_mappings()
        print(f"Drive mappings: {drive_mappings}")
        current_drive_letter = None
        for remote_name, drive_letter in drive_mappings.items():
            if remote_name.lower() == network_path.lower():
                current_drive_letter = drive_letter
                break

        print(f"Current drive letter: {current_drive_letter}")
        if current_drive_letter:
            win32wnet.WNetCancelConnection2(f"{current_drive_letter}", 0, 0)
            print(f"Cancelled connection for drive letter: {current_drive_letter}")

        net_resource = win32wnet.NETRESOURCE()
        net_resource.lpRemoteName = network_path
        net_resource.lpLocalName = f"{new_drive_letter}:"
        net_resource.lpProvider = None
        net_resource.dwType = win32netcon.RESOURCETYPE_DISK

        win32wnet.WNetAddConnection2(net_resource, password, username)
        print(f"Mounted {network_path} to {new_drive_letter}:")
        return {"status": "success"}
    except Exception as e:
        print(f"Error mounting share: {e}")
        return {"output": str(e), "status": "error"}


LOCK_FILE = "app.lock"


def create_lock_file():
    global lock_file
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        return
    lock_file = open(LOCK_FILE, "w")
    try:
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        print("Lock file created and locked")
    except IOError:
        print("Another instance of the program is already running.")
        sys.exit(1)


def remove_lock_file():
    global lock_file
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        return
    try:
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        lock_file.close()
        os.remove(LOCK_FILE)
        print("Lock file unlocked and removed")
    except Exception as e:
        print(f"Error removing lock file: {e}")


def setup_logging(log_file="app.log"):
    # Open the log file in write mode to clear its contents
    with open(log_file, "w"):
        pass
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler(sys.stdout)],
    )
    logging.debug("Logging initialized")


class LoggerWriter:
    def __init__(self, logger, level):
        self.logger = logger
        self.level = level

    def write(self, message):
        if message != "\n":
            self.logger.log(self.level, message)

    def flush(self):
        pass


def redirect_output_to_log(log_file="app.log"):
    class LoggerWriter:
        def __init__(self, logger, level):
            self.logger = logger
            self.level = level

        def write(self, message):
            if message != "\n":
                self.logger.log(self.level, message)

        def flush(self):
            pass

    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    log = logging.getLogger()
    sys.stdout = LoggerWriter(log, logging.INFO)
    sys.stderr = LoggerWriter(log, logging.ERROR)


if __name__ == "__main__":
    redirect_output_to_log()  # Redirect stdout and stderr to the log file
    setup_logging()  # Configure logging to write to a file and the console

    create_lock_file()  # Create the lock file at startup

    try:
        app.run(
            debug=True, host="0.0.0.0", port=5000, use_reloader=False
        )  # Disable the reloader in debug mode
    finally:
        remove_lock_file()  # Remove the lock file at the end of execution
