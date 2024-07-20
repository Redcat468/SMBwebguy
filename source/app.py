from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import os
import json
import base64
import sys
import logging
from logging.handlers import RotatingFileHandler
import datetime
import win32wnet
import win32netcon
import win32net
import win32api
import string
import binascii

# Setup logging
LOG_FILE = 'app.log'
MAX_LOG_LINES = 20000


# Define a custom logging handler
class CustomRotatingFileHandler(RotatingFileHandler):
    def emit(self, record):
        record.msg = f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} - {record.msg}'
        super().emit(record)
        self.truncate_log_file()

    def truncate_log_file(self):
        with open(self.baseFilename, 'r+') as file:
            lines = file.readlines()
            if len(lines) > MAX_LOG_LINES:
                file.seek(0)
                file.writelines(lines[-MAX_LOG_LINES:])
                file.truncate()

# Initialize the rotating file handler
handler = CustomRotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=1)
handler.setFormatter(logging.Formatter('%(message)s'))

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

# Also log to console
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(console_handler)

# Redirect stdout and stderr to the logger
class StreamToLogger:
    def __init__(self, logger, log_level):
        self.logger = logger
        self.log_level = log_level
        self.linebuf = ''

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self.logger.log(self.log_level, line.rstrip())

    def flush(self):
        pass

sys.stdout = StreamToLogger(logger, logging.INFO)
sys.stderr = StreamToLogger(logger, logging.ERROR)

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this to a random secret key

# Paths to JSON files
USERS_FILE = 'users.json'
CONFIG_FILE = 'servers_credentials.json'
DEFAULT_PRESET_FILE = 'mappings.json'

def disconnect_all_smb_shares():
    os.system('net use * /d /y')
    
def add_user_directory(username):
    user_dir = os.path.join('users', username)
    os.makedirs(user_dir, exist_ok=True)
    # Créer des fichiers JSON par défaut pour l'utilisateur s'ils n'existent pas déjà
    servers_credentials_path = os.path.join(user_dir, 'servers_credentials.json')
    mappings_path = os.path.join(user_dir, 'mappings.json')
    
    if not os.path.exists(servers_credentials_path):
        write_config(servers_credentials_path, [], is_absolute_path=True)
    
    if not os.path.exists(mappings_path):
        write_config(mappings_path, [{"preset_name": "default", "mappings": []}], is_absolute_path=True)

@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')

        users = read_config(USERS_FILE)
        if next((u for u in users if u['username'] == username), None):
            return jsonify({'status': 'error', 'message': 'User already exists'})

        users.append({'username': username, 'password': password})
        write_config(USERS_FILE, users)
        
        # Créer un répertoire pour le nouvel utilisateur
        add_user_directory(username)

        return jsonify({'status': 'success'})
    return render_template('create_user.html')


def get_user_directory():
    username = session.get('username')
    logger.info(f"Current session username: {username}")
    if username:
        return os.path.join('users', username)
    return None

def read_config(file_name, is_absolute_path=False):
    if not is_absolute_path:
        user_dir = get_user_directory()
        if user_dir:
            file_path = os.path.join(user_dir, file_name)
        else:
            file_path = file_name  # Use global path if no user is logged in
    else:
        file_path = file_name
    
    logger.info(f"Reading config from: {file_path}")

    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r') as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return []

def write_config(file_path, config, is_absolute_path=False):
    if not is_absolute_path:
        user_dir = get_user_directory()
        if user_dir:
            file_path = os.path.join(user_dir, file_path)
    
    logger.info(f"Writing config to: {file_path}")
    
    with open(file_path, 'w') as file:
        json.dump(config, file)

        
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('list_shares'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password_b64 = data.get('password')

        logger.info(f"Attempting login with username: {username}")

        # Verify if the password is a valid base64 encoded string
        try:
            logger.info(f"Received Base64 password: {password_b64}")
            # Check if the length of the base64 string is valid
            if len(password_b64) % 4 != 0:
                raise ValueError("Invalid base64-encoded string length")
            password = base64.b64decode(password_b64).decode()
            logger.info(f"Decoded password: {password}")
        except (TypeError, binascii.Error, UnicodeDecodeError, ValueError) as e:
            logger.error(f"Error decoding base64 password: {e}")
            return jsonify({'status': 'error', 'message': 'Invalid password format'})

        users = read_config(USERS_FILE)
        logger.info(f"Loaded users: {users}")

        user = next((u for u in users if u['username'] == username), None)
        if user:
            try:
                stored_password = base64.b64decode(user['password']).decode()
                if stored_password == password:
                    session['username'] = username
                    logger.info(f"Login successful for user: {username}")
                    # Create user directory if it does not exist
                    add_user_directory(username)
                    disconnect_all_smb_shares()
                    mount_disks_for_user()
                    return jsonify({'status': 'success'})
                else:
                    logger.error(f"Invalid credentials for user: {username}")
                    return jsonify({'status': 'error', 'message': 'Invalid credentials'})
            except (TypeError, binascii.Error, UnicodeDecodeError) as e:
                logger.error(f"Error decoding stored base64 password: {e}")
                return jsonify({'status': 'error', 'message': 'Invalid password format in stored data'})

        logger.error(f"User not found: {username}")
        return jsonify({'status': 'error', 'message': 'Invalid credentials'})

    return render_template('login.html')




@app.route('/logout', methods=['POST'])
def logout():
    disconnect_all_smb_shares()
    session.pop('username', None)
    return jsonify({'status': 'success'})

@app.route('/list_shares')
def list_shares():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('list_shares.html')

@app.route('/config_servers')
def config_servers():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('config_servers.html')

@app.route('/get_users', methods=['GET'])
def get_users():
    users = read_config(USERS_FILE)
    return jsonify({'status': 'success', 'users': users})

@app.route('/delete_user', methods=['POST'])
def delete_user():
    data = request.json
    username = data.get('username')

    users = read_config(USERS_FILE)
    users = [u for u in users if u['username'] != username]
    write_config(USERS_FILE, users)
    return jsonify({'status': 'success'})

@app.route('/get_servers', methods=['GET'])
def get_servers():
    config = read_config('servers_credentials.json')
    return jsonify(config)

@app.route('/add_server', methods=['POST'])
def add_server():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    encoded_password = base64.b64encode(password.encode()).decode()
    server_ip = data.get('server_ip')
    nickname = data.get('nickname')

    response = os.system(f"ping -n 1 {server_ip}")
    if response != 0:
        return jsonify({'status': 'error', 'message': 'Server is not reachable on the network'})

    try:
        net_resource = win32wnet.NETRESOURCE()
        net_resource.lpRemoteName = f"\\\\{server_ip}"
        net_resource.lpProvider = None
        net_resource.dwType = win32netcon.RESOURCETYPE_DISK

        win32wnet.WNetAddConnection2(net_resource, password, username)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

    config = read_config('servers_credentials.json')
    config.append({
        'username': username,
        'password': encoded_password,
        'server_ip': server_ip,
        'nickname': nickname
    })
    write_config('servers_credentials.json', config)
    return jsonify({'status': 'success'})

@app.route('/delete_server', methods=['POST'])
def delete_server():
    data = request.json
    server_ip = data.get('server_ip')

    config = read_config('servers_credentials.json')
    config = [server for server in config if server['server_ip'] != server_ip]
    write_config('servers_credentials.json', config)
    return jsonify({'status': 'success'})

@app.route('/list_all_shares', methods=['GET'])
def list_all_shares():
    if 'username' not in session:
        logger.error('User not authenticated')
        return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

    config = read_config(CONFIG_FILE)
    logger.info(f"Loaded server configurations: {config}")
    all_shares = []
    for server in config:
        server_ip = server['server_ip']
        username = server['username']
        password = base64.b64decode(server['password']).decode()
        nickname = server.get('nickname', '')  # Ensure nickname is included

        try:
            net_resource = win32wnet.NETRESOURCE()
            net_resource.lpRemoteName = f"\\\\{server_ip}"
            net_resource.lpProvider = None
            net_resource.dwType = win32netcon.RESOURCETYPE_DISK

            win32wnet.WNetAddConnection2(net_resource, password, username)
        except Exception as e:
            logger.error(f"Error connecting to server {server_ip}: {e}")
            continue

        try:
            shares, _, _ = win32net.NetShareEnum(server_ip, 1)
            for share in shares:
                all_shares.append({
                    'server_ip': server_ip,
                    'nickname': nickname,
                    'name': share['netname'],
                    'type': share['type'],
                    'remark': share['remark']
                })
        except Exception as e:
            logger.error(f"Error listing shares on server {server_ip}: {e}")
            continue

    logger.info(f"Shares: {all_shares}")
    return jsonify({'status': 'success', 'shares': all_shares})

@app.route('/list_mounted_shares', methods=['GET'])
def list_mounted_shares():
    config = read_config(CONFIG_FILE)
    mounted_shares = []
    drive_mappings = get_drive_mappings()
    for server in config:
        server_ip = server['server_ip']
        nickname = server['nickname']
        for remote_name, drive_letter in drive_mappings.items():
            if remote_name.lower().startswith(f"\\\\{server_ip.lower()}\\"):
                share_name = remote_name.split(f"\\\\{server_ip}\\")[1]
                mounted_shares.append({
                    'server_ip': server_ip,
                    'nickname': nickname,
                    'name': share_name,
                    'drive_letter': drive_letter.upper()  # Ensure drive letter is in upper case
                })
    return jsonify(mounted_shares)

@app.route('/mount_share', methods=['POST'])
def mount_share():
    data = request.json
    username = data.get('username')
    password = base64.b64decode(data.get('password')).decode()
    server_ip = data.get('server_ip')
    share_name = data.get('share_name')
    new_drive_letter = data.get('drive_letter')

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
            win32wnet.WNetCancelConnection2(f"{current_drive_letter}", 0, 0)

        net_resource = win32wnet.NETRESOURCE()
        net_resource.lpRemoteName = network_path
        net_resource.lpLocalName = f"{new_drive_letter}:"
        net_resource.lpProvider = None
        net_resource.dwType = win32netcon.RESOURCETYPE_DISK

        win32wnet.WNetAddConnection2(net_resource, password, username)
        response = {'status': 'success'}
    except Exception as e:
        response = {
            'output': str(e),
            'status': 'error'
        }
    return jsonify(response)

@app.route('/unmount_share', methods=['POST'])
def unmount_share():
    data = request.json
    drive_letter = data.get('drive_letter').upper()  # Ensure drive letter is in upper case

    try:
        win32wnet.WNetCancelConnection2(f"{drive_letter}", 0, 0)
        response = {'status': 'success'}
    except win32wnet.error as e:
        error_code, _, error_message = e.args
        response = {
            'output': f"({error_code}, 'WNetCancelConnection2', '{error_message}')",
            'status': 'error'
        }
    return jsonify(response)

@app.route('/available_drive_letters', methods=['GET'])
def available_drive_letters():
    try:
        all_drive_letters = set(string.ascii_uppercase)
        used_drive_letters = set([drive[0].upper() for drive in win32api.GetLogicalDriveStrings().split('\x00')[:-1]])
        available_drive_letters = sorted(list(all_drive_letters - used_drive_letters))

        response = {
            'letters': available_drive_letters,
            'status': 'success'
        }
    except Exception as e:
        response = {
            'output': str(e),
            'status': 'error'
        }
    return jsonify(response)

@app.route('/save_mapping_preset', methods=['POST'])
def save_mapping_preset():
    drive_mappings = get_drive_mappings()
    new_mappings = []
    for remote_name, drive_letter in drive_mappings.items():
        parts = remote_name.split('\\')
        if len(parts) >= 4:
            server_ip = parts[2]
            share_name = parts[3]
            new_mappings.append({
                'server_ip': server_ip,
                'share_name': share_name,
                'drive_letter': drive_letter.rstrip(":")
            })

    write_config(DEFAULT_PRESET_FILE, [{'preset_name': 'default', 'mappings': new_mappings}])
    return jsonify({'status': 'success'})

def get_drive_mappings():
    drive_mappings = {}
    drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
    for drive in drives:
        try:
            remote_name = win32wnet.WNetGetConnection(drive)
            if remote_name:
                drive_mappings[remote_name.lower()] = drive.upper()  # Ensure drive letter is in upper case
        except win32wnet.error as e:
            continue

    try:
        resume = 0
        while True:
            use_info, _, resume = win32net.NetUseEnum(None, 1, resume)
            for info in use_info:
                remote_name = info['remote']
                local_name = info['local']
                if local_name:
                    drive_mappings[remote_name.lower()] = local_name.upper()  # Ensure drive letter is in upper case
            if resume == 0:
                break
    except win32net.error as e:
        pass

    return drive_mappings

@app.route('/load_default', methods=['POST'])
def mount_disks():
    return mount_disks_for_user()

def mount_disks_for_user():
    try:
        user_dir = get_user_directory()
        if not user_dir:
            logger.error("No user directory found.")
            return jsonify({'status': 'error', 'message': 'No user directory found'})

        mappings_file = os.path.join(user_dir, 'mappings.json')
        if not os.path.exists(mappings_file):
            logger.error(f"Mappings file not found at {mappings_file}.")
            return jsonify({'status': 'error', 'message': 'Mappings file not found'})

        config_file = os.path.join(user_dir, 'servers_credentials.json')
        if not os.path.exists(config_file):
            logger.error(f"Server credentials file not found at {config_file}.")
            return jsonify({'status': 'error', 'message': 'Server credentials file not found'})

        # Log the paths to the files
        logger.info(f"Reading mappings from {mappings_file}")
        logger.info(f"Reading server credentials from {config_file}")

        mappings = read_config(mappings_file, is_absolute_path=True)
        if not mappings or not mappings[0].get('mappings'):
            logger.error(f"Mappings file is empty or invalid: {mappings}")
            return jsonify({'status': 'error', 'message': 'Mappings file is empty or invalid'})

        mappings_list = mappings[0].get('mappings', [])
        servers = read_config(config_file, is_absolute_path=True)

        # Log the contents of the mappings and servers
        logger.info(f"Loaded mappings: {mappings_list}")
        logger.info(f"Loaded server configurations: {servers}")

        all_results = []

        for mapping in mappings_list:
            server_ip = mapping['server_ip']
            share_name = mapping['share_name']
            drive_letter = mapping['drive_letter']

            # Find server credentials
            server = next((s for s in servers if s['server_ip'] == server_ip), None)
            if not server:
                logger.error(f"Server {server_ip} not found in configuration")
                all_results.append({'server_ip': server_ip, 'status': 'error', 'message': 'Server not found in configuration'})
                continue

            username = server['username']
            password = base64.b64decode(server['password']).decode()
            logger.info(f"Mounting {share_name} from {server_ip} on {drive_letter} using username {username}")

            # Attempt to mount the share
            result = mount_share_with_args(server_ip, share_name, username, password, drive_letter)
            if result['status'] != 'success':
                logger.error(f"Failed to mount {share_name} from {server_ip} on {drive_letter}: {result['output']}")
            all_results.append(result)

        return jsonify({'status': 'success', 'results': all_results})
    except Exception as e:
        logger.error(f"Error in mount_disks_for_user: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

    
def mount_share_with_args(server_ip, share_name, username, password, new_drive_letter):
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
            win32wnet.WNetCancelConnection2(f"{current_drive_letter}", 0, 0)

        net_resource = win32wnet.NETRESOURCE()
        net_resource.lpRemoteName = network_path
        net_resource.lpLocalName = f"{new_drive_letter}:"
        net_resource.lpProvider = None
        net_resource.dwType = win32netcon.RESOURCETYPE_DISK

        win32wnet.WNetAddConnection2(net_resource, password, username)
        return {'status': 'success'}
    except Exception as e:
        return {
            'output': str(e),
            'status': 'error'
        }


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
