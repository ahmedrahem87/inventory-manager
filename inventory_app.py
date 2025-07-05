from flask import Flask, session, render_template, request, redirect, url_for, flash, jsonify, send_file
from datetime import timedelta
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from netmiko import ConnectHandler, NetMikoAuthenticationException, NetMikoTimeoutException
from cryptography.fernet import Fernet
from functools import wraps
from fpdf import FPDF
import yaml
import os
import subprocess
import requests
import traceback
import datetime, requests, json

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production
base_dir = os.path.abspath(os.path.dirname(__file__))

CREDENTIALS_DIR = "/home/admin/cred"
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

INVENTORY_FILE = 'inventory.yaml'
EXPORT_DIR = './exports'
BACKUP_DIR = os.path.expanduser('~/router_backups')

def load_credentials():
    with open(os.path.join(CREDENTIALS_DIR, "secret.key"), "rb") as key_file:
        key = key_file.read()
    fernet = Fernet(key)

    with open(os.path.join(CREDENTIALS_DIR, "credentials.enc"), "rb") as enc_file:
        lines = enc_file.readlines()
        username = fernet.decrypt(lines[0].strip()).decode()
        password = fernet.decrypt(lines[1].strip()).decode()
    return username, password

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = session.get('role')
            if user_role != required_role:
                flash('You are not authorized to access this page.', 'danger')
                return redirect(url_for('dashboard'))  # or any safe page
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class User(UserMixin):
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    user_data = users.get(user_id)
    if user_data:
        return User(
            id=user_id,
            username=user_id,
            password=user_data['password'],
            role=user_data['role']
        )
    return None

users = {
    'admin': {
        'password': generate_password_hash('admin123'),
        'role': 'admin'
    },
    'viewer': {
        'password': generate_password_hash('viewer123'),
        'role': 'viewer'
    }
}


app.permanent_session_lifetime = timedelta(minutes=10)

# ----------------------------- ROUTES ----------------------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_data = users.get(username)

        if user_data and check_password_hash(user_data['password'], password):
            user = User(id=username, username=username, password=user_data['password'], role=user_data['role'])
            login_user(user)

            # ✅ Set role after successful login
            session['role'] = user.role

            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    query = request.args.get('query', '').strip().lower()

    if os.path.exists(INVENTORY_FILE):
        with open(INVENTORY_FILE) as f:
            data = yaml.safe_load(f)
    else:
        data = {'devices': []}

    devices = data.get('devices', [])

    if query:
        devices = [
            device for device in devices
            if query in device['name'].lower() or query in device['ip']
        ]

    return render_template('dashboard.html', devices=devices)

@app.route('/add_device', methods=['POST'])
@login_required
def add_device():
    device = {
        'name': request.form['name'],
        'ip': request.form['ip'],
        'platform': request.form['platform'],
        'groups': request.form['groups'].split(',')
    }
    data = load_inventory()
    data['devices'].append(device)
    save_inventory(data)
    flash('Device added successfully')
    return redirect(url_for('dashboard'))

@app.route('/remove_devices', methods=['POST'])
@login_required
def remove_devices():
    selected_names = request.form.getlist('device_names')

    if os.path.exists(INVENTORY_FILE):
        with open(INVENTORY_FILE) as f:
            data = yaml.safe_load(f)
    else:
        data = {'devices': []}

    data['devices'] = [device for device in data['devices'] if device['name'] not in selected_names]

    with open(INVENTORY_FILE, 'w') as f:
        yaml.dump(data, f)

    export_to_ansible(data)
    export_to_prometheus(data)
    export_to_netmiko(data)

    flash(f'Removed {len(selected_names)} device(s) successfully.')
    return redirect(url_for('dashboard'))

@app.route('/edit_device/<name>', methods=['GET', 'POST'])
@login_required
def edit_device(name):
    data = load_inventory()
    device = next((d for d in data['devices'] if d['name'] == name), None)

    if not device:
        flash('Device not found')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        device['ip'] = request.form['ip']
        device['platform'] = request.form['platform']
        device['groups'] = request.form['groups'].split(',')

        save_inventory(data)
        flash('Device updated successfully')
        return redirect(url_for('dashboard'))

    return render_template('edit_device.html', device=device)

@app.route('/backups')
@login_required
def view_backups():
    backup_structure = []
    if os.path.exists(BACKUP_DIR):
        for day in sorted(os.listdir(BACKUP_DIR), reverse=True):
            full_day_path = os.path.join(BACKUP_DIR, day)
            if os.path.isdir(full_day_path):
                files = sorted(os.listdir(full_day_path))
                backup_structure.append({'date': day, 'files': files})

    return render_template('backups.html', backup_files=backup_structure)

@app.route('/view_backup/<date>/<filename>')
@login_required
def view_backup_content(date, filename):
    full_path = os.path.join(BACKUP_DIR, date, filename)
    if os.path.isfile(full_path):
        with open(full_path) as f:
            content = f.read()
        return f"<pre>{content}</pre><br><a href='{url_for('view_backups')}'>← Back</a>"
    return "File not found", 404

@app.route('/jobs', methods=['GET', 'POST'])
@login_required
@role_required('admin')  # Only users with role 'admin' can access
def jobs():
    data = load_inventory()
    devices = data.get('devices', [])

    groups = sorted({g for d in devices for g in d.get('groups', [])})
    vendors = sorted({d['platform'] for d in devices})
    names = sorted({d['name'] for d in devices})
    username, password = load_credentials()
						 
    output = ""

    if request.method == 'POST':
        selected_group = request.form.get('group')
        selected_vendor = request.form.get('vendor')
        selected_device_names = request.form.getlist('device_name')  # changed to list
        command = request.form.get('command')

        if not command:
             output = "Please enter a command."
        else:
            for device in devices:
                match_group = selected_group in device.get('groups', [])
                match_vendor = selected_vendor == device['platform'] if selected_vendor else True
                match_device = device['name'] in selected_device_names if selected_device_names else True
                
                if match_group and match_vendor and match_device:
											   
                    try:
                        conn = ConnectHandler(
                            device_type=device['platform'],
                            host=device['ip'],
                            username=username,      # Replace with your logic
                            password=password,       # Replace with your logic
                            timeout=120,
                            auth_timeout=30,
                            banner_timeout=30

                        )
                        cmd_output = ""
                        for cmd in command.strip().splitlines():
                            if cmd.strip():
                                cmd_output += f"\n$ {cmd}\n"
                                cmd_output += conn.send_command(cmd)
                                cmd_output += "\n"
                        #if len(cmd_output) > 5000:
                         #   cmd_output = cmd_output[:5000] + "\n\n[Output Truncated]\n"
                        output += f"\n<span class='device-header'>=== {device['name']} ({device['ip']}) ===</span>\n{cmd_output}\n"
                        conn.disconnect()

                    except (NetMikoAuthenticationException, NetMikoTimeoutException) as e:
                        output += f"\n--- ERROR on {device['name']} ({device['ip']}) ---\n{str(e)}\n"

                    except Exception as e:
                        error_message = f"\n--- UNEXPECTED ERROR on {device['name']} ({device['ip']}) ---\n{str(e)}\n"
                        output += error_message

                        # Log full traceback to terminal or Gunicorn logs
                        print(error_message)
                        traceback.print_exc()

    if request.form.get('save_output'):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"output_{timestamp}.txt"
        file_path = os.path.join(EXPORT_DIR, filename)
        os.makedirs(EXPORT_DIR, exist_ok=True)
        with open(file_path, 'w') as f:
            f.write(output)
        flash(f'Output saved to file: {filename}')
        session['last_saved_output'] = filename  # optional for download

    if request.args.get('ajax'):
        return output, 200, {'Content-Type': 'text/plain; charset=utf-8'}  # return plain text for AJAX

    return render_template(
        'jobs.html',
        groups=groups,
        vendors=vendors,
        names=names,
        output=output
    )

@app.route('/filter_inventory')
@login_required
def filter_inventory():
    group = request.args.get('group')
    data = load_inventory()
    devices = data.get('devices', [])

    vendors = sorted({d['platform'] for d in devices if group in d.get('groups', [])})
    names = sorted({d['name'] for d in devices if group in d.get('groups', [])})

    return jsonify({'vendors': vendors, 'names': names})

@app.route('/download_output/<filename>')
@login_required
def download_output(filename):
    file_path = os.path.join(EXPORT_DIR, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        flash("File not found.")
        return redirect(url_for('jobs'))

@app.route('/link-report', methods=['GET', 'POST'])
@login_required
def link_report():
    devices = []
    data = []
    start_date = end_date = None

    # Step 1: Fetch unique device names (e.g., from a Prometheus label)
    prom_resp = requests.get("http://localhost:9090/api/v1/label/instance/values")
    if prom_resp.ok:
        devices = prom_resp.json().get("data", [])

    if request.method == 'POST':
        selected_device = request.form.get('device')
        start_date = request.form.get('start')
        end_date = request.form.get('end')

        start_ts = datetime.datetime.fromisoformat(start_date).timestamp()
        end_ts = datetime.datetime.fromisoformat(end_date).timestamp()

        # Query down links for selected device over time
        query = f'ifOperStatus{{instance="{selected_device}", operstate="down"}}'

        prometheus_url = "http://localhost:9090/api/v1/query_range"
        params = {
            "query": query,
            "start": start_ts,
            "end": end_ts,
            "step": "5m"
        }

        response = requests.get(prometheus_url, params=params)
        if response.ok:
            data = response.json()["data"]["result"]

    return render_template("link_report.html", devices=devices, data=data, start=start_date, end=end_date)

@app.route('/download_link_report', methods=['POST'])
@login_required
def download_link_report():
    report_data = json.loads(request.form['report_data'])

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    for item in report_data:
        pdf.multi_cell(0, 10, txt=json.dumps(item, indent=2))

    filename = f"link_down_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    file_path = os.path.join(EXPORT_DIR, filename)
    pdf.output(file_path)

    return send_file(file_path, as_attachment=True)


# ----------------------------- HELPERS ----------------------------------
def load_inventory():
    if os.path.exists(INVENTORY_FILE):
        with open(INVENTORY_FILE) as f:
            return yaml.safe_load(f) or {'devices': []}
    return {'devices': []}

def save_inventory(data):
    with open(INVENTORY_FILE, 'w') as f:
        yaml.dump(data, f)
    export_to_ansible(data)
    export_to_prometheus(data)
    export_to_netmiko(data)

def export_to_ansible(data):
    ansible_data = {'all': {'hosts': {}, 'children': {}}}
    for d in data['devices']:
        ansible_data['all']['hosts'][d['name']] = {
            'ansible_host': d['ip'],
            'ansible_user': 'admin',
            'ansible_password': 'admin',
            'ansible_network_os': d['platform']
        }
        for group in d.get('groups', []):
            ansible_data['all']['children'].setdefault(group, {'hosts': {}})['hosts'][d['name']] = None

    os.makedirs(EXPORT_DIR, exist_ok=True)
    with open(os.path.join(EXPORT_DIR, 'ansible_hosts.yml'), 'w') as f:
        yaml.dump(ansible_data, f)

def export_to_prometheus(data):
    targets = [{'targets': [d['ip']], 'labels': {'hostname': d['name']}} for d in data['devices']]
    os.makedirs(EXPORT_DIR, exist_ok=True)
    export_path = os.path.join(EXPORT_DIR, 'snmp_targets.yml')
    with open(export_path, 'w') as f:
        yaml.dump(targets, f)
    try:
        subprocess.run(['/usr/bin/cp', export_path, '/usr/local/prometheus/snmp_targets.yml'], check=True)
        r = subprocess.run(['curl', '-X', 'POST', 'http://localhost:9090/-/reload'], check=True)
        print(f"Prometheus reload response: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"Prometheus reload failed: {e}")

def export_to_netmiko(data):
    netmiko_inventory = {'devices': []}
    for d in data['devices']:
        netmiko_inventory['devices'].append({
            'device': {
                'device_type': d['platform'],
                'host': d['ip']
            },
            'hostname': d['name']
        })

    os.makedirs(EXPORT_DIR, exist_ok=True)
    export_path = os.path.join(EXPORT_DIR, 'inventory.yml')
    with open(export_path, 'w') as f:
        yaml.dump(netmiko_inventory, f)
    try:
        subprocess.run(['/usr/bin/cp', export_path, '/home/admin/config_collect/inventory.yml'], check=True)
    except Exception as e:
        print(f"Netmiko inventory copy failed: {e}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

