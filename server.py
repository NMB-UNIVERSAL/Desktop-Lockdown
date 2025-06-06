import os
import sys
import json
import ctypes
import threading
import hashlib
import socket
import webbrowser
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from waitress import serve
import psutil

# Import our lockdown functionality
from main import LockdownApp

# Create Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for API access from mobile

# Store application state
app_state = {
    "lockdown_instance": None,
    "config_file": "config.json",
    "password_hash_file": "password.hash",
    "blocked_apps": [],
    "blocked_sites": [],
    "is_locked": False
}

# Ensure running as admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

# Load configuration
def load_config():
    if os.path.exists(app_state["config_file"]):
        try:
            with open(app_state["config_file"], 'r') as f:
                config = json.load(f)
                app_state["blocked_apps"] = config.get('blocked_apps', [])
                app_state["blocked_sites"] = config.get('blocked_sites', [])
                app_state["is_locked"] = config.get('is_locked', False)
        except Exception as e:
            print(f"Failed to load configuration: {e}")
            app_state["blocked_apps"] = []
            app_state["blocked_sites"] = []
            app_state["is_locked"] = False

# Save configuration
def save_config():
    config = {
        'blocked_apps': app_state["blocked_apps"],
        'blocked_sites': app_state["blocked_sites"],
        'is_locked': app_state["is_locked"]
    }
    try:
        with open(app_state["config_file"], 'w') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"Failed to save configuration: {e}")

# Verify password
def verify_password(entered_password):
    try:
        with open(app_state["password_hash_file"], 'r') as f:
            stored_hash = f.read().strip()
        entered_hash = hashlib.sha256(entered_password.encode()).hexdigest()
        return entered_hash == stored_hash
    except Exception as e:
        print(f"Failed to verify password: {e}")
        return False

# Create a background lockdown app instance
def create_lockdown_instance():
    # This function creates a headless instance of the lockdown app
    # that runs in the background
    lockdown = LockdownApp(headless=True)
    return lockdown

# Static files route for the web interface
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

# API endpoints
@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        "is_locked": app_state["is_locked"],
        "blocked_apps": app_state["blocked_apps"],
        "blocked_sites": app_state["blocked_sites"],
        "is_admin": is_admin()
    })

@app.route('/api/lock', methods=['POST'])
def lock_system():
    data = request.json or {}
    password = data.get('password', '')
    
    if not verify_password(password):
        return jsonify({"success": False, "message": "Incorrect password"})
    
    if not is_admin():
        return jsonify({"success": False, "message": "Application needs admin privileges"})
    
    try:
        # Lock the system through our lockdown instance
        if app_state["lockdown_instance"]:
            app_state["lockdown_instance"].lock_system()
            app_state["is_locked"] = True
            save_config()
            return jsonify({"success": True, "message": "System locked successfully"})
        else:
            return jsonify({"success": False, "message": "Lockdown instance not initialized"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error locking system: {str(e)}"})

@app.route('/api/unlock', methods=['POST'])
def unlock_system():
    data = request.json or {}
    password = data.get('password', '')
    
    if not verify_password(password):
        return jsonify({"success": False, "message": "Incorrect password"})
    
    if not is_admin():
        return jsonify({"success": False, "message": "Application needs admin privileges"})
    
    try:
        # Unlock the system through our lockdown instance
        if app_state["lockdown_instance"]:
            app_state["lockdown_instance"].unlock_system_headless(password)
            app_state["is_locked"] = False
            save_config()
            return jsonify({"success": True, "message": "System unlocked successfully"})
        else:
            return jsonify({"success": False, "message": "Lockdown instance not initialized"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error unlocking system: {str(e)}"})

@app.route('/api/apps', methods=['GET'])
def get_apps():
    return jsonify({"apps": app_state["blocked_apps"]})

@app.route('/api/apps', methods=['POST'])
def add_app():
    data = request.json or {}
    password = data.get('password', '')
    app_name = data.get('app_name', '')
    
    if not verify_password(password):
        return jsonify({"success": False, "message": "Incorrect password"})
    
    if not app_name:
        return jsonify({"success": False, "message": "No application name provided"})
    
    if app_name in app_state["blocked_apps"]:
        return jsonify({"success": False, "message": "Application already in block list"})
    
    app_state["blocked_apps"].append(app_name)
    save_config()
    
    # Update the lockdown instance
    if app_state["lockdown_instance"]:
        app_state["lockdown_instance"].update_blocked_apps(app_state["blocked_apps"])
    
    return jsonify({"success": True, "message": f"Added {app_name} to blocked applications"})

@app.route('/api/apps/<app_name>', methods=['DELETE'])
def remove_app(app_name):
    data = request.json or {}
    password = data.get('password', '')
    
    if not verify_password(password):
        return jsonify({"success": False, "message": "Incorrect password"})
    
    if app_name in app_state["blocked_apps"]:
        app_state["blocked_apps"].remove(app_name)
        save_config()
        
        # Update the lockdown instance
        if app_state["lockdown_instance"]:
            app_state["lockdown_instance"].update_blocked_apps(app_state["blocked_apps"])
        
        return jsonify({"success": True, "message": f"Removed {app_name} from blocked applications"})
    else:
        return jsonify({"success": False, "message": "Application not in block list"})

@app.route('/api/sites', methods=['GET'])
def get_sites():
    return jsonify({"sites": app_state["blocked_sites"]})

@app.route('/api/sites', methods=['POST'])
def add_site():
    data = request.json or {}
    password = data.get('password', '')
    site_name = data.get('site_name', '')
    
    if not verify_password(password):
        return jsonify({"success": False, "message": "Incorrect password"})
    
    if not site_name:
        return jsonify({"success": False, "message": "No website name provided"})
    
    if site_name in app_state["blocked_sites"]:
        return jsonify({"success": False, "message": "Website already in block list"})
    
    app_state["blocked_sites"].append(site_name)
    save_config()
    
    # Update the lockdown instance
    if app_state["lockdown_instance"]:
        app_state["lockdown_instance"].update_blocked_sites(app_state["blocked_sites"])
    
    return jsonify({"success": True, "message": f"Added {site_name} to blocked websites"})

@app.route('/api/sites/<site_name>', methods=['DELETE'])
def remove_site(site_name):
    data = request.json or {}
    password = data.get('password', '')
    
    if not verify_password(password):
        return jsonify({"success": False, "message": "Incorrect password"})
    
    if site_name in app_state["blocked_sites"]:
        app_state["blocked_sites"].remove(site_name)
        save_config()
        
        # Update the lockdown instance
        if app_state["lockdown_instance"]:
            app_state["lockdown_instance"].update_blocked_sites(app_state["blocked_sites"])
        
        return jsonify({"success": True, "message": f"Removed {site_name} from blocked websites"})
    else:
        return jsonify({"success": False, "message": "Website not in block list"})

@app.route('/api/change-password', methods=['POST'])
def change_password():
    data = request.json or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not verify_password(current_password):
        return jsonify({"success": False, "message": "Incorrect current password"})
    
    if not new_password:
        return jsonify({"success": False, "message": "New password cannot be empty"})
    
    try:
        # Hash and save the new password
        password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        with open(app_state["password_hash_file"], 'w') as f:
            f.write(password_hash)
        return jsonify({"success": True, "message": "Password changed successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error changing password: {str(e)}"})

def get_local_ip():
    """Get the local IP address of the machine"""
    try:
        # Create a socket connection to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return '127.0.0.1'  # Fallback to localhost

def run_server():
    """Run the web server on a background thread"""
    # Get local IP for mobile access
    local_ip = get_local_ip()
    port = 5000
    print(f"Starting Nubaid Lockdown Server on http://{local_ip}:{port}")
    print(f"Access from mobile device by opening this URL in a browser: http://{local_ip}:{port}")
    
    # Don't attempt to generate QR code as per user request
    
    # Don't open browser automatically - prevents browser opening on brother's computer
    
    # Run the server (production-ready with waitress)
    serve(app, host='0.0.0.0', port=port)

def main():
    # Ensure we're running as admin
    if not is_admin():
        print("WARNING: Application needs admin privileges for full functionality.")
        print("Please restart the application as administrator.")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1
        )
        sys.exit(0)
    
    # Load configuration
    load_config()
    
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # Create lockdown instance
    app_state["lockdown_instance"] = create_lockdown_instance()
    
    # Run the server
    run_server()

if __name__ == '__main__':
    main() 