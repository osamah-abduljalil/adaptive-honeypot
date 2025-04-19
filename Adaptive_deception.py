import json
import time
import joblib
import pandas as pd
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import numpy as np
import random
import subprocess
from datetime import datetime
import os

# Debug toggle
# DEBUG = True
# def debug(msg): 
#     if DEBUG: print(msg)

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Load trained model and encoders
model_package = joblib.load('prod_model_v1.pkl')
model = model_package['model']
encoders = model_package['encoders']
feature_columns = model_package['metadata']['features']

# --- Feature extraction ---
def extract_features(log_entry):
    now = datetime.now()

    def safe_encode(encoder, value, default='unknown'):
        try:
            return encoder.transform([value])[0]
        except:
            return encoder.transform([default])[0] if default in encoder.classes_ else 0

    feature_dict = {
        'src_ip_encoded': safe_encode(encoders['ip'], log_entry.get('src_ip', 'unknown')),
        'username_encoded': safe_encode(encoders['user'], log_entry.get('username', 'unknown')),
        'hour': now.hour,
        'duration': float(log_entry.get('duration', 0)),
        'login_attempts': 1,
        'success_rate': 0.0,
        'time_since_first': (now - datetime(2024, 1, 1)).total_seconds(),
        'time_since_last': 0.0,
        'password_length': len(log_entry.get('password', '')),
        'is_common_username': int(log_entry.get('username') in ['admin', 'root', 'test']),
        'is_common_password': int(log_entry.get('password') in ['123456', 'password', 'admin']),
        'suspicious_command': int('input' in log_entry and any(cmd in log_entry['input'] for cmd in ['wget', 'curl', 'chmod', 'rm -rf', 'sudo']))
    }

    df = pd.DataFrame([feature_dict]).reindex(columns=feature_columns, fill_value=0)
    return df

# --- Prediction ---
def predict_attack(log_entry):
    features_df = extract_features(log_entry)
    # debug(f"Features shape: {features_df.shape}")
    # debug(f"Features: {features_df}")

    try:
        prediction = model.predict(features_df)
        if prediction[0] == 'brute_force' and log_entry.get('login_attempts', 0) < 5:
            prediction[0] = 'normal'
    except Exception as e:
        logging.error(f"Prediction error: {e}")
        prediction = ['normal']

    return prediction[0]

# --- Adaptive deception ---
def adapt_deception(attack_type, src_ip):
    if attack_type == 'brute_force':
        duration = random.randint(5, 15) * 60
        logging.info(f"Brute force detected from {src_ip}. Locking for {duration // 60} mins.")
        lockout_ip(src_ip, duration)
        introduce_delay()
    elif attack_type == 'credential_stuffing':
        logging.info(f"Credential stuffing from {src_ip}. Introducing login delay.")
        introduce_login_delay()
        simulate_incorrect_login(src_ip)
    else:
        logging.info("Normal activity. Continuing normal operations.")

def lockout_ip(ip, duration):
    try:
        subprocess.run(f"sudo ufw deny from {ip} to any", shell=True, check=True)
        time.sleep(duration)
        subprocess.run(f"sudo ufw delete deny from {ip} to any", shell=True, check=True)
        logging.info(f"IP {ip} unblocked.")
    except subprocess.CalledProcessError as e:
        logging.error(f"IP block/unblock error: {e}")

def introduce_delay():
    delay = random.randint(3, 10)
    logging.info(f"Introducing delay of {delay}s")
    time.sleep(delay)

def introduce_login_delay():
    introduce_delay()

def simulate_incorrect_login(ip):
    logging.info(f"Simulating failed logins for IP {ip}.")
    fake_failed_logins(ip)

def fake_failed_logins(ip):
    logging.info(f"Fake failed logins for {ip} generated.")


# --- File change handler ---
class LogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith('cowrie.json'):
            logging.info(f"Modified file detected: {event.src_path}")
            try:
                with open(event.src_path, 'r') as file:
                    lines = file.readlines()
                    if not lines:
                        return
                    latest_line = lines[-1].strip()
                    if not latest_line:
                        return
                    latest_log = json.loads(latest_line)
            except json.JSONDecodeError:
                logging.warning("Invalid JSON line skipped.")
                return
            except Exception as e:
                logging.error(f"Error reading log file: {e}")
                return

            attack_type = predict_attack(latest_log)
            logging.info(f"Predicted attack type: {attack_type}")
            adapt_deception(attack_type, latest_log.get('src_ip', 'unknown'))

# --- Main ---
if __name__ == "__main__":
    path = os.path.join(os.getcwd(), 'cowrie.json')
    event_handler = LogHandler()
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(path), recursive=False)
    observer.start()

    logging.info(f"Watching for changes in {path}...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
