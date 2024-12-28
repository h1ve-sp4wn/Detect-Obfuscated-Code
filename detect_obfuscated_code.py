import os
import logging
import base64
import requests
from unicorn import *
from unicorn.x86_const import *
from sklearn.ensemble import IsolationForest
import numpy as np
import sys
import subprocess
from ctypes import windll

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def detect_control_flow_anomalies(code):
    flow_patterns = ['jmp', 'call', 'ret', 'lea']
    if any(pattern in code for pattern in flow_patterns):
        logger.debug("Control flow anomaly detected.")
        return True
    return False

def anti_debugging_checks():
    try:
        if os.name == 'nt':
            windll.kernel32.IsDebuggerPresent()
            logger.debug("Debugger check on Windows passed")
            return True
        
        elif sys.platform == 'linux' or sys.platform == 'linux2':  # Linux
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if line.startswith("TracerPid"):
                        tracer_pid = int(line.split(":")[1].strip())
                        if tracer_pid != 0:
                            logger.debug("Debugger detected on Linux (TracerPid non-zero)")
                            return True
            logger.debug("No debugger detected on Linux")
            return False
        
        elif sys.platform == 'darwin':  # macOS
            result = subprocess.run(['sysctl', 'kern.proc.all'], capture_output=True, text=True)
            if 'debugger' in result.stdout.lower():
                logger.debug("Debugger detected on macOS")
                return True
            
            try:
                import ctypes
                libc = ctypes.CDLL("libc.dylib")
                libc.ptrace(0, 0, 0, 0)  # Try to check ptrace functionality
            except Exception as e:
                logger.debug(f"Mac ptrace check failed: {e}")
                return False

            logger.debug("No debugger detected on macOS")
            return False
        
        else:
            logger.debug(f"Unknown OS detected: {platform.system()}")
            return False
        
    except Exception as e:
        logger.debug(f"Anti-debugging check failed: {e}")
    return False

def detect_string_encryption(data):
    if len(data) > 10 and all(c in "0123456789abcdef" for c in data[:10]):
        logger.debug("Potential string encryption detected.")
        return True
    return False

def emulate_code(data):
    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(0x1000, 2*1024*1024)
        mu.mem_write(0x1000, data)
        mu.reg_write(UC_X86_REG_RIP, 0x1000)
        mu.emu_start(0x1000, 0x1000 + len(data))
        return "Emulation successful"
    except UcError as e:
        logger.error(f"Emulation failed: {e}")
        return "Emulation failed"

def extract_code_features(data):
    features = []
    entropy = sum((data.count(c) / len(data)) * -1 * (data.count(c) / len(data)).log(2) for c in set(data))
    features.append(entropy)
    logger.debug(f"Extracted features: {features}")
    return features

def ml_anomaly_detection(data_features):
    clf = IsolationForest(n_estimators=100, contamination='auto')
    clf.fit(np.array(data_features).reshape(-1, 1))
    prediction = clf.predict(np.array(data_features).reshape(-1, 1))
    if prediction == -1:
        logger.warning("Polymorphic/metamorphic pattern detected.")
        return True
    return False

def hybrid_analysis(input_data):
    static_analysis_result = static_analysis(input_data)
    if not static_analysis_result:
        dynamic_analysis_result = dynamic_analysis(input_data)
        if dynamic_analysis_result:
            return dynamic_analysis_result
    return static_analysis_result

def static_analysis(data):
    if data.startswith('base64:'):
        return decode_base64(data[7:])
    if data.startswith('hex:'):
        return decode_hex(data[4:])
    return False

def dynamic_analysis(data):
    emulation_result = emulate_code(data.encode('utf-8'))
    if "Emulation failed" in emulation_result:
        return "Dynamic analysis detected issues."
    return False

def decode_base64(encoded_str):
    try:
        return base64.b64decode(encoded_str).decode('utf-8')
    except Exception as e:
        logger.error(f"Base64 decoding failed: {e}")
        return None

def decode_hex(encoded_str):
    try:
        return bytes.fromhex(encoded_str).decode('utf-8')
    except Exception as e:
        logger.error(f"Hex decoding failed: {e}")
        return None

def check_with_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {'x-apikey': 'your_api_key'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        if json_response['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            logger.warning("Malicious code detected via VirusTotal.")
            return True
    return False

def detect_obfuscated_code(input_data):
    logger.info("Starting obfuscated code detection...")

    if detect_control_flow_anomalies(input_data):
        logger.info("Control flow anomaly detected in the input data.")
    
    if anti_debugging_checks():
        logger.warning("Potential anti-debugging behavior detected.")

    if detect_string_encryption(input_data):
        logger.warning("Encrypted string pattern detected.")
    
    hybrid_result = hybrid_analysis(input_data)
    if hybrid_result:
        logger.info(f"Hybrid analysis detected issues: {hybrid_result}")
    
    emulation_result = emulate_code(input_data.encode('utf-8'))
    if "Emulation failed" in emulation_result:
        logger.warning("Emulation failure indicates possible metamorphic code.")

    ml_features = extract_code_features(input_data)
    if ml_anomaly_detection(ml_features):
        logger.warning("Anomaly detected via ML-based analysis.")

    file_hash = hash(input_data)
    if check_with_virustotal(file_hash):
        logger.warning("Code matches a known malicious sample in VirusTotal.")

input_data = "some suspicious obfuscated code here"
detect_obfuscated_code(input_data)