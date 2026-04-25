"""
config.py — Central configuration for MalLLM
============================================
WHY this file exists:
    Instead of hardcoding settings (API keys, paths, model names) across
    multiple files, we keep everything in ONE place. If you need to change
    the OpenAI model, you change it HERE and it affects the entire system.
    This is called the "Single Source of Truth" principle.

NEVER commit your real API key to git. Use a .env file instead.
"""

import os
from pathlib import Path
from  dotenv import load_dotenv

#Load .env file
load_dotenv()

# ======= PATHS ======
BASE_DIR = Path(__file__).parent # root of project
SAMPLES_DIR = BASE_DIR / 'samples' #where exe files go
RESULTS_DIR = BASE_DIR / 'results' #where json outputs go

#create dir if don't exist
SAMPLES_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

# ===== OPENAI SETS =====
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-4.1" #which model we use
MAX_TOKENS = 1500  #Max response length
TEMPERATURE = 0.2 #  Low = more deterministic, we want consistent analysis,not creative writing


# ==== Static Analysis Sets ====
MIN_STRING_LENGTH = 4 # Minimum chars to consider a string "interesting"
HIGH_ENTROPY_THRESHOLD = 7.0  # Entropy > 7.0 → possibly packed/encrypted section

# ==== Suspicious API calls that indicate malicious behavior ====
#Based on MalApi.io we have pre-filter those api calls so the prompt is more focused and token-efficient
SUSPICIOUS_APIS = {
    "injection": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtAllocateVirtualMemory", "RtlCreateUserThread"
    ],
    "keylogger": [
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
        "SetWindowsHookExA", "SetWindowsHookExW"
    ],
    "network": [
        "WSAStartup", "connect", "send", "recv", "InternetOpen",
        "InternetConnect", "HttpOpenRequest", "URLDownloadToFile"
    ],
    "persistence": [
        "RegSetValueEx", "RegCreateKeyEx", "CreateService",
        "OpenSCManager", "ChangeServiceConfig"
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
        "CryptAcquireContext", "BCryptEncrypt"
    ],
    "evasion": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "GetTickCount"
    ]
}

# ==== Classification Labels ====
MALWARE_CATEGORIES = [
    "benign",
    "dropper",
    "keylogger",
    "ransomware",
    "trojan",
    "rootkit",
    "spyware",
    "worm",
    "adware"
]

# ==== Behavior Labels ====
BEHAVIOR_LABELS = [
    "process_injection",
    "persistence",
    "network_communication",
    "data_exfiltration",
    "file_encryption",
    "keylogging",
    "privilege_escalation",
    "anti_analysis"
]


