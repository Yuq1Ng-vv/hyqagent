"""Cross-language command injection fixture — Python."""

import os


def ping_host():
    host = sys.argv[1]  # $ source=command_injection
    os.system(f"ping -c 1 {host}")  # $ sink=command_injection


def run_admin_cmd():
    cmd = os.environ.get("ADMIN_CMD")  # $ source=command_injection
    os.popen(cmd)  # $ sink=command_injection
