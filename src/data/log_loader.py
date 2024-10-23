import json
from ..utils.pid_utils import normalize_pid

def load_audit_log(log_file):
    """Load and parse audit logs from file."""
    logs = []
    with open(log_file, 'r') as file:
        for line in file:
            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return logs