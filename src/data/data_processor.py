import pandas as pd
from ..utils.pid_utils import normalize_pid

def create_dataframe(logs):
    """Create DataFrame from parsed logs with normalized PIDs."""
    df = pd.DataFrame([{
        'timestamp': log.get('@timestamp'),  # Get timestamp from root level
        'user': log.get('user', {}).get('name'),
        'uid': log.get('user', {}).get('id'),
        'process': log.get('process', {}).get('name'),
        'pid': normalize_pid(log.get('process', {}).get('pid')),
        'ppid': normalize_pid(log.get('process', {}).get('parent', {}).get('pid')),
        'syscall': log.get('auditd', {}).get('data', {}).get('syscall'),
        'event_type': log.get('auditd', {}).get('message_type'),
        'result': log.get('auditd', {}).get('result')
    } for log in logs if 'process' in log])
    
    # Convert timestamp to datetime
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    return df.dropna(subset=['pid'])