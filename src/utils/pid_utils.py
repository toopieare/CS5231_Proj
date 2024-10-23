import pandas as pd

def normalize_pid(pid):
    """Normalize PID to integer, handling both float and string representations."""
    if pd.isna(pid):
        return None
    try:
        return int(float(pid))
    except (ValueError, TypeError):
        return None