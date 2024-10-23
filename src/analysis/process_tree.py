from src.utils.pid_utils import normalize_pid

def build_process_tree(df):
    """Build process tree from DataFrame."""
    process_tree = {}
    
    # First pass: Create entries for all PIDs
    for _, row in df.iterrows():
        pid = int(row['pid'])
        ppid = normalize_pid(row['ppid'])
        process = row['process']
        
        if pid not in process_tree:
            process_tree[pid] = {'process': process, 'children': [], 'ppid': ppid}
        elif process_tree[pid]['process'] is None:
            process_tree[pid]['process'] = process
            
        if ppid and ppid not in process_tree:
            process_tree[ppid] = {'process': None, 'children': [], 'ppid': None}
    
    # Second pass: Build parent-child relationships
    for pid, info in process_tree.items():
        ppid = info['ppid']
        if ppid and ppid in process_tree:
            if process_tree[pid] not in process_tree[ppid]['children']:
                process_tree[ppid]['children'].append(process_tree[pid])

    return process_tree