from collections import defaultdict
from datetime import datetime, timedelta
import re
import pandas as pd

def generate_mermaid_diagram(process_tree, analyzer, df):
    """Generate Mermaid diagram from process tree."""
    mermaid_code = []
    mermaid_code.append("flowchart TD")
    mermaid_code.append("    classDef normal fill:#b3e0ff,stroke:#333,stroke-width:1px")
    mermaid_code.append("    classDef suspicious fill:#ffcccc,stroke:#red,stroke-width:2px")
    mermaid_code.append("    classDef root fill:#99ff99,stroke:#333,stroke-width:1px")
    mermaid_code.append("    classDef privileged fill:#ffb366,stroke:#333,stroke-width:2px")
    
    processed_nodes = set()
    node_class = {}

    def add_process_node(pid, process_info):
        if pid in processed_nodes:
            return
        
        processed_nodes.add(pid)
        process_name = process_info['process'] or 'unknown'
        
        alerts = analyzer.analyze_process(pid, process_info, df)
        
        style_class = 'normal'
        if any('Running as root' in alert for alert in alerts):
            style_class = 'privileged'
        if any(('⚠️' in alert or '❌' in alert) for alert in alerts):
            style_class = 'suspicious'
        if pid == 1:
            style_class = 'root'
            
        node_class[pid] = style_class
        
        node_text = f"{process_name} (PID: {int(pid)})"
        if alerts:
            alert_text = '<br>' + '<br>• '.join(alerts)
            node_text = f"{node_text}{alert_text}"
        
        mermaid_code.append(f'    pid{int(pid)}["{node_text}"]')
        mermaid_code.append(f'    class pid{int(pid)} {style_class}')
        
        ppid = process_info['ppid']
        if ppid:
            edge_style = '-->'
            if style_class == 'suspicious':
                edge_style = '==>'
            mermaid_code.append(f'    pid{int(ppid)}{edge_style}pid{int(pid)}')
        
        for child in process_info['children']:
            child_pid = [k for k, v in process_tree.items() if v == child][0]
            add_process_node(child_pid, child)

    if 1 in process_tree:
        add_process_node(1, process_tree[1])
    
    for pid, info in process_tree.items():
        if pid not in processed_nodes:
            add_process_node(pid, info)

    return '\n'.join(mermaid_code)

def clean_text_for_mermaid(text):
    """Clean text to be Mermaid-compatible."""
    cleaned = re.sub(r'[^a-zA-Z0-9\s]', '_', str(text))
    cleaned = cleaned.replace(' ', '_')
    if cleaned and not cleaned[0].isalpha():
        cleaned = 'p' + cleaned
    cleaned = re.sub(r'_+', '_', cleaned)
    return cleaned.rstrip('_') or 'unknown'

def generate_gantt_diagram(process_tree, analyzer, behavior_analyzer, df):
    """Generate Gantt diagram with proper task format."""
    mermaid_code = []
    mermaid_code.append("gantt")
    mermaid_code.append("    title Process Activity Timeline")
    mermaid_code.append("    dateFormat YYYY-MM-DD HH:mm:ss")
    mermaid_code.append("    axisFormat %H:%M:%S")
    
    min_time = df['timestamp'].min()
    max_time = df['timestamp'].max()
    
    # Group processes by category
    sections = {
        'System Processes': [],
        'User Processes': [],
        'Background Services': [],
        'Suspicious Processes': []
    }
    
    for pid, process_info in process_tree.items():
        try:
            process_data = df[df['pid'] == pid]
            if process_data.empty:
                continue
            
            start_time = process_data['timestamp'].min()
            end_time = process_data['timestamp'].max()
            duration = (end_time - start_time).total_seconds()
            
            if duration < 0.1:  # Skip very short processes
                continue
                
            process_name = process_info['process'] or f'unknown_{pid}'
            alerts = analyzer.analyze_process(pid, process_info, df)
            has_alerts = any('⚠️' in alert for alert in alerts)
            
            # Categorize process
            if has_alerts:
                category = 'Suspicious Processes'
            elif pid == 1 or 'root' in str(process_data['user'].iloc[0]).lower():
                category = 'System Processes'
            elif any(name in str(process_name).lower() for name in ['bash', 'sh', 'terminal']):
                category = 'User Processes'
            else:
                category = 'Background Services'
            
            # Format timestamps
            start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
            end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Create task name
            task_name = clean_text_for_mermaid(f"{process_name}_{pid}")
            
            # Determine status
            if has_alerts:
                status = "crit"
            elif duration > 60:
                status = "active"
            elif duration > 10:
                status = "done"
            else:
                status = "milestone"
            
            # Add task
            task = f"    {task_name} : {status}, {start_str}, {end_str}"
            sections[category].append((start_time, task))
            
        except Exception as e:
            print(f"Error processing process {pid}: {str(e)}")
            continue
    
    # Add sections with sorted tasks
    for section_name, tasks in sections.items():
        if tasks:
            mermaid_code.append(f"\n    section {section_name}")
            sorted_tasks = sorted(tasks, key=lambda x: x[0])
            mermaid_code.extend(task for _, task in sorted_tasks)
    
    return '\n'.join(mermaid_code)