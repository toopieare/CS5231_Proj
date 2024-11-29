from collections import defaultdict
from datetime import datetime, timedelta
import re
import pandas as pd

def generate_mermaid_diagram(process_tree, security_analyzer, behavior_analyzer, df):
    """Generate Mermaid diagram with both security and behavior analysis."""
    mermaid_code = []
    mermaid_code.append("flowchart TD")
    mermaid_code.append("    classDef normal fill:#b3e0ff,stroke:#333,stroke-width:1px")
    mermaid_code.append("    classDef suspicious fill:#ffcccc,stroke:#red,stroke-width:2px")
    mermaid_code.append("    classDef anomalous fill:#ff99ff,stroke:#purple,stroke-width:2px")  # New class for high behavior scores
    mermaid_code.append("    classDef root fill:#99ff99,stroke:#333,stroke-width:1px")
    mermaid_code.append("    classDef privileged fill:#ffb366,stroke:#333,stroke-width:2px")
    
    processed_nodes = set()
    node_class = {}
    
    # Get behavior scores for all processes
    frequencies, timestamps = behavior_analyzer.calculate_syscall_frequency(df)

    def add_process_node(pid, process_info):
        if pid in processed_nodes:
            return
        
        processed_nodes.add(pid)
        process_name = process_info['process'] or 'unknown'
        
        # Get both security alerts and behavior score
        alerts = security_analyzer.analyze_process(pid, process_info, df)
        behavior_score, category_scores = behavior_analyzer.calculate_behavior_score(
            frequencies, timestamps, pid
        )
        
        # Determine node style based on both analyses
        style_class = 'normal'
        if any('Running as root' in alert for alert in alerts):
            style_class = 'privileged'
        if any(('⚠️' in alert or '❌' in alert) for alert in alerts):
            style_class = 'suspicious'
        if behavior_score > 0.7:  # High behavior score threshold
            style_class = 'anomalous'
        if pid == 1:
            style_class = 'root'
            
        node_class[pid] = style_class
        
        # Enhanced node text with both analyses
        node_text = [
            f"{process_name} (PID: {int(pid)})",
            f"Behavior Score: {behavior_score:.2f}"
        ]
        
        if category_scores:
            high_categories = [cat for cat, score in category_scores.items() if score > 0.5]
            if high_categories:
                node_text.append(f"High activity: {', '.join(high_categories)}")
        
        if alerts:
            alert_text = '<br>' + '<br>• '.join(alerts)
            node_text.append(alert_text)
        
        mermaid_code.append(f'    pid{int(pid)}["{" <br> ".join(node_text)}"]')
        mermaid_code.append(f'    class pid{int(pid)} {style_class}')
        
        # Add relationships
        ppid = process_info['ppid']
        if ppid:
            edge_style = '-->'
            if style_class in ['suspicious', 'anomalous']:
                edge_style = '==>'
            mermaid_code.append(f'    pid{int(ppid)}{edge_style}pid{int(pid)}')
        
        for child in process_info['children']:
            child_pid = [k for k, v in process_tree.items() if v == child][0]
            add_process_node(child_pid, child)

    # Build the tree
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

def generate_gantt_diagram(process_tree, security_analyzer, behavior_analyzer, df):
    """Generate Gantt diagram with proper task format and behavior analysis."""
    mermaid_code = []
    mermaid_code.append("gantt")
    mermaid_code.append("    title Process Activity Timeline")
    mermaid_code.append("    dateFormat YYYY-MM-DD HH:mm:ss")
    mermaid_code.append("    axisFormat %H:%M:%S")
    
    min_time = df['timestamp'].min()
    max_time = df['timestamp'].max()
    
    # Get behavior scores for all processes
    frequencies, timestamps = behavior_analyzer.calculate_syscall_frequency(df)
    
    # Group processes by category and behavior
    sections = {
        'High Activity Processes': [],
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
            
            # Get both behavior and security analysis
            behavior_score, category_scores = behavior_analyzer.calculate_behavior_score(
                frequencies, timestamps, pid
            )
            alerts = security_analyzer.analyze_process(pid, process_info, df)
            has_alerts = any('⚠️' in alert for alert in alerts)
            
            # Categorize process based on both analyses
            if has_alerts:
                category = 'Suspicious Processes'
            elif behavior_score > 0.7:  # High behavior score threshold
                category = 'High Activity Processes'
            elif pid == 1 or 'root' in str(process_data['user'].iloc[0]).lower():
                category = 'System Processes'
            elif any(name in str(process_name).lower() for name in ['bash', 'sh', 'terminal']):
                category = 'User Processes'
            else:
                category = 'Background Services'
            
            # Format timestamps
            start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
            end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Create task name with behavior score
            task_name = clean_text_for_mermaid(f"{process_name}_{pid} (Score: {behavior_score:.2f})")
            
            # Determine status based on behavior and security analysis
            if has_alerts:
                status = "crit"
            elif behavior_score > 0.7:
                status = "active"
            elif behavior_score > 0.3:
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