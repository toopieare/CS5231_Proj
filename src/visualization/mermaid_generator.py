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
        
        # Create node label with process info and alerts
        node_text = f"{process_name} (PID: {int(pid)})"
        if alerts:
            # Format alerts as a bulleted list in the node
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

    # Process all nodes starting with PID 1
    if 1 in process_tree:
        add_process_node(1, process_tree[1])
    
    # Process orphaned nodes
    for pid, info in process_tree.items():
        if pid not in processed_nodes:
            add_process_node(pid, info)

    return '\n'.join(mermaid_code)