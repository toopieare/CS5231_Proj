import os
from src.data.log_loader import load_audit_log
from src.data.data_processor import create_dataframe
from src.analysis.security_analyzer import SecurityAnalyzer
from src.analysis.behavior_analyzer import BehaviorAnalyzer
from src.analysis.process_tree import build_process_tree
from src.visualization.mermaid_generator import generate_mermaid_diagram, generate_gantt_diagram
from src.visualization.html_generator import create_html_output
from config import Config

def main():
    # Load and parse logs
    print("Loading audit logs...")
    logs = load_audit_log(Config.LOG_FILE)
    
    # Create DataFrame
    print("Processing data...")
    df = create_dataframe(logs)
    
    # Initialize analyzers
    print("Analyzing processes...")
    security_analyzer = SecurityAnalyzer()
    behavior_analyzer = BehaviorAnalyzer()
    
    # Build process tree
    process_tree = build_process_tree(df)
    
    # Generate visualizations
    print("Generating visualizations...")
    traditional_mermaid = generate_mermaid_diagram(process_tree, security_analyzer, df)
    gantt_mermaid = generate_gantt_diagram(process_tree, security_analyzer, behavior_analyzer, df)
    
    # Create output directory
    os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
    
    # Save visualizations with appropriate settings
    print("Saving visualizations...")
    with open(os.path.join(Config.OUTPUT_DIR, 'process_flow.html'), 'w', encoding='utf-8') as f:
        f.write(create_html_output(traditional_mermaid, diagram_type="flowchart"))
    
    with open(os.path.join(Config.OUTPUT_DIR, 'process_gantt.html'), 'w', encoding='utf-8') as f:
        f.write(create_html_output(gantt_mermaid, diagram_type="gantt"))
    
    print("Visualizations have been generated!")
    print(f"Open '{Config.OUTPUT_DIR}/process_flow.html' for the process tree view")
    print(f"Open '{Config.OUTPUT_DIR}/process_gantt.html' for the timeline view")


if __name__ == "__main__":
    main()