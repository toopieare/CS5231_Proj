import os
from src.data.log_loader import load_audit_log
from src.data.data_processor import create_dataframe
from src.analysis.security_analyzer import SecurityAnalyzer
from src.analysis.behavior_analyzer import BehaviorAnalyzer
from src.analysis.ml_behavior_analyzer import MLBehaviorAnalyzer
from src.analysis.process_tree import build_process_tree
from src.visualization.mermaid_generator import generate_mermaid_diagram, generate_gantt_diagram
from src.visualization.html_generator import create_html_output
from src.analysis.analysis_reporter import (
    generate_comparison_report,
    validate_behavior_scores
)
from config import Config

def initialize_analyzers(df):
    """Initialize and prepare all analyzers."""
    print("Initializing analyzers...")
    security_analyzer = SecurityAnalyzer()
    behavior_analyzer = BehaviorAnalyzer()
    
    # Initialize and train ML analyzer
    print("Initializing ML analyzer...")
    ml_analyzer = MLBehaviorAnalyzer(behavior_analyzer.syscall_categories)
    ml_analyzer.train(df)
    
    return security_analyzer, behavior_analyzer, ml_analyzer

def generate_visualizations(process_tree, security_analyzer, behavior_analyzer, df):
    """Generate all visualizations."""
    print("Generating visualizations...")
    traditional_mermaid = generate_mermaid_diagram(process_tree, security_analyzer, behavior_analyzer, df)
    gantt_mermaid = generate_gantt_diagram(process_tree, security_analyzer, behavior_analyzer, df)
    return traditional_mermaid, gantt_mermaid

def save_visualizations(traditional_mermaid, gantt_mermaid, output_dir):
    """Save visualization files."""
    print("Saving visualizations...")
    os.makedirs(output_dir, exist_ok=True)
    
    with open(os.path.join(output_dir, 'process_flow.html'), 'w', encoding='utf-8') as f:
        f.write(create_html_output(traditional_mermaid, diagram_type="flowchart"))
    
    with open(os.path.join(output_dir, 'process_gantt.html'), 'w', encoding='utf-8') as f:
        f.write(create_html_output(gantt_mermaid, diagram_type="gantt"))

def main():
    # Load and process data
    print("Loading audit logs...")
    logs = load_audit_log(Config.LOG_FILE)
    
    print("Processing data...")
    df = create_dataframe(logs)
    
    # Initialize analyzers
    security_analyzer, behavior_analyzer, ml_analyzer = initialize_analyzers(df)
    
    # Build process tree
    process_tree = build_process_tree(df)
    
    # Validate behavior scores for specific processes
    print("\nValidating behavior scores for key processes...")
    target_pids = [4427, 4428, 4430]  # Python processes from example
    for pid in target_pids:
        validate_behavior_scores(df, behavior_analyzer, pid)
    
    # Generate visualizations
    traditional_mermaid, gantt_mermaid = generate_visualizations(
        process_tree, security_analyzer, behavior_analyzer, df
    )
    
    # Generate comparison report
    print("Generating analysis comparison...")
    generate_comparison_report(df, behavior_analyzer, ml_analyzer, process_tree)
    
    # Save visualizations
    save_visualizations(traditional_mermaid, gantt_mermaid, Config.OUTPUT_DIR)
    
    print("Visualizations have been generated!")
    print(f"Open '{Config.OUTPUT_DIR}/process_flow.html' for the process tree view")
    print(f"Open '{Config.OUTPUT_DIR}/process_gantt.html' for the timeline view")

if __name__ == "__main__":
    main()