import os
from src.data.log_loader import load_audit_log
from src.data.data_processor import create_dataframe
from src.analysis.security_analyzer import SecurityAnalyzer
from src.analysis.process_tree import build_process_tree
from src.visualization.mermaid_generator import generate_mermaid_diagram
from src.visualization.html_generator import create_html_output
from config import Config

def main():
    # Load and parse logs
    logs = load_audit_log(Config.LOG_FILE)
    
    # Create DataFrame
    df = create_dataframe(logs)
    
    # Generate visualization
    analyzer = SecurityAnalyzer()
    mermaid_code = generate_mermaid_diagram(build_process_tree(df), analyzer, df)
    
    # Create output directory
    os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
    
    # Save HTML visualization
    html_content = create_html_output(mermaid_code)
    output_path = os.path.join(Config.OUTPUT_DIR, 'process_flow.html')
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print("Process flow visualization has been generated!")
    print(f"Open '{output_path}' in your web browser to view the visualization.")

if __name__ == "__main__":
    main()