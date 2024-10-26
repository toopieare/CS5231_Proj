# Process Flow Visualization Tool for Audit Logs

This tool analyzes and visualizes process relationships and behaviors from Linux audit logs generated by auditbeat. It creates a visualization showing process hierarchies, suspicious activities, and security alerts.

## Features

- Parses auditbeat NDJSON log files
- Builds process hierarchy trees
- Identifies suspicious process behaviors and security concerns
- Generates visualization using Mermaid.js
- Color-coded process classification:
  - 🟢 Green: Root processes (PID 1)
  - 🔵 Blue: Normal processes
  - 🟠 Orange: Privileged processes (running as root)
  - 🔴 Red: Suspicious processes

## Security Checks

The tool analyzes processes for:
- Hex-encoded process names
- Known suspicious process names
- Attack indicators in process names
- Suspicious syscalls (process injection, privilege escalation, etc.)
- Root execution
- Failed operations

## Installation

1. Clone the repository:
```bash
git clone https://github.com/toopieare/CS5231_Proj.git
cd CS5231_Proj
```

2. Create a virtual environment (recommended):
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Place your auditbeat log file in the `input` directory (default filename: `auditbeat-20241019.ndjson`)

2. Run the tool:
```bash
python main.py
```

3. View the results:
- Open `output/process_flow.html` in a web browser to see the visualization

## Configuration

The tool's configuration can be modified in `config.py`:
- `OUTPUT_DIR`: Directory for generated visualizations
- `LOG_FILE`: Path to the input log file
- `MERMAID_CONFIG`: Mermaid.js diagram configuration
- `STYLE_CLASSES`: Process node styling configuration

## Project Structure

```
CS5231_Proj/
├── config.py           # Configuration settings
├── main.py            # Main application entry point
├── requirements.txt   # Python dependencies
├── src/
│   ├── analysis/      # Process analysis and security checks
│   ├── data/          # Log parsing and data processing
│   ├── utils/         # Utility functions
│   └── visualization/ # Visualization generation
├── input/             # Input log files
└── output/            # Generated visualizations
```

## Understanding the Visualization

The visualization shows:
- Process hierarchies with parent-child relationships
- Process information (PID, name)
- Security alerts and suspicious behaviors
- System call patterns
- Privilege levels
- Failed operations

Edge types:
- Normal edges (-->) indicate standard parent-child relationships
- Bold edges (==>) indicate relationships involving suspicious processes