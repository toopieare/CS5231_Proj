class Config:
    OUTPUT_DIR = './output'
    LOG_FILE = './input/auditbeat-20241125-4.ndjson'
    
    MERMAID_CONFIG = {
        'curve': 'basis',
        'nodeSpacing': 50,
        'rankSpacing': 50,
        'padding': 20
    }
    
    STYLE_CLASSES = {
        'normal': 'fill:#b3e0ff,stroke:#333,stroke-width:1px',
        'suspicious': 'fill:#ffcccc,stroke:#red,stroke-width:2px',
        'root': 'fill:#99ff99,stroke:#333,stroke-width:1px',
        'privileged': 'fill:#ffb366,stroke:#333,stroke-width:2px'
    }