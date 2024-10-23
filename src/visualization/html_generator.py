def create_html_output(mermaid_code):
    """Create HTML page with Mermaid diagram."""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Process Flow Visualization</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.6.1/mermaid.min.js"></script>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f5f5f5;
            }}
            .container {{
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .legend {{
                margin-top: 20px;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }}
            .legend-item {{
                margin: 5px 0;
                display: flex;
                align-items: center;
            }}
            .legend-color {{
                width: 20px;
                height: 20px;
                margin-right: 10px;
                border: 1px solid #333;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Process Flow Visualization</h1>
            <div class="mermaid">
                {mermaid_code}
            </div>
            
            <div class="legend">
                <h3>Legend:</h3>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #99ff99;"></div>
                    <span>Root Process (PID 1)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #b3e0ff;"></div>
                    <span>Normal Process</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #ffb366;"></div>
                    <span>Privileged Process (Running as Root)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #ffcccc;"></div>
                    <span>Suspicious Process</span>
                </div>
            </div>
        </div>
        <script>
            mermaid.initialize({{ 
                startOnLoad: true,
                flowchart: {{
                    curve: 'basis',
                    nodeSpacing: 50,
                    rankSpacing: 50,
                    padding: 20
                }}
            }});
        </script>
    </body>
    </html>
    """
    return html_content