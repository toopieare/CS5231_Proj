def create_html_output(mermaid_code, diagram_type="flowchart"):
    """Create HTML page with improved styling and layout."""
    mermaid_config = """
        mermaid.initialize({
            startOnLoad: true,
            flowchart: {
                htmlLabels: true,
                curve: 'basis',
                useMaxWidth: false,
                padding: 20
            },
            gantt: {
                fontSize: 24,
                numberSectionStyles: 4,
                axisFormat: '%H:%M:%S',
                barHeight: 40,
                barGap: 8,
                topPadding: 50,
                bottomPadding: 50,
                sectionPadding: 20,
                useMaxWidth: false,
                fontFamily: 'Arial',
                labelOffset: 75,
                tickInterval: '1minute'
            }
        });
    """
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Process Visualization</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.6.1/mermaid.min.js"></script>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
                overflow: hidden;
                width: 100vw;
                height: 100vh;
                box-sizing: border-box;
            }}
            .container {{
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                height: calc(100vh - 40px);
                display: flex;
                flex-direction: column;
                position: relative;
            }}
            .controls {{
                position: fixed;
                top: 20px;
                right: 20px;
                background: white;
                padding: 15px;
                border-radius: 8px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                z-index: 1000;
                display: flex;
                gap: 10px;
            }}
            .controls button {{
                padding: 12px 20px;
                cursor: pointer;
                background-color: #4a90e2;
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 16px;
                font-weight: 500;
                transition: all 0.2s ease;
                min-width: 100px;
                text-align: center;
            }}
            .controls button:hover {{
                background-color: #357abd;
                transform: translateY(-1px);
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .controls button:active {{
                transform: translateY(0);
            }}
            .diagram-wrapper {{
                flex: 1;
                position: relative;
                overflow: hidden;
                border: 1px solid #ddd;
                border-radius: 8px;
                margin-top: 60px;
            }}
            .diagram-container {{
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                overflow: auto;
                width: 100%;
                height: 100%;
            }}
            .mermaid {{
                transform-origin: 0 0;
                padding: 40px;
                {f"min-width: 200%;" if diagram_type == "gantt" else ""}
                {f"background-color: white;" if diagram_type == "gantt" else ""}
            }}
            /* Gantt-specific styles */
            .mermaid.gantt-chart {{
                font-family: Arial, sans-serif;
            }}
            .mermaid.gantt-chart .section {{
                font-weight: bold;
                font-size: 20px !important;
            }}
            .mermaid.gantt-chart .task {{
                font-size: 18px !important;
            }}
            .mermaid.gantt-chart text {{
                font-size: 16px !important;
            }}
            .mermaid.gantt-chart .tick text {{
                font-size: 14px !important;
                fill: #333;
            }}
            /* Override any inline styles */
            #mermaid-diagram text {{
                font-size: 16px !important;
            }}
            .tick > text {{
                font-size: 20px !important;
            }}
            .section {{
                font-size: 24px !important;
            }}
            g.tick {{
                font-size: 20px !important;
            }}
            .taskText {{
                font-size: 18px !important;
            }}
            /* Custom scrollbars */
            .diagram-container::-webkit-scrollbar {{
                width: 12px;
                height: 12px;
            }}
            .diagram-container::-webkit-scrollbar-track {{
                background: #f1f1f1;
                border-radius: 6px;
            }}
            .diagram-container::-webkit-scrollbar-thumb {{
                background: #888;
                border-radius: 6px;
                border: 3px solid #f1f1f1;
            }}
            .diagram-container::-webkit-scrollbar-thumb:hover {{
                background: #666;
            }}
            #error-display {{
                position: fixed;
                bottom: 20px;
                left: 20px;
                background: white;
                color: #e74c3c;
                padding: 15px 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                display: none;
                z-index: 1000;
                font-size: 14px;
                max-width: 80%;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="controls">
                <button onclick="zoomIn()">Zoom In</button>
                <button onclick="zoomOut()">Zoom Out</button>
                <button onclick="resetZoom()">Reset</button>
                <button onclick="fitToScreen()">Fit Screen</button>
            </div>
            
            <div class="diagram-wrapper">
                <div class="diagram-container" id="diagram-container">
                    <div class="mermaid {'gantt-chart' if diagram_type == 'gantt' else ''}" id="mermaid-diagram">
                        {mermaid_code}
                    </div>
                </div>
            </div>
            
            <div id="error-display"></div>
        </div>
        
        <script>
            {mermaid_config}
            
            // Initialize after Mermaid renders
            mermaid.init(undefined, ".mermaid").then(function() {{
                // Add this to force text size update after rendering
                if ("{diagram_type}" === "gantt") {{
                    document.querySelectorAll('.tick text').forEach(text => {{
                        text.style.fontSize = '20px';
                    }});
                    document.querySelectorAll('.taskText').forEach(text => {{
                        text.style.fontSize = '18px';
                    }});
                    // Start gantt with a wider view
                    setTimeout(() => {{
                        fitToScreen();
                    }}, 100);
                }}
            }});

            // ... (rest of your JavaScript remains the same)
    """
    
    # Add the rest of your existing JavaScript code here
    html_content += """
            let currentZoom = 1;
            const diagram = document.getElementById('mermaid-diagram');
            const container = document.getElementById('diagram-container');
            let isDragging = false;
            let startX, startY, scrollLeft, scrollTop;
            
            function zoomIn() {
                currentZoom = Math.min(currentZoom * 1.2, 10);
                updateZoom();
            }
            
            function zoomOut() {
                currentZoom = Math.max(currentZoom * 0.8, 0.1);
                updateZoom();
            }
            
            function resetZoom() {
                currentZoom = 1;
                updateZoom();
                container.scrollTo(0, 0);
            }
            
            function fitToScreen() {
                const containerRect = container.getBoundingClientRect();
                const diagramRect = diagram.getBoundingClientRect();
                
                const scaleX = containerRect.width / (diagramRect.width / currentZoom);
                const scaleY = containerRect.height / (diagramRect.height / currentZoom);
                currentZoom = Math.min(scaleX, scaleY) * 0.9;
                updateZoom();
                
                // Center the diagram
                container.scrollLeft = (diagramRect.width * currentZoom - containerRect.width) / 2;
            }
            
            function updateZoom() {
                const containerRect = container.getBoundingClientRect();
                const scrollCenterX = container.scrollLeft + containerRect.width / 2;
                const scrollCenterY = container.scrollTop + containerRect.height / 2;
                
                diagram.style.transform = `scale(${currentZoom})`;
                
                const newWidth = containerRect.width * currentZoom;
                const newHeight = containerRect.height * currentZoom;
                container.scrollLeft = (scrollCenterX * currentZoom) - (containerRect.width / 2);
                container.scrollTop = (scrollCenterY * currentZoom) - (containerRect.height / 2);
            }
            
            // Mouse wheel zoom
            container.addEventListener('wheel', function(e) {
                if (e.ctrlKey) {
                    e.preventDefault();
                    const delta = e.deltaY > 0 ? 0.9 : 1.1;
                    currentZoom = Math.min(Math.max(currentZoom * delta, 0.1), 10);
                    updateZoom();
                }
            });
            
            // Pan handling
            container.addEventListener('mousedown', function(e) {
                isDragging = true;
                container.style.cursor = 'grabbing';
                startX = e.pageX - container.offsetLeft;
                startY = e.pageY - container.offsetTop;
                scrollLeft = container.scrollLeft;
                scrollTop = container.scrollTop;
            });
            
            container.addEventListener('mousemove', function(e) {
                if (!isDragging) return;
                e.preventDefault();
                const x = e.pageX - container.offsetLeft;
                const y = e.pageY - container.offsetTop;
                const dx = x - startX;
                const dy = y - startY;
                container.scrollLeft = scrollLeft - dx;
                container.scrollTop = scrollTop - dy;
            });
            
            container.addEventListener('mouseup', function() {
                isDragging = false;
                container.style.cursor = 'default';
            });
            
            container.addEventListener('mouseleave', function() {
                isDragging = false;
                container.style.cursor = 'default';
            });
            
            // Error handling
            mermaid.parseError = function(err, hash) {
                const errorDisplay = document.getElementById('error-display');
                errorDisplay.style.display = 'block';
                errorDisplay.textContent = 'Mermaid Error: ' + err;
                console.error('Mermaid error:', err);
            };
        </script>
    </body>
    </html>
    """
    return html_content