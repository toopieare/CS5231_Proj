import os
from collections import defaultdict

def generate_comparison_report(df, traditional_analyzer, ml_analyzer, process_tree):
    """Generate HTML report comparing traditional and ML analysis."""
    results = _collect_analysis_results(df, traditional_analyzer, ml_analyzer, process_tree)
    
    # Generate HTML report
    report_path = os.path.join('output', 'analysis_comparison.html')
    _generate_comparison_html(results, report_path)

def _collect_analysis_results(df, traditional_analyzer, ml_analyzer, process_tree):
    """Collect analysis results for all processes."""
    results = []
    frequencies, timestamps = traditional_analyzer.calculate_syscall_frequency(df)
    
    for pid, process_info in process_tree.items():
        try:
            result = _analyze_single_process(
                pid, process_info, df, 
                traditional_analyzer, ml_analyzer,
                frequencies, timestamps
            )
            results.append(result)
        except Exception as e:
            print(f"Error processing PID {pid}: {str(e)}")
            continue
    
    # Sort results by scores
    results.sort(key=lambda x: (-x['traditional_score'], -x['ml_score']))
    return results

def _analyze_single_process(pid, process_info, df, traditional_analyzer, 
                          ml_analyzer, frequencies, timestamps):
    """Analyze a single process and return its results."""
    # Get traditional analysis score
    behavior_score, category_scores = traditional_analyzer.calculate_behavior_score(
        frequencies, timestamps, pid
    )
    
    # Get ML analysis score
    ml_score = ml_analyzer.analyze_process(df, pid)
    
    # Get process data
    process_data = df[df['pid'] == pid]
    syscalls = process_data['syscall'].dropna().value_counts()
    
    # Print detailed debug info
    _print_process_debug_info(pid, process_info, behavior_score, 
                            syscalls, timestamps, category_scores, ml_score)
    
    return {
        'pid': pid,
        'process': process_info['process'] or 'unknown',
        'traditional_score': float(behavior_score),
        'ml_score': float(ml_score),
        'category_scores': category_scores,
        'syscall_details': {
            'count': len(syscalls),
            'types': list(syscalls.index),
            'total_events': len(process_data),
            'timestamp_count': len(timestamps.get(pid, [])),
            'frequency_keys': list(frequencies.get(pid, {}).keys())
        }
    }

def _print_process_debug_info(pid, process_info, behavior_score, syscalls, 
                            timestamps, category_scores, ml_score):
    """Print debug information for a process."""
    print(f"\nPID {pid} ({process_info['process']}) analysis:")
    print(f"  Behavior score: {behavior_score:.3f}")
    print(f"  Total syscalls: {len(syscalls)}")
    print(f"  Raw syscall counts: {dict(syscalls)}")
    print(f"  Timestamps available: {len(timestamps.get(pid, []))}")
    print(f"  Categories: {category_scores}")
    print(f"  ML score: {ml_score:.3f}")

def validate_behavior_scores(df, analyzer, pid):
    """Validate behavior score calculation for a specific PID."""
    frequencies, timestamps = analyzer.calculate_syscall_frequency(df)
    
    if pid not in frequencies or not frequencies[pid]:
        print(f"No frequency data for PID {pid}")
        return
        
    if pid not in timestamps or not timestamps[pid]:
        print(f"No timestamp data for PID {pid}")
        return
    
    _print_validation_data(pid, frequencies, timestamps, analyzer)
    return _calculate_validation_score(pid, frequencies, timestamps, analyzer)

def _print_validation_data(pid, frequencies, timestamps, analyzer):
    """Print validation data for a process."""
    print(f"\nValidating PID {pid}:")
    print("Frequencies:")
    for syscall, count in frequencies[pid].items():
        print(f"  {syscall}: {count}")
    
    print("\nTimestamps:")
    print(f"  First: {min(timestamps[pid])}")
    print(f"  Last: {max(timestamps[pid])}")
    print(f"  Count: {len(timestamps[pid])}")

def _calculate_validation_score(pid, frequencies, timestamps, analyzer):
    """Calculate and print validation score components."""
    time_range = max(timestamps[pid]) - min(timestamps[pid])
    calls_per_second = len(timestamps[pid]) / max(time_range.total_seconds(), 1)
    
    total_calls = sum(frequencies[pid].values())
    syscall_diversity = len(frequencies[pid]) / max(total_calls, 1)
    frequency_score = min(calls_per_second / 10, 1)
    
    print("\nScore Components:")
    print(f"  Syscall diversity: {syscall_diversity:.3f}")
    print(f"  Frequency score: {frequency_score:.3f}")
    
    category_scores = _calculate_category_scores(
        analyzer, frequencies, pid, total_calls
    )
    
    behavior_score = (
        syscall_diversity * 0.3 +
        frequency_score * 0.3 +
        sum(category_scores.values()) * 0.4
    )
    
    print(f"\nFinal behavior score: {behavior_score:.3f}")
    return behavior_score

def _calculate_category_scores(analyzer, frequencies, pid, total_calls):
    """Calculate category scores for validation."""
    category_scores = {}
    for category, syscalls in analyzer.syscall_categories.items():
        category_count = sum(frequencies[pid].get(syscall, 0) for syscall in syscalls)
        category_scores[category] = category_count / max(total_calls, 1)
        print(f"  {category} score: {category_scores[category]:.3f}")
    return category_scores

# Add this function to src/analysis/analysis_reporter.py

def _generate_comparison_html(results, output_path):
    """Create HTML comparison report with additional debug information."""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Analysis Method Comparison</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
            th { background-color: #f4f4f4; }
            .highlight { background-color: #fff3cd; }
            .significant-diff { background-color: #f8d7da; }
            .chart { margin: 20px 0; height: 400px; }
            .debug-info { font-size: 0.8em; color: #666; white-space: pre-wrap; }
        </style>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    </head>
    <body>
        <h1>Process Analysis Comparison</h1>
        
        <div id="scatterPlot" class="chart"></div>
        
        <h2>Detailed Results</h2>
        <table>
            <tr>
                <th>PID</th>
                <th>Process</th>
                <th>Traditional Score</th>
                <th>ML Score</th>
                <th>Difference</th>
                <th>Category Scores</th>
                <th>Debug Info</th>
            </tr>
    """
    
    scatter_data = {
        'traditional': [],
        'ml': [],
        'pids': [],
        'processes': []
    }
    
    for result in results:
        difference = abs(result['traditional_score'] - result['ml_score'])
        row_class = 'significant-diff' if difference > 0.3 else 'highlight' if difference > 0.1 else ''
        
        scatter_data['traditional'].append(result['traditional_score'])
        scatter_data['ml'].append(result['ml_score'])
        scatter_data['pids'].append(str(result['pid']))
        scatter_data['processes'].append(str(result['process']))
        
        # Add debug information
        debug_info = f"""
            Syscall count: {result['syscall_details']['count']}
            Event count: {result['syscall_details']['total_events']}
            Timestamp count: {result['syscall_details']['timestamp_count']}
            Syscall types: {', '.join(result['syscall_details']['types'])}
            Frequency keys: {', '.join(result['syscall_details']['frequency_keys'])}
        """
        
        html_content += f"""
            <tr class="{row_class}">
                <td>{result['pid']}</td>
                <td>{result['process']}</td>
                <td>{result['traditional_score']:.3f}</td>
                <td>{result['ml_score']:.3f}</td>
                <td>{difference:.3f}</td>
                <td>{', '.join(f'{k}: {v:.2f}' for k, v in result['category_scores'].items())}</td>
                <td class="debug-info">{debug_info}</td>
            </tr>
        """
    
    # Add visualization
    html_content += """
        </table>
        
        <h2>Score Distribution</h2>
        <div id="histograms" class="chart"></div>
        
        <script>
            // Scatter plot
            var scatter = {
                x: %s,
                y: %s,
                mode: 'markers',
                type: 'scatter',
                text: %s,
                hovertemplate: 'Process: %%{text}<br>Traditional: %%{x:.3f}<br>ML: %%{y:.3f}',
            };
            
            var scatterLayout = {
                title: 'Traditional vs ML Scores',
                xaxis: {title: 'Traditional Score'},
                yaxis: {title: 'ML Score'},
                showlegend: false
            };
            
            Plotly.newPlot('scatterPlot', [scatter], scatterLayout);
            
            // Histograms
            var traditional_hist = {
                x: %s,
                type: 'histogram',
                name: 'Traditional Scores',
                opacity: 0.7
            };
            
            var ml_hist = {
                x: %s,
                type: 'histogram',
                name: 'ML Scores',
                opacity: 0.7
            };
            
            var histLayout = {
                title: 'Score Distributions',
                barmode: 'overlay',
                xaxis: {title: 'Score'},
                yaxis: {title: 'Count'}
            };
            
            Plotly.newPlot('histograms', [traditional_hist, ml_hist], histLayout);
        </script>
    </body>
    </html>
    """ % (
        str(scatter_data['traditional']),
        str(scatter_data['ml']),
        str(scatter_data['processes']),
        str(scatter_data['traditional']),
        str(scatter_data['ml'])
    )
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)