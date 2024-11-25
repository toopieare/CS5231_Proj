from collections import defaultdict
import numpy as np
from datetime import datetime, timedelta

class BehaviorAnalyzer:
    def __init__(self):
        self.syscall_categories = {
            'file': ['open', 'write', 'read', 'unlink', 'mkdir', 'rmdir'],
            'network': ['connect', 'bind', 'accept', 'socket', 'sendto', 'recvfrom'],
            'process': ['fork', 'clone', 'execve', 'kill'],
            'memory': ['mmap', 'mprotect', 'brk'],
            'privilege': ['setuid', 'setgid', 'chmod', 'chown']
        }
    
    def calculate_syscall_frequency(self, df):
        """Calculate syscall frequency per process over time."""
        frequencies = defaultdict(lambda: defaultdict(int))
        timestamps = defaultdict(list)
        
        for _, row in df.iterrows():
            pid = row['pid']
            syscall = row.get('syscall')  # Use get() to handle missing syscall
            timestamp_str = row.get('@timestamp') or row.get('timestamp')  # Try both possible timestamp fields
            
            if syscall and timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    frequencies[pid][syscall] += 1
                    timestamps[pid].append(timestamp)
                except (ValueError, AttributeError):
                    continue  # Skip invalid timestamps
        
        return frequencies, timestamps
    
    def calculate_behavior_score(self, frequencies, timestamps, pid):
        """Calculate a behavior score based on syscall patterns."""
        if pid not in frequencies or not frequencies[pid]:
            return 0, {}
        
        # Calculate time-based metrics
        if not timestamps[pid]:
            return 0, {}
            
        time_range = max(timestamps[pid]) - min(timestamps[pid])
        calls_per_second = len(timestamps[pid]) / max(time_range.total_seconds(), 1)
        
        # Calculate category scores
        category_scores = defaultdict(float)
        total_calls = sum(frequencies[pid].values())
        
        for category, syscalls in self.syscall_categories.items():
            category_count = sum(frequencies[pid].get(syscall, 0) for syscall in syscalls)
            category_scores[category] = category_count / max(total_calls, 1)
        
        # Calculate anomaly score based on syscall diversity and frequency
        syscall_diversity = len(frequencies[pid]) / max(total_calls, 1)
        frequency_score = min(calls_per_second / 10, 1)  # Normalize to 0-1
        
        # Combine scores
        behavior_score = (
            syscall_diversity * 0.3 +
            frequency_score * 0.3 +
            sum(category_scores.values()) * 0.4
        )
        
        return behavior_score, category_scores

    def get_process_color(self, behavior_score, category_scores):
        """Generate RGB color based on behavior score and categories."""
        if not category_scores:
            return "#b3e0ff"  # Default blue
        
        # Base color components
        r = int(255 * (category_scores.get('process', 0) + category_scores.get('privilege', 0)))
        g = int(255 * (1 - behavior_score))  # Lower score = more green
        b = int(255 * (category_scores.get('network', 0) + category_scores.get('file', 0)))
        
        # Ensure valid RGB values
        r = min(max(r, 0), 255)
        g = min(max(g, 0), 255)
        b = min(max(b, 0), 255)
        
        return f"#{r:02x}{g:02x}{b:02x}"