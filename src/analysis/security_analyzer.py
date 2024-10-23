import re

class SecurityAnalyzer:
    def __init__(self):
        self.suspicious_patterns = {
            'encoded_name': r'^[0-9A-Fa-f]+$',
            'suspicious_names': ['cmd.exe', 'powershell', 'bash', 'nc', 'netcat', 'wget', 'curl'],
            'attack_indicators': ['attack', 'exploit', 'hack', 'malware', 'program']
        }
        
        self.suspicious_syscalls = {
            'process_injection': ['ptrace', 'memfd_create'],
            'privilege_escalation': ['setuid', 'setgid', 'setreuid'],
            'file_operations': ['open', 'write', 'unlink'],
            'network': ['connect', 'bind', 'accept'],
            'execution': ['execve', 'fork', 'clone']
        }

    def analyze_process(self, pid, process_info, df):
        """Analyze a process for suspicious behavior."""
        alerts = []
        try:
            process_logs = df[df['pid'] == pid]
            
            process_name = process_info['process']
            if process_name:
                # Check for hex-encoded names
                if re.match(self.suspicious_patterns['encoded_name'], str(process_name)):
                    alerts.append("⚠️ Hex-encoded name")
                
                # Check for suspicious names
                for pattern in self.suspicious_patterns['suspicious_names']:
                    if pattern.lower() in str(process_name).lower():
                        alerts.append(f"⚠️ Contains suspicious pattern: {pattern}")
                
                # Check for attack indicators
                for indicator in self.suspicious_patterns['attack_indicators']:
                    if indicator.lower() in str(process_name).lower():
                        alerts.append(f"⚠️ Contains attack indicator: {indicator}")

            # Analyze syscalls
            syscalls = process_logs['syscall'].dropna().value_counts()
            for syscall_type, syscall_list in self.suspicious_syscalls.items():
                matching_syscalls = [s for s in syscalls.index if s in syscall_list]
                if matching_syscalls:
                    alerts.append(f"🔍 {syscall_type.replace('_', ' ').title()}: {', '.join(matching_syscalls)}")

            # Check for root execution
            if '0' in process_logs['uid'].astype(str).values:
                alerts.append("⚡ Running as root")

            # Check for failed operations
            failed_ops = process_logs[process_logs['result'] == 'fail']
            if not failed_ops.empty:
                alerts.append(f"❌ {len(failed_ops)} failed operations")

        except Exception as e:
            print(f"Error analyzing process {pid}: {str(e)}")
            
        return alerts