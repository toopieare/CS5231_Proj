import re
from collections import defaultdict

class SecurityAnalyzer:
    def __init__(self):
        # Enhanced suspicious patterns
        self.suspicious_patterns = {
            # Suspicious process name patterns
            'encoded_name': [
                r'^[0-9A-Fa-f]+$',                    # Pure hex strings
                r'[0-9A-Fa-f]{32,}',                  # Long hex strings
                r'%..[%]..',                          # URL encoded sequences
                r'\\x[0-9a-fA-F]{2}',                # Hex escaped characters
                r'base64:',                           # Base64 indicators
                r'[A-Za-z0-9+/]{32,}={0,2}$'         # Potential base64 content
            ],
            
            # Known suspicious process names
            'suspicious_names': [
                'cmd.exe', 'powershell', 'bash', 'nc', 'netcat', 'wget', 'curl',
                'ncat', 'socat', 'nmap', 'python', 'perl', 'ruby', 'nohup',
                'dev/tcp', 'dev/udp', '/tmp/', '.sh', '.pl', '.py'
            ],
            
            # Attack-related keywords
            'attack_indicators': [
                'attack', 'exploit', 'hack', 'malware', 'backdoor', 'reverse',
                'shell', 'payload', 'inject', 'tunnel', 'crypto', 'miner'
            ],
            
            # Obfuscation patterns
            'obfuscation': [
                r'\s{2,}',                            # Multiple spaces
                r'`.*`',                              # Backtick execution
                r'\$\{.*\}',                          # Variable expansion
                r'\\[0-9]{1,3}',                      # Octal encoding
                r'\\u[0-9a-fA-F]{4}'                 # Unicode encoding
            ]
        }
        
        # Enhanced syscall categories
        self.suspicious_syscalls = {
            'process_injection': [
                'ptrace', 'memfd_create', 'process_vm_writev',
                'process_vm_readv', 'inject_thread'
            ],
            'privilege_escalation': [
                'setuid', 'setgid', 'setreuid', 'setregid',
                'setresuid', 'setresgid', 'capset'
            ],
            'file_operations': [
                'open', 'write', 'unlink', 'rename', 'chmod',
                'chown', 'mkdir', 'rmdir', 'link'
            ],
            'network': [
                'connect', 'bind', 'accept', 'socket', 'sendto',
                'recvfrom', 'sendmsg', 'recvmsg'
            ],
            'execution': [
                'execve', 'fork', 'clone', 'vfork', 'execveat',
                'spawn', 'system'
            ],
            'hiding': [
                'unlink', 'rename', 'rmdir', 'delete_module',
                'prctl'
            ]
        }
        
        # New: Behavior patterns that might indicate malicious activity
        self.suspicious_behaviors = {
            'frequent_exec': {
                'syscalls': ['execve', 'fork', 'clone'],
                'threshold': 10,  # Number of calls in short period
                'window': 60      # Time window in seconds
            },
            'file_tampering': {
                'syscalls': ['unlink', 'rename', 'rmdir'],
                'threshold': 5,
                'window': 60
            },
            'privilege_abuse': {
                'syscalls': ['setuid', 'setgid', 'capset'],
                'threshold': 3,
                'window': 60
            },
            'network_abuse': {
                'syscalls': ['connect', 'bind', 'sendto'],
                'threshold': 20,
                'window': 60
            }
        }

    def check_encoded_name(self, process_name):
        """Check for encoded or obfuscated process names."""
        alerts = []
        
        # Check each encoding pattern
        for pattern in self.suspicious_patterns['encoded_name']:
            if re.search(pattern, str(process_name)):
                alerts.append(f"⚠️ Potentially encoded/obfuscated name (pattern: {pattern})")
                
        # Check for unusual character distributions
        if process_name:
            char_freq = defaultdict(int)
            for char in str(process_name):
                char_freq[char] += 1
            
            # Check for unusual character distribution
            total_chars = len(str(process_name))
            hex_chars = sum(char_freq[c] for c in '0123456789abcdefABCDEF')
            if hex_chars / total_chars > 0.7:  # More than 70% hex characters
                alerts.append("⚠️ High concentration of hex characters")
                
            # Check for unusual Unicode characters
            unusual_chars = sum(1 for c in str(process_name) if ord(c) > 127)
            if unusual_chars > 0:
                alerts.append(f"⚠️ Contains {unusual_chars} non-ASCII characters")
        
        return alerts

    def analyze_syscall_patterns(self, df, pid):
        """Analyze syscall patterns for suspicious behavior."""
        alerts = []
        process_df = df[df['pid'] == pid]
        
        # Group syscalls by time windows
        time_windows = defaultdict(lambda: defaultdict(int))
        
        for _, row in process_df.iterrows():
            syscall = row.get('syscall')
            timestamp = row.get('timestamp')
            
            if syscall and timestamp:
                window_key = int(timestamp.timestamp() / 60)  # 60-second windows
                time_windows[window_key][syscall] += 1
        
        # Check each behavior pattern
        for behavior, config in self.suspicious_behaviors.items():
            for window, syscalls in time_windows.items():
                count = sum(syscalls.get(syscall, 0) for syscall in config['syscalls'])
                if count >= config['threshold']:
                    alerts.append(f"⚠️ Suspicious {behavior}: {count} relevant syscalls in 60s")
        
        return alerts

    def analyze_process(self, pid, process_info, df):
        """Analyze a process for suspicious behavior."""
        alerts = []
        try:
            process_name = process_info['process']
            
            # Check process name patterns
            if process_name:
                # Check for encoded/obfuscated names
                alerts.extend(self.check_encoded_name(process_name))
                
                # Check for suspicious known names
                for pattern in self.suspicious_patterns['suspicious_names']:
                    if pattern.lower() in str(process_name).lower():
                        alerts.append(f"⚠️ Contains suspicious pattern: {pattern}")
                
                # Check for attack indicators
                for indicator in self.suspicious_patterns['attack_indicators']:
                    if indicator.lower() in str(process_name).lower():
                        alerts.append(f"⚠️ Contains attack indicator: {indicator}")
                
                # Check for obfuscation patterns
                for pattern in self.suspicious_patterns['obfuscation']:
                    if re.search(pattern, str(process_name)):
                        alerts.append(f"⚠️ Possible obfuscation detected: {pattern}")
            
            # Analyze syscall patterns
            process_logs = df[df['pid'] == pid]
            syscalls = process_logs['syscall'].dropna().value_counts()
            
            for syscall_type, syscall_list in self.suspicious_syscalls.items():
                matching_syscalls = [s for s in syscalls.index if s in syscall_list]
                if matching_syscalls:
                    alerts.append(f"🔍 {syscall_type.replace('_', ' ').title()}: {', '.join(matching_syscalls)}")
            
            # Check for privilege escalation
            if '0' in process_logs['uid'].astype(str).values:
                alerts.append("⚡ Running as root")
            
            # Check for failed operations
            failed_ops = process_logs[process_logs['result'] == 'fail']
            if not failed_ops.empty:
                alerts.append(f"❌ {len(failed_ops)} failed operations")
            
            # Analyze syscall patterns over time
            alerts.extend(self.analyze_syscall_patterns(df, pid))

        except Exception as e:
            print(f"Error analyzing process {pid}: {str(e)}")
            
        return alerts