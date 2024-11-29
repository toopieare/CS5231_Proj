import torch
from torch import nn
import torch.nn.functional as F
from collections import defaultdict
import numpy as np
from datetime import datetime, timedelta

class ProcessAutoencoder(nn.Module):
    def __init__(self, input_size):
        super(ProcessAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_size, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 16)
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, input_size)
        )
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

class MLBehaviorAnalyzer:
    """ML-based behavior analyzer that runs in parallel with traditional analysis."""
    
    def __init__(self, syscall_categories):
        self.syscall_categories = syscall_categories
        self.feature_size = len(syscall_categories) * 2 + 3
        self.model = ProcessAutoencoder(self.feature_size)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        self.reconstruction_errors = []
        self.error_threshold = None
        
    def extract_features(self, df, pid):
        """Extract features from process behavior."""
        process_data = df[df['pid'] == pid]
        if process_data.empty:
            return None
            
        total_calls = len(process_data)
        category_freqs = []
        category_rates = []
        
        for category, syscalls in self.syscall_categories.items():
            category_calls = process_data[process_data['syscall'].isin(syscalls)]
            freq = len(category_calls) / max(total_calls, 1)
            category_freqs.append(freq)
            
            if len(process_data) >= 2:
                time_range = (process_data['timestamp'].max() - process_data['timestamp'].min()).total_seconds()
                rate = len(category_calls) / max(time_range, 1)
                category_rates.append(rate)
            else:
                category_rates.append(0)
        
        if len(process_data) >= 2:
            duration = (process_data['timestamp'].max() - process_data['timestamp'].min()).total_seconds()
            avg_interval = duration / len(process_data)
            calls_per_second = len(process_data) / max(duration, 1)
        else:
            duration = avg_interval = calls_per_second = 0
        
        features = category_freqs + category_rates + [duration, avg_interval, calls_per_second]
        return torch.tensor(features, dtype=torch.float32)
    
    def train(self, df):
        """Train the autoencoder on all processes."""
        print("Training ML model...")
        X = []
        all_pids = df['pid'].unique()
        
        for pid in all_pids:
            features = self.extract_features(df, pid)
            if features is not None:
                X.append(features)
        
        if not X:
            print("No valid training data found")
            return
            
        X = torch.stack(X).to(self.device)
        X_mean = X.mean(dim=0)
        X_std = X.std(dim=0)
        X_normalized = (X - X_mean) / (X_std + 1e-7)
        
        self.X_mean = X_mean
        self.X_std = X_std
        
        optimizer = torch.optim.Adam(self.model.parameters())
        
        self.model.train()
        for epoch in range(100):  # 100 epochs
            optimizer.zero_grad()
            reconstructed = self.model(X_normalized)
            loss = F.mse_loss(reconstructed, X_normalized)
            loss.backward()
            optimizer.step()
            
            if (epoch + 1) % 10 == 0:
                print(f'Epoch [{epoch+1}/100], Loss: {loss.item():.4f}')
        
        # Calculate threshold
        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(X_normalized)
            errors = F.mse_loss(reconstructed, X_normalized, reduction='none').mean(dim=1)
            self.reconstruction_errors = errors.cpu().numpy()
            self.error_threshold = np.mean(self.reconstruction_errors) + 2 * np.std(self.reconstruction_errors)
        
        print("ML model training completed")
    
    def analyze_process(self, df, pid):
        """Analyze a process using the trained autoencoder."""
        if not hasattr(self, 'X_mean'):
            return 0.0  # Return 0 if model hasn't been trained
            
        self.model.eval()
        features = self.extract_features(df, pid)
        
        if features is None:
            return 0.0
            
        with torch.no_grad():
            features = features.to(self.device)
            features_normalized = (features - self.X_mean) / (self.X_std + 1e-7)
            reconstructed = self.model(features_normalized)
            error = F.mse_loss(reconstructed, features_normalized).item()
            
            score = min(error / self.error_threshold if self.error_threshold else 0.0, 1.0)
            
        return score