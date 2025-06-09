import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, OneHotEncoder, RobustScaler
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
import joblib
import logging
from pathlib import Path
import pandas as pd
from datetime import datetime
from sklearn.metrics import roc_curve, auc
from typing import Dict, List, Tuple, Optional
from .feature_selector import FeatureSelector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, contamination: float = 0.1, n_features: int = 50, n_components: float = 0.95):
        """
        Initialize the anomaly detector.
        
        Args:
            contamination: Expected proportion of anomalies in the data
            n_features: Number of features to select
            n_components: Number of PCA components to keep (float < 1.0 for variance ratio, int for exact number)
        """
        self.contamination = contamination
        self.n_components = n_components
        self.feature_selector = FeatureSelector(n_features=n_features)
        self.is_trained = False
        self.model_path = Path('data/models/anomaly_detector.joblib')
        self.feature_importance = None
        self.anomaly_threshold = -0.5  # Threshold for anomaly scores
        self.selected_feature_names = None
        self.numeric_features = None
        self.categorical_features = None
        self.feature_types = None  # Store feature types for consistency
        
        # Create preprocessing pipeline
        self.pipeline = None  # Will be initialized in train() when we know feature types
        
        # Define attack type correlation rules
        self.attack_correlation_rules = {
            'dos': {
                'features': ['packets_per_second', 'bytes_per_second'],
                'threshold': 0.7
            },
            'port_scan': {
                'features': ['unique_dst_ports', 'unique_src_ports'],
                'threshold': 0.6
            },
            'dns_amplification': {
                'features': ['dns_queries', 'dns_responses'],
                'threshold': 0.8
            },
            'tcp_syn_flood': {
                'features': ['tcp_flag_distribution'],
                'threshold': 0.7
            },
            'dns_tunneling': {
                'features': ['avg_packet_length', 'dns_queries'],
                'threshold': 0.6
            },
            'http_flood': {
                'features': ['http_requests', 'unique_http_hosts'],
                'threshold': 0.7
            }
        }
    
    def _engineer_features(self, features: pd.DataFrame) -> pd.DataFrame:
        """Engineer additional features for network traffic analysis."""
        df = features.copy()
        
        # Handle timestamps and basic time-based features
        if 'timestamp' in df.columns:
            df['timestamp'] = df['timestamp'].apply(lambda x: float(x) if hasattr(x, 'to_eng_string') else x)
            df['timestamp_numeric'] = df['timestamp'].astype(float)
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
            df['time_diff'] = df['timestamp'].diff().dt.total_seconds()
            df['packets_per_second'] = 1 / df['time_diff'].replace(0, np.nan)
            df = df.drop(columns=['timestamp'])
        else:
            df['timestamp_numeric'] = np.arange(len(df))
            df['time_diff'] = 1.0
            df['packets_per_second'] = 1.0
        
        # Convert ports to numeric if they exist
        for port in ['src_port', 'dst_port']:
            if port in df.columns:
                df[port] = pd.to_numeric(df[port], errors='coerce').fillna(0).astype(int)
        
        # Calculate flow statistics
        flow_features = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
        if all(col in df.columns for col in flow_features):
            # Basic flow statistics
            flow_group = df.groupby(['src_ip', 'dst_ip', 'src_port', 'dst_port'])
            df['flow_duration'] = flow_group['timestamp_numeric'].transform(lambda x: x.max() - x.min())
            df['flow_packet_count'] = flow_group['length'].transform('count')
            df['flow_byte_count'] = flow_group['length'].transform('sum')
            df['flow_port_count'] = flow_group['dst_port'].transform('nunique')
            
            # Flow rates
            df['flow_packets_per_second'] = df['flow_packet_count'] / df['flow_duration'].replace(0, np.nan)
            df['flow_bytes_per_second'] = df['flow_byte_count'] / df['flow_duration'].replace(0, np.nan)
            
            # Additional flow features
            ip_group = df.groupby(['src_ip', 'dst_ip'])
            df['unique_ports_per_flow'] = ip_group['dst_port'].transform('nunique')
            df['packets_per_flow'] = ip_group['length'].transform('count')
            df['bytes_per_flow'] = ip_group['length'].transform('sum')
            
            # Fill NaN values
            for col in ['flow_packets_per_second', 'flow_bytes_per_second']:
                df[col] = df[col].fillna(0)
        else:
            # Default values for missing flow features
            default_flow_features = {
                'flow_duration': 1.0,
                'flow_packet_count': 1,
                'flow_byte_count': df['length'] if 'length' in df.columns else 0,
                'flow_port_count': 1,
                'flow_packets_per_second': 1.0,
                'flow_bytes_per_second': df['length'] if 'length' in df.columns else 0,
                'unique_ports_per_flow': 1,
                'packets_per_flow': 1,
                'bytes_per_flow': df['length'] if 'length' in df.columns else 0
            }
            for feature, value in default_flow_features.items():
                df[feature] = value
        
        # DNS-specific features
        if 'dns_qr' in df.columns and 'dns_qname' in df.columns:
            df['dns_qr'] = pd.to_numeric(df['dns_qr'], errors='coerce').fillna(0)
            
            # DNS ratios
            dns_group = df.groupby('dns_qname')
            df['dns_query_ratio'] = dns_group['dns_qr'].transform(lambda x: (x == 0).sum() / len(x))
            df['dns_response_ratio'] = dns_group['dns_qr'].transform(lambda x: (x == 1).sum() / len(x))
            
            # DNS rates
            time_span = df['timestamp_numeric'].max() - df['timestamp_numeric'].min()
            df['dns_queries_per_second'] = dns_group['dns_qr'].transform(
                lambda x: (x == 0).sum() / time_span if time_span > 0 else 0
            )
            df['dns_responses_per_second'] = dns_group['dns_qr'].transform(
                lambda x: (x == 1).sum() / time_span if time_span > 0 else 0
            )
        else:
            # Default DNS values
            for feature in ['dns_query_ratio', 'dns_response_ratio', 'dns_queries_per_second', 'dns_responses_per_second']:
                df[feature] = 0.0
        
        # Statistical features
        if 'length' in df.columns:
            df['packet_size_ratio'] = df['length'] / df['length'].mean()
            df['packet_size_std'] = df['length'].rolling(window=5, min_periods=1).std()
            df['inter_arrival_time'] = df['time_diff'].rolling(window=5, min_periods=1).mean()
        else:
            for feature in ['packet_size_ratio', 'packet_size_std', 'inter_arrival_time']:
                df[feature] = 0.0
        
        # Remove highly correlated features
        numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns
        if len(numeric_cols) > 1:
            corr_matrix = df[numeric_cols].corr().abs()
            upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
            to_drop = [column for column in upper.columns if any(upper[column] > 0.95)]
            df = df.drop(columns=to_drop)
        
        # Ensure all features are numeric
        for col in df.columns:
            if col not in ['src_ip', 'dst_ip', 'dns_qname']:  # Skip original categorical columns
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        return df

    def _identify_feature_types(self, features: pd.DataFrame) -> Dict[str, List[str]]:
        """Identify and store feature types for consistency."""
        # All features are now numeric except original categorical columns
        numeric_cols = features.select_dtypes(include=['int64', 'float64']).columns.tolist()
        
        return {
            'numeric': numeric_cols,
            'categorical': []  # No categorical features
        }
    
    def _create_pipeline(self, features: pd.DataFrame):
        """Create preprocessing pipeline based on feature types."""
        # Store feature types for consistency
        self.feature_types = self._identify_feature_types(features)
        
        # Create preprocessing steps for numeric features
        numeric_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', RobustScaler())
        ])
        
        # Create full pipeline
        self.pipeline = Pipeline([
            ('preprocessor', numeric_transformer),
            ('pca', PCA(n_components=self.n_components)),
            ('detector', IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1,
                max_samples='auto'
            ))
        ])
    
    def train(self, features: pd.DataFrame, labels: np.ndarray = None) -> Dict:
        """
        Train the anomaly detection model.
        
        Args:
            features: DataFrame containing the features
            labels: Optional array of labels for supervised feature selection
            
        Returns:
            Dictionary containing training metrics
        """
        try:
            logger.info("Starting model training")
            
            # Engineer features
            features = self._engineer_features(features)
            
            # Select features
            selected_features = self.feature_selector.select_features(features, labels)
            self.selected_feature_names = self.feature_selector.get_selected_features()
            
            # Create and train pipeline
            self._create_pipeline(selected_features)
            self.pipeline.fit(selected_features)
            self.is_trained = True
            
            # Get feature importance and convert to native Python types
            feature_importance = self.feature_selector.get_feature_importance()
            feature_importance = {
                k: float(v) if isinstance(v, (np.float32, np.float64)) else int(v) if isinstance(v, (np.int32, np.int64)) else v
                for k, v in feature_importance.items()
            }
            
            # Calculate training metrics with native Python types
            training_metrics = {
                'n_features': int(len(self.selected_feature_names)),
                'n_components': int(self.pipeline.named_steps['pca'].n_components_),
                'explained_variance_ratio': [float(x) for x in self.pipeline.named_steps['pca'].explained_variance_ratio_],
                'feature_importance': feature_importance,
                'selected_features': self.selected_feature_names,
                'feature_types': self.feature_types
            }
            
            logger.info(f"Model training completed with {len(self.selected_feature_names)} features")
            return training_metrics
            
        except Exception as e:
            logger.error(f"Error in model training: {str(e)}")
            raise
    
    def predict(self, features: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies in the data.
        
        Args:
            features: DataFrame containing the features
            
        Returns:
            Tuple of (predictions, anomaly_scores)
        """
        try:
            # Apply feature engineering to ensure all required features exist
            features = self._engineer_features(features)
            
            # Select the same features as during training
            selected_features = features[self.selected_feature_names]
            
            # Get predictions and scores
            predictions = self.pipeline.predict(selected_features)
            anomaly_scores = self.pipeline.named_steps['detector'].score_samples(
                self.pipeline[:-1].transform(selected_features)
            )
            
            return predictions, anomaly_scores
            
        except Exception as e:
            logger.error(f"Error in prediction: {str(e)}")
            raise
    
    def save(self, model_path: str):
        """Save the model and its components."""
        try:
            Path(model_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Save the entire pipeline and metadata
            joblib.dump({
                'pipeline': self.pipeline,
                'selected_feature_names': self.selected_feature_names,
                'feature_importance': self.feature_importance,
                'feature_types': self.feature_types
            }, model_path)
            
            logger.info("Model and components saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
            raise
    
    def load(self, model_path: str):
        """Load the model and its components."""
        try:
            saved_data = joblib.load(model_path)
            self.pipeline = saved_data['pipeline']
            self.selected_feature_names = saved_data['selected_feature_names']
            self.feature_importance = saved_data['feature_importance']
            self.feature_types = saved_data['feature_types']
            
            self.is_trained = True
            logger.info("Model and components loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise
    
    def verify_model(self, features: pd.DataFrame) -> Dict:
        """
        Verify the model's performance on the data.
        
        Args:
            features: DataFrame containing the features
            
        Returns:
            Dictionary containing verification results
        """
        try:
            logger.info("Starting model verification...")
            
            # Debug logging for feature types and values
            logger.info(f"Feature types before engineering: {features.dtypes}")
            logger.info(f"Sample values before engineering: {features.head(1).to_dict()}")
            
            # Apply feature engineering to ensure all required features exist
            features = self._engineer_features(features)
            
            # Debug logging after feature engineering
            logger.info(f"Feature types after engineering: {features.dtypes}")
            logger.info(f"Sample values after engineering: {features.head(1).to_dict()}")
            
            # Select the same features as during training
            selected_features = features[self.selected_feature_names]
            
            # Debug logging for selected features
            logger.info(f"Selected feature types: {selected_features.dtypes}")
            logger.info(f"Selected feature sample values: {selected_features.head(1).to_dict()}")
            
            # Get predictions and scores
            predictions = self.pipeline.predict(selected_features)
            scores = self.pipeline.named_steps['detector'].score_samples(
                self.pipeline[:-1].transform(selected_features)
            )
            
            # Calculate basic metrics
            total_samples = len(features)
            anomalies_detected = int(np.sum(predictions == -1))
            anomaly_ratio = float(np.mean(predictions == -1))
            mean_score = float(np.mean(scores))
            std_score = float(np.std(scores))
            
            # Calculate ROC curve data
            # For unsupervised learning, we'll use the anomaly scores
            # and assume a threshold that matches our contamination rate
            threshold = np.percentile(scores, (1 - self.contamination) * 100)
            binary_predictions = (scores < threshold).astype(int)
            
            # Calculate confusion matrix metrics
            true_positives = int(np.sum((binary_predictions == 1) & (predictions == -1)))
            false_positives = int(np.sum((binary_predictions == 1) & (predictions == 1)))
            true_negatives = int(np.sum((binary_predictions == 0) & (predictions == 1)))
            false_negatives = int(np.sum((binary_predictions == 0) & (predictions == -1)))
            
            # Calculate precision, recall, and F1 score
            precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
            recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            # Calculate ROC curve
            fpr, tpr, _ = roc_curve(predictions == -1, -scores)  # Negative scores because lower is more anomalous
            roc_auc = auc(fpr, tpr)
            
            # Compile all results
            verification_results = {
                'total_samples': total_samples,
                'anomalies_detected': anomalies_detected,
                'anomaly_ratio': anomaly_ratio,
                'mean_anomaly_score': mean_score,
                'std_anomaly_score': std_score,
                'performance_metrics': {
                    'precision': float(precision),
                    'recall': float(recall),
                    'f1_score': float(f1_score),
                    'true_positives': true_positives,
                    'false_positives': false_positives,
                    'true_negatives': true_negatives,
                    'false_negatives': false_negatives,
                    'roc_curve': {
                        'fpr': fpr.tolist(),
                        'tpr': tpr.tolist(),
                        'auc': float(roc_auc)
                    }
                }
            }
            
            logger.info("Model verification completed")
            return verification_results
            
        except Exception as e:
            logger.error(f"Error during model verification: {str(e)}")
            raise 