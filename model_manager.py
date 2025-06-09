from core.packet_analyzer import PacketAnalyzer
from ml.anomaly_detector import AnomalyDetector
import pandas as pd
import logging
import argparse
from pathlib import Path
from scapy.all import rdpcap
import json
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.metrics import confusion_matrix
import joblib
from sklearn.impute import SimpleImputer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_session_log(session_type, **kwargs):
    """Create a log entry with session information."""
    log_dir = Path(f'{session_type}_logs')
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = log_dir / f'{session_type}_session_{timestamp}.json'
    
    log_data = {
        'timestamp': datetime.now().isoformat(),
        'session_type': session_type,
        **kwargs
    }
    
    return log_file, log_data

def plot_roc_curve(fpr, tpr, auc, save_path):
    """Plot ROC curve and save to file."""
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend(loc="lower right")
    plt.savefig(save_path)
    plt.close()

def plot_confusion_matrix(cm, save_path):
    """Plot confusion matrix and save to file."""
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Normal', 'Anomaly'],
                yticklabels=['Normal', 'Anomaly'])
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    plt.savefig(save_path)
    plt.close()

def load_pcap(file_path: str) -> list:
    """Load packets from a pcap file."""
    try:
        logger.info(f"Loading packets from {file_path}")
        packets = rdpcap(file_path)
        logger.info(f"Loaded {len(packets)} packets")
        return packets
    except Exception as e:
        logger.error(f"Error loading pcap file: {str(e)}")
        raise

def process_packets(packets: list, analyzer: PacketAnalyzer) -> pd.DataFrame:
    """Process packets and extract features."""
    try:
        logger.info("Processing packets...")
        for packet in packets:
            analyzer.add_packet(packet)
        
        features_df = analyzer.process_buffer()
        logger.info(f"Extracted features for {len(features_df)} packets")
        return features_df
    except Exception as e:
        logger.error(f"Error processing packets: {str(e)}")
        raise

def train_model(features: pd.DataFrame, output_dir: str, contamination: float = 0.001, n_features: int = 50):
    """Train the anomaly detection model."""
    try:
        logger.info("Initializing anomaly detector...")
        detector = AnomalyDetector(contamination=contamination, n_features=n_features)
        
        # Train the model
        logger.info("Training model...")
        training_metrics = detector.train(features)
        
        # Add configuration parameters to metrics
        training_metrics['configuration'] = {
            'contamination': contamination,
            'n_features': n_features,
            'total_samples': len(features),
            'feature_count': len(features.columns),
            'selected_features': detector.selected_feature_names
        }
        
        # Save model and components
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        model_path = output_path / 'anomaly_detector.joblib'
        feature_names_path = output_path / 'selected_features.json'
        
        # Save model
        detector.save(str(model_path))
        
        # Save selected feature names
        with open(feature_names_path, 'w') as f:
            json.dump({'selected_features': detector.selected_feature_names}, f, indent=2)
        
        # Save training metrics
        metrics_path = output_path / f'training_metrics_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(metrics_path, 'w') as f:
            json.dump(training_metrics, f, indent=2)
        
        logger.info(f"Model and metrics saved to {output_dir}")
        return detector, training_metrics
        
    except Exception as e:
        logger.error(f"Error training model: {str(e)}")
        raise

def verify_model(test_pcap: str, model_path: str = 'data/models/anomaly_detector.joblib', known_anomalies=None):
    """Verify the trained model using test data."""
    try:
        # Initialize components
        packet_analyzer = PacketAnalyzer()
        
        # Load model and feature names
        model_dir = Path(model_path).parent
        feature_names_path = model_dir / 'selected_features.json'
        
        if not feature_names_path.exists():
            raise FileNotFoundError(f"Feature names file not found at {feature_names_path}")
            
        with open(feature_names_path, 'r') as f:
            feature_names = json.load(f)['selected_features']
            
        # Load the model
        anomaly_detector = AnomalyDetector()
        anomaly_detector.load(str(model_path))
        
        # Load and process test data
        logger.info(f"Processing test data from {test_pcap}")
        packets = load_pcap(test_pcap)
        features = process_packets(packets, packet_analyzer)
        
        # Apply feature engineering first
        features = anomaly_detector._engineer_features(features)
        
        # Select features and ensure they match the training data types
        selected_features = features[feature_names].copy()
        
        # Convert feature types to match training data
        for col in selected_features.columns:
            if col in anomaly_detector.feature_types['numeric']:
                selected_features[col] = pd.to_numeric(selected_features[col], errors='coerce')
            elif col in anomaly_detector.feature_types['categorical']:
                selected_features[col] = selected_features[col].astype('category')
        
        # Verify model
        logger.info("Verifying model performance...")
        verification_results = anomaly_detector.verify_model(selected_features)
        
        # Create output directories
        log_dir = Path('verification_logs')
        plot_dir = log_dir / 'plots'
        log_dir.mkdir(exist_ok=True)
        plot_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = log_dir / f'verification_{timestamp}.json'
        
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'test_dataset': str(test_pcap),
            'model_path': str(model_path),
            'verification_results': verification_results
        }
        
        with open(log_file, 'w') as f:
            json.dump(log_data, f, indent=2)
        
        # Print summary
        logger.info("\nVerification Results:")
        logger.info(f"Total samples: {verification_results['total_samples']}")
        logger.info(f"Anomalies detected: {verification_results['anomalies_detected']}")
        logger.info(f"Anomaly ratio: {verification_results['anomaly_ratio']:.2%}")
        
        if 'performance_metrics' in verification_results:
            metrics = verification_results['performance_metrics']
            logger.info("\nPerformance Metrics:")
            logger.info(f"Precision: {metrics['precision']:.2%}")
            logger.info(f"Recall: {metrics['recall']:.2%}")
            logger.info(f"F1 Score: {metrics['f1_score']:.2%}")
            logger.info(f"True Positives: {metrics['true_positives']}")
            logger.info(f"False Positives: {metrics['false_positives']}")
            logger.info(f"True Negatives: {metrics['true_negatives']}")
            logger.info(f"False Negatives: {metrics['false_negatives']}")
            
            # Plot ROC curve
            roc_data = metrics['roc_curve']
            plot_roc_curve(
                np.array(roc_data['fpr']),
                np.array(roc_data['tpr']),
                roc_data['auc'],
                plot_dir / f'roc_curve_{timestamp}.png'
            )
            
            # Plot confusion matrix
            cm = np.array([
                [metrics['true_negatives'], metrics['false_positives']],
                [metrics['false_negatives'], metrics['true_positives']]
            ])
            plot_confusion_matrix(
                cm,
                plot_dir / f'confusion_matrix_{timestamp}.png'
            )
            
            logger.info(f"\nPlots saved to {plot_dir}")
        
        logger.info(f"\nDetailed results saved to {log_file}")
        return verification_results
        
    except Exception as e:
        logger.error(f"Error during model verification: {str(e)}")
        raise

def train_and_verify(normal_pcap: str, test_pcap: str, anomaly_pcap: str = None, 
                    output_dir: str = 'data/models', contamination: float = 0.001, 
                    n_features: int = 50):
    """Train the model and verify it in one go."""
    try:
        # Initialize packet analyzer
        analyzer = PacketAnalyzer()
        
        # Load and process normal traffic
        normal_packets = load_pcap(normal_pcap)
        normal_features = process_packets(normal_packets, analyzer)
        
        # Load and process anomalous traffic if provided
        if anomaly_pcap:
            anomaly_packets = load_pcap(anomaly_pcap)
            anomaly_features = process_packets(anomaly_packets, analyzer)
            features = pd.concat([normal_features, anomaly_features])
            labels = np.array([0] * len(normal_features) + [1] * len(anomaly_features))
        else:
            features = normal_features
            labels = None
        
        # Train model
        detector, training_metrics = train_model(
            features,
            output_dir,
            contamination=contamination,
            n_features=n_features
        )
        
        # Verify model
        verification_results = verify_model(test_pcap, str(Path(output_dir) / 'anomaly_detector.joblib'))
        
        return detector, training_metrics, verification_results
        
    except Exception as e:
        logger.error(f"Error in train_and_verify: {str(e)}")
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Train and verify anomaly detection model')
    parser.add_argument('--mode', choices=['train', 'verify', 'train_and_verify'], required=True,
                      help='Operation mode')
    parser.add_argument('--normal', help='Path to pcap file with normal traffic')
    parser.add_argument('--test', help='Path to pcap file with test traffic')
    parser.add_argument('--anomaly', help='Path to pcap file with anomalous traffic')
    parser.add_argument('--output', default='data/models', help='Output directory for model and metrics')
    parser.add_argument('--model', default='data/models/anomaly_detector.pkl',
                      help='Path to the trained model (for verify mode)')
    parser.add_argument('--contamination', type=float, default=0.001,
                      help='Expected proportion of anomalies')
    parser.add_argument('--n-features', type=int, default=50,
                      help='Number of features to select')
    
    args = parser.parse_args()
    
    if args.mode == 'train':
        if not args.normal:
            parser.error("--normal is required for train mode")
        # Initialize analyzer and process packets
        analyzer = PacketAnalyzer()
        packets = load_pcap(args.normal)
        features = process_packets(packets, analyzer)
        train_model(features, args.output, args.contamination, args.n_features)
    
    elif args.mode == 'verify':
        if not args.test:
            parser.error("--test is required for verify mode")
        verify_model(args.test, args.model)
    
    elif args.mode == 'train_and_verify':
        if not args.normal or not args.test:
            parser.error("--normal and --test are required for train_and_verify mode")
        train_and_verify(args.normal, args.test, args.anomaly, args.output,
                        args.contamination, args.n_features) 