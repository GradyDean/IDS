#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path
from scapy.all import sniff, rdpcap
from core.packet_analyzer import PacketAnalyzer
from ml.anomaly_detector import AnomalyDetector
from gui.alert_display import AlertDisplay
import sys
from datetime import datetime
import json
from core.ids import IntrusionDetectionSystem
from core.ctu_dataset import CTUDatasetProcessor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IDS:
    def __init__(self, model_path='data/models/anomaly_detector.pkl'):
        """Initialize the Intrusion Detection System."""
        self.packet_analyzer = PacketAnalyzer()
        self.anomaly_detector = AnomalyDetector(model_path)
        self.alert_display = AlertDisplay()
        
        # Create necessary directories
        Path('logs').mkdir(exist_ok=True)
        Path('alerts').mkdir(exist_ok=True)
        
        # Set up logging
        self.setup_logging()
    
    def setup_logging(self):
        """Set up logging to file."""
        log_file = Path('logs') / f'ids_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    def packet_callback(self, packet):
        """Process each captured packet."""
        try:
            # Analyze packet
            self.packet_analyzer.packet_callback(packet)
            
            # Get features for the current window
            features = self.packet_analyzer.get_features()
            
            # Detect anomalies
            if features is not None:
                results = self.anomaly_detector.predict(features)
                
                # Check for anomalies
                if results['predictions'][-1] == -1:  # Anomaly detected
                    self.handle_anomaly(packet, results)
        
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
    
    def handle_anomaly(self, packet, results):
        """Handle detected anomalies."""
        try:
            # Get attack correlations
            attack_correlations = results.get('attack_correlations', [])
            
            # Create alert
            alert = {
                'timestamp': datetime.now().isoformat(),
                'packet_info': {
                    'src_ip': packet.getlayer('IP').src if packet.haslayer('IP') else 'N/A',
                    'dst_ip': packet.getlayer('IP').dst if packet.haslayer('IP') else 'N/A',
                    'protocol': packet.getlayer('IP').proto if packet.haslayer('IP') else 'N/A',
                },
                'anomaly_score': float(results['scores'][-1]),
                'confidence': float(results['confidence'][-1]),
                'attack_correlations': attack_correlations
            }
            
            # Log alert
            logger.warning(f"Anomaly detected: {alert}")
            
            # Save alert to file
            alert_file = Path('alerts') / f'alert_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            with open(alert_file, 'w') as f:
                json.dump(alert, f, indent=2)
            
            # Display alert in GUI
            self.alert_display.add_alert(alert)
        
        except Exception as e:
            logger.error(f"Error handling anomaly: {str(e)}")
    
    def start_monitoring(self, interface):
        """Start real-time network monitoring."""
        try:
            logger.info(f"Starting monitoring on interface {interface}")
            self.alert_display.show()
            sniff(iface=interface, prn=self.packet_callback, store=0)
        
        except Exception as e:
            logger.error(f"Error in monitoring: {str(e)}")
            sys.exit(1)
    
    def analyze_pcap(self, pcap_file):
        """Analyze a PCAP file."""
        try:
            logger.info(f"Analyzing PCAP file: {pcap_file}")
            packets = rdpcap(pcap_file)
            
            for packet in packets:
                self.packet_callback(packet)
            
            logger.info("PCAP analysis completed")
        
        except Exception as e:
            logger.error(f"Error analyzing PCAP: {str(e)}")
            sys.exit(1)

def train_with_ctu_dataset(dataset_path: str, output_dir: str = 'data/models'):
    """
    Train the IDS using the CTU dataset.
    
    Args:
        dataset_path: Path to the CTU dataset directory
        output_dir: Directory to save the trained model
    """
    try:
        logger.info("Initializing CTU dataset processor...")
        dataset = CTUDatasetProcessor(dataset_path)
        
        # Get training data
        logger.info("Loading training data...")
        features, labels = dataset.get_training_data()
        
        # Initialize and train anomaly detector
        logger.info("Training anomaly detector...")
        detector = AnomalyDetector(contamination=0.1)
        training_metrics = detector.train(features, labels)
        
        # Save model and metrics
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        model_path = output_path / 'anomaly_detector.joblib'
        detector.save(str(model_path))
        
        metrics_path = output_path / 'training_metrics.json'
        with open(metrics_path, 'w') as f:
            json.dump(training_metrics, f, indent=4)
        
        logger.info(f"Model saved to {model_path}")
        logger.info(f"Training metrics saved to {metrics_path}")
        
        return detector, training_metrics
        
    except Exception as e:
        logger.error(f"Error in training: {str(e)}")
        raise

def test_with_ctu_dataset(dataset_path: str, model_path: str):
    """
    Test the IDS using the CTU dataset.
    
    Args:
        dataset_path: Path to the CTU dataset directory
        model_path: Path to the trained model
    """
    try:
        logger.info("Initializing CTU dataset processor...")
        dataset = CTUDatasetProcessor(dataset_path)
        
        # Get test data
        logger.info("Loading test data...")
        packets, features = dataset.get_test_data()
        
        # Initialize IDS with trained model
        logger.info("Initializing IDS with trained model...")
        ids = IntrusionDetectionSystem(use_gui=False)
        ids.anomaly_detector.load(model_path)
        
        # Process test data
        logger.info("Processing test data...")
        results = []
        for i, packet in enumerate(packets):
            if i % 1000 == 0:
                logger.info(f"Processed {i} packets...")
            
            # Process packet
            ids.packet_analyzer.packet_buffer.append(packet)
            if len(ids.packet_analyzer.packet_buffer) >= 100:  # Process in batches
                ids.process_traffic()
                results.extend(ids.get_detection_results())
                ids.packet_analyzer.packet_buffer = []
        
        # Process remaining packets
        if ids.packet_analyzer.packet_buffer:
            ids.process_traffic()
            results.extend(ids.get_detection_results())
        
        # Save results
        output_path = Path('verification_logs')
        output_path.mkdir(parents=True, exist_ok=True)
        
        results_path = output_path / 'ctu_test_results.json'
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=4)
        
        logger.info(f"Test results saved to {results_path}")
        
    except Exception as e:
        logger.error(f"Error in testing: {str(e)}")
        raise

def main():
    parser = argparse.ArgumentParser(description='Train and test IDS with CTU dataset')
    parser.add_argument('--dataset', required=True, help='Path to CTU dataset directory')
    parser.add_argument('--mode', choices=['train', 'test', 'both'], default='both',
                      help='Operation mode: train, test, or both')
    parser.add_argument('--model', help='Path to trained model (required for test mode)')
    parser.add_argument('--output', default='data/models',
                      help='Output directory for models and metrics')
    
    args = parser.parse_args()
    
    if args.mode in ['test', 'both'] and not args.model:
        parser.error("--model is required for test mode")
    
    try:
        if args.mode in ['train', 'both']:
            detector, metrics = train_with_ctu_dataset(args.dataset, args.output)
        
        if args.mode in ['test', 'both']:
            test_with_ctu_dataset(args.dataset, args.model or str(Path(args.output) / 'anomaly_detector.joblib'))
            
    except Exception as e:
        logger.error(f"Error in main: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 