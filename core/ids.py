from scapy.all import sniff
import logging
from pathlib import Path
from datetime import datetime
import json
from ml.anomaly_detector import AnomalyDetector
from core.packet_analyzer import PacketAnalyzer
from core.attack_detector import AttackDetector
from core.threat_intelligence import ThreatIntelligence
from gui.alert_display import AlertDisplay

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IntrusionDetectionSystem:
    def __init__(self, interface=None, config_path=None, use_gui=True):
        """
        Initialize the Intrusion Detection System.
        
        Args:
            interface: Network interface to monitor
            config_path: Path to configuration file
            use_gui: Whether to use the GUI interface
        """
        self.interface = interface
        self.config_path = config_path or Path('config/config.yaml')
        self.packet_analyzer = PacketAnalyzer(interface)
        self.anomaly_detector = AnomalyDetector()
        self.attack_detector = AttackDetector()
        self.threat_intelligence = ThreatIntelligence()
        self.alerts = []
        self.confirmed_attacks = []
        self.is_running = False
        self.use_gui = use_gui
        self.gui = None
        
        if use_gui:
            self.alert_display = AlertDisplay()
        
        # Create necessary directories
        Path('logs').mkdir(exist_ok=True)
        Path('alerts').mkdir(exist_ok=True)
        
        # Set up logging
        self.setup_logging()
        
        # Store detection results
        self.detection_results = []
        
        # Load configuration
        self._load_config()
        
    def _load_config(self):
        """Load configuration from file."""
        if self.config_path and os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    
                # Update components with configuration
                if 'threat_intelligence' in config:
                    self.threat_intelligence = ThreatIntelligence(
                        api_key=config['threat_intelligence'].get('api_key'),
                        server_url=config['threat_intelligence'].get('server_url')
                    )
                    
            except Exception as e:
                logger.error(f"Error loading configuration: {str(e)}")
                
    def start(self):
        """Start the IDS system."""
        try:
            logger.info("Starting Intrusion Detection System")
            self.is_running = True
            
            if self.use_gui:
                self._start_gui()
            else:
                # Only start packet capture automatically in non-GUI mode
                self.packet_analyzer.start_capture()
            
        except Exception as e:
            logger.error(f"Error starting IDS: {str(e)}")
            self.is_running = False
            raise
    
    def _start_gui(self):
        """Start the GUI application."""
        app = QApplication(sys.argv)
        self.gui = MainWindow(self)
        self.gui.show()
        sys.exit(app.exec_())
    
    def stop(self):
        """Stop the IDS system."""
        if self.is_running:
            self.is_running = False
            if hasattr(self.packet_analyzer, 'stop_capture'):
                self.packet_analyzer.stop_capture()
            logger.info("Stopping Intrusion Detection System")
    
    def process_traffic(self):
        """Process captured traffic and detect anomalies."""
        try:
            # Get features from packet analyzer
            features = self.packet_analyzer.get_features()
            
            if features.empty:
                return
            
            # Detect anomalies using ML
            ml_results = self.anomaly_detector.predict(features)
            
            # Detect specific attacks
            attack_results = self.attack_detector.detect_attacks(
                features.iloc[-1].to_dict(),
                self.packet_analyzer.packet_buffer[-1] if self.packet_analyzer.packet_buffer else {}
            )
            
            # Get threat intelligence patterns
            threat_patterns = self.threat_intelligence.get_attack_patterns()
            
            # Process anomalies and attacks
            self._process_detections(ml_results, attack_results, features, threat_patterns)
                    
        except Exception as e:
            logger.error(f"Error processing traffic: {str(e)}")
    
    def _process_detections(self, ml_results, attack_results, features, threat_patterns):
        """Process and combine ML and attack detection results."""
        # Process ML anomalies
        for i, pred in enumerate(ml_results['predictions']):
            if pred == -1:  # Anomaly detected
                # Check for attack correlations
                attack_correlations = next(
                    (corr['correlations'] for corr in ml_results['attack_correlations'] 
                     if corr['index'] == i),
                    []
                )
                
                if attack_correlations:
                    # Use the highest confidence correlation
                    best_correlation = max(attack_correlations, key=lambda x: x['confidence'])
                    self._handle_anomaly(
                        features.iloc[i],
                        ml_results['confidence'][i],
                        best_correlation['type'],
                        {
                            'ml_confidence': ml_results['confidence'][i],
                            'attack_confidence': best_correlation['confidence'],
                            'contributing_features': best_correlation['contributing_features']
                        }
                    )
                else:
                    self._handle_anomaly(
                        features.iloc[i],
                        ml_results['confidence'][i],
                        'ml_anomaly'
                    )
        
        # Process specific attacks
        for attack in attack_results:
            # Check against threat intelligence patterns
            if self._match_threat_pattern(attack, threat_patterns):
                attack['confidence'] = min(attack['confidence'] + 0.2, 1.0)  # Boost confidence
                
            self._handle_anomaly(
                features.iloc[-1],
                attack['confidence'],
                attack['type'],
                attack['details']
            )
    
    def _match_threat_pattern(self, attack, threat_patterns):
        """Check if an attack matches any known threat patterns."""
        for pattern in threat_patterns:
            if pattern['type'] == attack['type']:
                # Compare attack signatures
                if self._compare_signatures(attack['details'], pattern['signature']):
                    return True
        return False
    
    def _compare_signatures(self, attack_details, pattern_signature):
        """Compare attack details with a threat pattern signature."""
        # Implement signature comparison logic here
        # This is a simplified example - you would want more sophisticated matching
        try:
            for key, value in pattern_signature.items():
                if key in attack_details:
                    if isinstance(value, dict):
                        if not self._compare_signatures(attack_details[key], value):
                            return False
                    elif attack_details[key] != value:
                        return False
            return True
        except Exception as e:
            logger.error(f"Error comparing signatures: {str(e)}")
            return False
    
    def _handle_anomaly(self, features, confidence, alert_type, details=None):
        """Handle detected anomalies and attacks."""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'features': features.to_dict(),
            'confidence': confidence,
            'severity': self._calculate_severity(confidence, alert_type),
            'details': details or {}
        }
        
        self.alerts.append(alert)
        logger.warning(f"Alert detected: {json.dumps(alert, indent=2)}")
        
        # If this is a high-confidence attack, share it
        if confidence > 0.8 and alert_type != 'ml_anomaly':
            self._share_attack_pattern(alert)
        
        # Store detection result
        self.detection_results.append(alert)
    
    def _share_attack_pattern(self, alert):
        """Share confirmed attack patterns with the threat intelligence network."""
        try:
            # Prepare attack data
            attack_data = {
                'type': alert['type'],
                'signature': alert['details'],
                'confidence': alert['confidence'],
                'timestamp': alert['timestamp'],
                'details': alert['details'],
                'network_context': {
                    'ip_addresses': self._extract_ips(alert['features']),
                    'mac_addresses': self._extract_macs(alert['features'])
                }
            }
            
            # Share the pattern
            if self.threat_intelligence.share_attack_pattern(attack_data):
                logger.info(f"Successfully shared attack pattern: {alert['type']}")
                self.confirmed_attacks.append(alert)
            else:
                logger.warning(f"Failed to share attack pattern: {alert['type']}")
                
        except Exception as e:
            logger.error(f"Error sharing attack pattern: {str(e)}")
    
    def _extract_ips(self, features):
        """Extract IP addresses from features."""
        ips = set()
        for key, value in features.items():
            if isinstance(value, str) and self._is_ip(value):
                ips.add(value)
        return list(ips)
    
    def _extract_macs(self, features):
        """Extract MAC addresses from features."""
        macs = set()
        for key, value in features.items():
            if isinstance(value, str) and self._is_mac(value):
                macs.add(value)
        return list(macs)
    
    def _is_ip(self, value):
        """Check if a string is an IP address."""
        parts = value.split('.')
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    
    def _is_mac(self, value):
        """Check if a string is a MAC address."""
        parts = value.split(':')
        return len(parts) == 6 and all(len(p) == 2 and p.isalnum() for p in parts)
    
    def _calculate_severity(self, confidence, alert_type):
        """Calculate the severity of an alert based on confidence and type."""
        if confidence > 0.8:
            return 'high'
        elif confidence > 0.5:
            return 'medium'
        return 'low'
    
    def get_alerts(self):
        """Get all alerts generated by the system."""
        return self.alerts
    
    def get_confirmed_attacks(self):
        """Get all confirmed attacks that have been shared."""
        return self.confirmed_attacks
    
    def train_model(self, training_data):
        """Train the anomaly detection model with historical data."""
        try:
            logger.info("Training anomaly detection model")
            self.anomaly_detector.train(training_data)
            logger.info("Model training completed")
            
        except Exception as e:
            logger.error(f"Error training model: {str(e)}")
            raise
    
    def setup_logging(self):
        """Set up logging to file."""
        log_file = Path('logs') / f'ids_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    def get_detection_results(self):
        """Get the list of detection results."""
        return self.detection_results
    
    def clear_detection_results(self):
        """Clear the detection results list."""
        self.detection_results = [] 