import logging
from typing import Dict, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackDetector:
    def __init__(self):
        """Initialize the attack detector."""
        self.attack_patterns = {
            'dos': {
                'threshold': 1000,  # packets per second
                'window': 60  # seconds
            },
            'port_scan': {
                'threshold': 10,  # unique ports
                'window': 60  # seconds
            },
            'dns_amplification': {
                'threshold': 10,  # response/query ratio
                'window': 60  # seconds
            }
        }
        
        # Initialize attack statistics
        self.stats = {
            'packet_count': 0,
            'unique_ports': set(),
            'dns_queries': 0,
            'dns_responses': 0,
            'start_time': None
        }
    
    def detect_attacks(self, features: Dict, packet: Dict) -> List[Dict]:
        """
        Detect attacks based on packet features.
        
        Args:
            features: Dictionary of packet features
            packet: Raw packet data
            
        Returns:
            List of detected attacks
        """
        try:
            attacks = []
            
            # Update statistics
            self._update_stats(features, packet)
            
            # Check for DoS attack
            if self._check_dos_attack():
                attacks.append({
                    'type': 'dos',
                    'confidence': 0.8,
                    'details': {
                        'packets_per_second': self.stats['packet_count'] / self.attack_patterns['dos']['window']
                    }
                })
            
            # Check for port scan
            if self._check_port_scan():
                attacks.append({
                    'type': 'port_scan',
                    'confidence': 0.7,
                    'details': {
                        'unique_ports': len(self.stats['unique_ports'])
                    }
                })
            
            # Check for DNS amplification
            if self._check_dns_amplification():
                attacks.append({
                    'type': 'dns_amplification',
                    'confidence': 0.6,
                    'details': {
                        'query_response_ratio': self.stats['dns_responses'] / max(1, self.stats['dns_queries'])
                    }
                })
            
            return attacks
            
        except Exception as e:
            logger.error(f"Error detecting attacks: {str(e)}")
            return []
    
    def _update_stats(self, features: Dict, packet: Dict):
        """Update attack detection statistics."""
        # Update packet count
        self.stats['packet_count'] += 1
        
        # Update unique ports
        if 'dst_port' in features:
            self.stats['unique_ports'].add(features['dst_port'])
        
        # Update DNS statistics
        if packet.get('protocol') == 53:  # DNS
            if packet.get('dns_qr') == 0:  # Query
                self.stats['dns_queries'] += 1
            else:  # Response
                self.stats['dns_responses'] += 1
        
        # Update start time if not set
        if self.stats['start_time'] is None:
            self.stats['start_time'] = features.get('timestamp', 0)
    
    def _check_dos_attack(self) -> bool:
        """Check for DoS attack based on packet rate."""
        if not self.stats['start_time']:
            return False
            
        elapsed_time = max(1, self.stats['packet_count'] / self.attack_patterns['dos']['threshold'])
        return self.stats['packet_count'] / elapsed_time > self.attack_patterns['dos']['threshold']
    
    def _check_port_scan(self) -> bool:
        """Check for port scan based on unique ports."""
        return len(self.stats['unique_ports']) > self.attack_patterns['port_scan']['threshold']
    
    def _check_dns_amplification(self) -> bool:
        """Check for DNS amplification attack."""
        if self.stats['dns_queries'] == 0:
            return False
            
        ratio = self.stats['dns_responses'] / self.stats['dns_queries']
        return ratio > self.attack_patterns['dns_amplification']['threshold'] 