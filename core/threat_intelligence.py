import json
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import hashlib
import os
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatIntelligence:
    def __init__(self, api_key: Optional[str] = None, server_url: Optional[str] = None):
        """
        Initialize the threat intelligence system.
        
        Args:
            api_key: API key for authentication with the threat intelligence server
            server_url: URL of the threat intelligence server
        """
        self.api_key = api_key or os.getenv('THREAT_INTEL_API_KEY')
        self.server_url = server_url or os.getenv('THREAT_INTEL_SERVER_URL')
        self.local_signatures = {}
        self.last_sync = None
        self.sync_interval = timedelta(hours=1)
        self.patterns = []
        self.pattern_file = Path('data/threat_patterns.json')
        self._load_patterns()
        
    def _load_patterns(self):
        """Load threat patterns from file."""
        try:
            if self.pattern_file.exists():
                with open(self.pattern_file, 'r') as f:
                    self.patterns = json.load(f)
            else:
                # Create default patterns
                self.patterns = [
                    {
                        'type': 'dos',
                        'criteria': {
                            'packets_per_second': 1000
                        },
                        'confidence': 0.8
                    },
                    {
                        'type': 'port_scan',
                        'criteria': {
                            'unique_ports': 10
                        },
                        'confidence': 0.7
                    },
                    {
                        'type': 'dns_amplification',
                        'criteria': {
                            'query_response_ratio': 10
                        },
                        'confidence': 0.6
                    }
                ]
                self._save_patterns()
        except Exception as e:
            logger.error(f"Error loading threat patterns: {str(e)}")
            self.patterns = []
    
    def _save_patterns(self):
        """Save threat patterns to file."""
        try:
            self.pattern_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.pattern_file, 'w') as f:
                json.dump(self.patterns, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving threat patterns: {str(e)}")
    
    def get_attack_patterns(self) -> List[Dict]:
        """Get all known attack patterns."""
        return self.patterns
    
    def add_pattern(self, pattern: Dict):
        """Add a new attack pattern."""
        try:
            self.patterns.append(pattern)
            self._save_patterns()
        except Exception as e:
            logger.error(f"Error adding threat pattern: {str(e)}")
    
    def remove_pattern(self, pattern_type: str):
        """Remove an attack pattern by type."""
        try:
            self.patterns = [p for p in self.patterns if p['type'] != pattern_type]
            self._save_patterns()
        except Exception as e:
            logger.error(f"Error removing threat pattern: {str(e)}")
    
    def update_pattern(self, pattern_type: str, new_pattern: Dict):
        """Update an existing attack pattern."""
        try:
            for i, pattern in enumerate(self.patterns):
                if pattern['type'] == pattern_type:
                    self.patterns[i] = new_pattern
                    self._save_patterns()
                    break
        except Exception as e:
            logger.error(f"Error updating threat pattern: {str(e)}")
    
    def share_attack_pattern(self, attack_data: Dict) -> bool:
        """
        Share a confirmed attack pattern with the threat intelligence network.
        
        Args:
            attack_data: Dictionary containing attack details
                {
                    'type': str,  # Type of attack
                    'signature': str,  # Attack signature/pattern
                    'confidence': float,  # Confidence score
                    'timestamp': str,  # ISO format timestamp
                    'details': Dict,  # Additional attack details
                    'network_context': Dict  # Network-specific context
                }
        
        Returns:
            bool: True if sharing was successful
        """
        try:
            if not self.api_key or not self.server_url:
                logger.warning("Threat intelligence sharing not configured")
                return False
                
            # Anonymize sensitive data
            anonymized_data = self._anonymize_data(attack_data)
            
            # Add metadata
            anonymized_data.update({
                'shared_at': datetime.now().isoformat(),
                'version': '1.0'
            })
            
            # Send to threat intelligence server
            response = requests.post(
                f"{self.server_url}/share",
                headers={'Authorization': f'Bearer {self.api_key}'},
                json=anonymized_data
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully shared attack pattern: {attack_data['type']}")
                return True
            else:
                logger.error(f"Failed to share attack pattern: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sharing attack pattern: {str(e)}")
            return False
            
    def _sync_patterns(self) -> None:
        """Synchronize attack patterns with the threat intelligence server."""
        try:
            response = requests.get(
                f"{self.server_url}/patterns",
                headers={'Authorization': f'Bearer {self.api_key}'}
            )
            
            if response.status_code == 200:
                patterns = response.json()
                self.local_signatures = {
                    self._generate_signature_id(p): p 
                    for p in patterns
                }
                self.last_sync = datetime.now()
                logger.info(f"Successfully synced {len(patterns)} attack patterns")
            else:
                logger.error(f"Failed to sync patterns: {response.text}")
                
        except Exception as e:
            logger.error(f"Error syncing patterns: {str(e)}")
            
    def _anonymize_data(self, data: Dict) -> Dict:
        """
        Anonymize sensitive data before sharing.
        
        Args:
            data: Original attack data
            
        Returns:
            Anonymized data
        """
        anonymized = data.copy()
        
        # Remove or hash sensitive information
        if 'network_context' in anonymized:
            context = anonymized['network_context']
            if 'ip_addresses' in context:
                context['ip_addresses'] = [
                    self._hash_ip(ip) for ip in context['ip_addresses']
                ]
            if 'mac_addresses' in context:
                context['mac_addresses'] = [
                    self._hash_mac(mac) for mac in context['mac_addresses']
                ]
                
        return anonymized
        
    def _hash_ip(self, ip: str) -> str:
        """Hash an IP address for anonymization."""
        return hashlib.sha256(ip.encode()).hexdigest()[:16]
        
    def _hash_mac(self, mac: str) -> str:
        """Hash a MAC address for anonymization."""
        return hashlib.sha256(mac.encode()).hexdigest()[:16]
        
    def _generate_signature_id(self, pattern: Dict) -> str:
        """Generate a unique ID for an attack pattern."""
        signature_str = f"{pattern['type']}:{pattern['signature']}"
        return hashlib.sha256(signature_str.encode()).hexdigest() 