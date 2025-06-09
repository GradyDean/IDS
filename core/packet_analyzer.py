from scapy.all import *
from scapy.layers.http import HTTP
import pandas as pd
import numpy as np
from typing import Dict, List, Optional
import logging
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketAnalyzer:
    def __init__(self):
        """Initialize the packet analyzer."""
        self.packet_buffer = []
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'end_time': None,
            'protocols': set(),
            'ports': set(),
            'flags': set()
        })
        
    def process_packet(self, packet: Packet) -> Optional[Dict]:
        """
        Process a single packet and extract relevant features.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary containing packet features
        """
        try:
            if not packet.haslayer(IP):
                return None
                
            # Basic packet info
            features = {
                'timestamp': packet.time,
                'length': len(packet),
                'protocol': packet[IP].proto,
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst
            }
            
            # Update flow statistics
            flow_key = f"{packet[IP].src}:{packet[IP].dst}"
            flow_stats = self.flow_stats[flow_key]
            
            flow_stats['packet_count'] += 1
            flow_stats['byte_count'] += len(packet)
            flow_stats['protocols'].add(packet[IP].proto)
            
            if flow_stats['start_time'] is None:
                flow_stats['start_time'] = packet.time
            flow_stats['end_time'] = packet.time
            
            # Process transport layer
            if packet.haslayer(TCP):
                features.update(self._process_tcp(packet[TCP], flow_stats))
            elif packet.haslayer(UDP):
                features.update(self._process_udp(packet[UDP], flow_stats))
            elif packet.haslayer(ICMP):
                features.update(self._process_icmp(packet[ICMP]))
                
            # Process application layer
            if packet.haslayer(DNS):
                features.update(self._process_dns(packet[DNS]))
            elif packet.haslayer(Raw):
                # Try to detect HTTP in raw payload
                http_features = self._process_http(packet[Raw])
                if http_features:
                    features.update(http_features)
                
            # Add flow statistics
            features.update(self._get_flow_features(flow_key))
            
            return features
            
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
            return None
            
    def _process_tcp(self, tcp: TCP, flow_stats: Dict) -> Dict:
        """Process TCP layer features."""
        features = {
            'src_port': tcp.sport,
            'dst_port': tcp.dport,
            'tcp_flags': tcp.flags,
            'tcp_window': tcp.window,
            'tcp_seq': tcp.seq,
            'tcp_ack': tcp.ack
        }
        
        flow_stats['ports'].add(tcp.sport)
        flow_stats['ports'].add(tcp.dport)
        flow_stats['flags'].add(tcp.flags)
        
        return features
        
    def _process_udp(self, udp: UDP, flow_stats: Dict) -> Dict:
        """Process UDP layer features."""
        features = {
            'src_port': udp.sport,
            'dst_port': udp.dport,
            'udp_length': udp.len
        }
        
        flow_stats['ports'].add(udp.sport)
        flow_stats['ports'].add(udp.dport)
        
        return features
        
    def _process_icmp(self, icmp: ICMP) -> Dict:
        """Process ICMP layer features."""
        return {
            'icmp_type': icmp.type,
            'icmp_code': icmp.code
        }
        
    def _process_dns(self, dns: DNS) -> Dict:
        """Process DNS layer features."""
        features = {
            'dns_qr': dns.qr,
            'dns_opcode': dns.opcode,
            'dns_rcode': dns.rcode
        }
        
        if dns.qr == 0:  # Query
            features['dns_qname'] = dns.qd.qname if dns.qd else None
            features['dns_qtype'] = dns.qd.qtype if dns.qd else None
        else:  # Response
            features['dns_ancount'] = dns.ancount
            features['dns_nscount'] = dns.nscount
            features['dns_arcount'] = dns.arcount
            
        return features
        
    def _process_http(self, raw: Raw) -> Optional[Dict]:
        """Process HTTP layer features from raw payload."""
        try:
            payload = raw.load.decode('utf-8', errors='ignore')
            if not any(method in payload for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']):
                return None
                
            lines = payload.split('\r\n')
            features = {
                'http_method': None,
                'http_host': None,
                'http_path': None,
                'http_status': None
            }
            
            # Parse first line for method and path
            if lines and ' ' in lines[0]:
                parts = lines[0].split(' ')
                if len(parts) >= 2:
                    features['http_method'] = parts[0]
                    features['http_path'] = parts[1]
            
            # Parse headers
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key == 'host':
                        features['http_host'] = value
                    elif key == 'status':
                        features['http_status'] = value
            
            return features
            
        except Exception as e:
            logger.debug(f"Error parsing HTTP: {str(e)}")
            return None
        
    def _get_flow_features(self, flow_key: str) -> Dict:
        """Get aggregated flow features."""
        flow_stats = self.flow_stats[flow_key]
        duration = flow_stats['end_time'] - flow_stats['start_time']
        
        return {
            'flow_duration': duration,
            'flow_packet_count': flow_stats['packet_count'],
            'flow_byte_count': flow_stats['byte_count'],
            'flow_protocol_count': len(flow_stats['protocols']),
            'flow_port_count': len(flow_stats['ports']),
            'flow_flag_count': len(flow_stats['flags']),
            'flow_packets_per_second': flow_stats['packet_count'] / duration if duration > 0 else 0,
            'flow_bytes_per_second': flow_stats['byte_count'] / duration if duration > 0 else 0
        }
        
    def process_buffer(self) -> pd.DataFrame:
        """
        Process the packet buffer and return features as a DataFrame.
        
        Returns:
            DataFrame containing packet features
        """
        try:
            # Process all packets in buffer
            features_list = []
            for packet in self.packet_buffer:
                features = self.process_packet(packet)
                if features:
                    features_list.append(features)
                    
            # Clear buffer
            self.packet_buffer = []
            
            # Convert to DataFrame
            if features_list:
                df = pd.DataFrame(features_list)
                
                # Add time-based features
                if 'timestamp' in df.columns:
                    df['time_diff'] = df['timestamp'].diff()
                    df['time_diff'] = df['time_diff'].fillna(0)
                    
                return df
            else:
                return pd.DataFrame()
                
        except Exception as e:
            logger.error(f"Error processing buffer: {str(e)}")
            return pd.DataFrame()
            
    def add_packet(self, packet: Packet):
        """Add a packet to the buffer."""
        self.packet_buffer.append(packet) 