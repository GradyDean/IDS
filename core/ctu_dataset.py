import pandas as pd
import numpy as np
from pathlib import Path
import logging
from scapy.all import rdpcap
from typing import Tuple, Dict, List
import os
import chardet

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CTUDatasetProcessor:
    def __init__(self, dataset_path: str):
        """
        Initialize the CTU dataset processor.
        
        Args:
            dataset_path: Path to the CTU dataset directory
        """
        self.dataset_path = Path(dataset_path)
        self.pcap_file = self.dataset_path
        self.flow_labels_file = self.dataset_path
        
    def load_flow_labels(self) -> pd.DataFrame:
        """
        Load flow labels from the CTU dataset.
        
        Returns:
            DataFrame containing flow labels
        """
        try:
            logger.info("Loading flow labels from CTU dataset...")
            
            # First, detect the file encoding
            with open(self.flow_labels_file, 'rb') as file:
                raw_data = file.read()
                result = chardet.detect(raw_data)
                encoding = result['encoding']
                logger.info(f"Detected file encoding: {encoding}")
            
            # Try reading with detected encoding
            try:
                df = pd.read_csv(self.flow_labels_file, sep='\t', encoding=encoding)
            except:
                # If that fails, try reading as binary
                logger.info("Attempting to read file as binary data...")
                df = pd.read_csv(self.flow_labels_file, sep='\t', encoding='latin1')
            
            # Process the data to identify anomalies
            df['is_anomaly'] = df['Label'].apply(lambda x: 1 if x == 'Botnet' else 0)
            
            # Select relevant features
            feature_columns = [
                'StartTime', 'Dur', 'Proto', 'SrcAddr', 'Sport', 'Dir', 
                'DstAddr', 'Dport', 'State', 'sTos', 'dTos', 'TotPkts', 
                'TotBytes', 'SrcBytes'
            ]
            
            # Add missing columns with default values if they don't exist
            for col in feature_columns:
                if col not in df.columns:
                    df[col] = 0
                    logger.warning(f"Column {col} not found in dataset, using default value 0")
            
            # Select only the features we need
            df = df[feature_columns + ['is_anomaly']]
            
            logger.info(f"Loaded {len(df)} flow records")
            return df
            
        except Exception as e:
            logger.error(f"Error loading flow labels: {str(e)}")
            raise
    
    def load_pcap(self) -> List[Dict]:
        """
        Load packets from the PCAP file.
        
        Returns:
            List of packet dictionaries
        """
        try:
            logger.info(f"Loading PCAP file: {self.pcap_file}")
            packets = rdpcap(str(self.pcap_file))
            return self._extract_pcap_features(packets)
        except Exception as e:
            logger.error(f"Error loading PCAP file: {str(e)}")
            raise
    
    def _extract_pcap_features(self, packets) -> List[Dict]:
        """Extract features from PCAP packets."""
        features = []
        for packet in packets:
            try:
                feature_dict = {
                    'timestamp': float(packet.time),
                    'length': len(packet),
                    'protocol': packet.type if hasattr(packet, 'type') else 0
                }
                
                # Extract IP layer features if present
                if packet.haslayer('IP'):
                    feature_dict.update({
                        'src_ip': packet['IP'].src,
                        'dst_ip': packet['IP'].dst,
                        'ip_proto': packet['IP'].proto
                    })
                
                # Extract TCP/UDP layer features if present
                if packet.haslayer('TCP'):
                    feature_dict.update({
                        'src_port': packet['TCP'].sport,
                        'dst_port': packet['TCP'].dport,
                        'tcp_flags': packet['TCP'].flags
                    })
                elif packet.haslayer('UDP'):
                    feature_dict.update({
                        'src_port': packet['UDP'].sport,
                        'dst_port': packet['UDP'].dport
                    })
                
                features.append(feature_dict)
                
            except Exception as e:
                logger.warning(f"Error extracting features from packet: {str(e)}")
                continue
        
        return features
    
    def get_training_data(self) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Get training data from flow labels.
        
        Returns:
            Tuple of (features, labels)
        """
        df = self.load_flow_labels()
        features = df.drop('is_anomaly', axis=1)
        labels = df['is_anomaly']
        return features, labels
    
    def get_test_data(self) -> Tuple[List[Dict], pd.DataFrame]:
        """
        Get test data from PCAP file.
        
        Returns:
            Tuple of (packets, features)
        """
        packets = self.load_pcap()
        features = pd.DataFrame(packets)
        return packets, features 