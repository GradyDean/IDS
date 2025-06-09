from core.packet_analyzer import PacketAnalyzer
from core.attack_detector import AttackDetector
import pandas as pd
import logging
import argparse
from pathlib import Path
import json
from scapy.all import rdpcap
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def measure_dataset_contamination(pcap_file):
    """
    Measure the contamination level in a network traffic dataset.
    
    Args:
        pcap_file: Path to the PCAP file to analyze
    """
    try:
        # Initialize components
        packet_analyzer = PacketAnalyzer()
        attack_detector = AttackDetector()
        
        logger.info(f"Analyzing dataset: {pcap_file}")
        
        # Read the PCAP file
        packets = rdpcap(pcap_file)
        
        # Process each packet
        for packet in packets:
            packet_analyzer.packet_callback(packet)
        
        # Get features from the processed data
        features = packet_analyzer.get_features()
        
        if features.empty:
            logger.error("No features extracted from the dataset")
            return
        
        # Analyze each packet for potential attacks
        total_packets = len(features)
        suspicious_packets = 0
        attack_types = {}
        
        for idx, feature_set in features.iterrows():
            try:
                # Convert feature set to dictionary and ensure it's a proper dict
                feature_dict = feature_set.to_dict()
                if not isinstance(feature_dict, dict):
                    logger.warning(f"Feature set {idx} is not a dictionary, skipping")
                    continue
                
                # Get the corresponding packet
                packet = packet_analyzer.packet_buffer[idx] if idx < len(packet_analyzer.packet_buffer) else {}
                
                # Detect attacks
                attacks = attack_detector.detect_attacks(feature_dict, packet)
                
                if attacks:
                    suspicious_packets += 1
                    # Count attack types
                    for attack in attacks:
                        attack_type = attack['type']
                        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            except Exception as e:
                logger.error(f"Error processing packet {idx}: {str(e)}")
                continue
        
        # Calculate contamination
        contamination = suspicious_packets / total_packets if total_packets > 0 else 0
        
        # Prepare results
        results = {
            'total_packets': total_packets,
            'suspicious_packets': suspicious_packets,
            'contamination': contamination,
            'attack_types': attack_types,
            'attack_distribution': {
                attack_type: count/total_packets 
                for attack_type, count in attack_types.items()
            }
        }
        
        # Create results directory if it doesn't exist
        results_dir = Path('analysis_results')
        results_dir.mkdir(exist_ok=True)
        
        # Save results
        results_file = results_dir / f"{Path(pcap_file).stem}_analysis.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Print summary
        logger.info(f"\nAnalysis Results for {pcap_file}:")
        logger.info(f"Total packets analyzed: {total_packets}")
        logger.info(f"Suspicious packets found: {suspicious_packets}")
        logger.info(f"Estimated contamination: {contamination:.2%}")
        logger.info("\nAttack type distribution:")
        for attack_type, count in attack_types.items():
            percentage = count/total_packets
            logger.info(f"- {attack_type}: {count} packets ({percentage:.2%})")
        
        logger.info(f"\nDetailed results saved to: {results_file}")
        
    except Exception as e:
        logger.error(f"Error analyzing dataset: {str(e)}")
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Measure contamination level in network traffic dataset')
    parser.add_argument('pcap_file', type=str, help='Path to the PCAP file to analyze')
    
    args = parser.parse_args()
    
    measure_dataset_contamination(args.pcap_file) 