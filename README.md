# Hybrid Network Intrusion Detection System

A sophisticated NIDS integrating machine learning, signature-based detection, and threat intelligence sharing to provide comprehensive real-time network monitoring.

## Features

- Real-time network traffic monitoring
- Machine learning-based anomaly detection
- Signature-based attack detection
- Threat intelligence integration
- Modern GUI interface

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ids.git
cd ids
```

2. Create a virtual environment and install dependencies:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Using the CTU Dataset

The system now supports training and testing with the CTU-Malware-Capture-Botnet-46 dataset. This dataset provides labeled network traffic data for botnet detection.

### Dataset Setup

1. Download the CTU dataset from [CTU-Malware-Capture-Botnet-46](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/)
2. Extract the dataset to a directory of your choice
3. Ensure the following files are present in the dataset directory:
   - `detailed-bidirectional-flow-labels/` directory containing flow label CSV files
   - `botnet-capture-20110815-fast-flux.pcap` for testing

### Training and Testing

The system can be used in three modes:
- `train`: Train a new model using the CTU dataset
- `test`: Test an existing model against the CTU dataset
- `both`: Train a new model and test it (default)

```bash
# Train and test
python main.py --dataset /path/to/ctu/dataset --mode both

# Train only
python main.py --dataset /path/to/ctu/dataset --mode train

# Test only
python main.py --dataset /path/to/ctu/dataset --mode test --model /path/to/model.joblib
```

### Output Files

- Trained models are saved in `data/models/`
- Training metrics are saved in `data/models/training_metrics.json`
- Test results are saved in `verification_logs/ctu_test_results.json`

## Real-time Monitoring

To monitor network traffic in real-time:

```bash
python main.py --interface eth0 --model data/models/anomaly_detector.joblib
```

## PCAP Analysis

To analyze a PCAP file:

```bash
python main.py --pcap capture.pcap --model data/models/anomaly_detector.joblib
```

## System Architecture

The system consists of several key components:

1. **Traffic Analysis Engine**
   - Packet capture and analysis
   - Protocol parsing and validation
   - Traffic pattern monitoring
   - Real-time processing capabilities

2. **Machine Learning Module**
   - Unsupervised learning for anomaly detection
   - Real-time feature extraction
   - Confidence scoring system
   - Model training with historical data

3. **Signature-based Detection**
   - Detection of common attack patterns
   - Protocol-specific attack signatures
   - Customizable detection rules
   - Pattern matching capabilities

4. **Threat Intelligence Integration**
   - Real-time threat pattern sharing
   - Collaborative attack detection
   - Anonymized data sharing
   - Automatic pattern synchronization

## Configuration

The system can be configured through the `config/config.yaml` file. Key settings include:

- Network interface configuration
- Detection thresholds
- Model parameters
- Logging settings

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- CTU-Malware-Capture-Botnet-46 dataset for providing labeled network traffic data
- Scapy for packet capture and analysis
- PySide6 for the GUI framework
- scikit-learn for machine learning capabilities

## System Overview

The system consists of several key components:

1. **Traffic Analysis Engine**: Monitors and analyzes network traffic in real-time
2. **Machine Learning Module**: Detects unusual network patterns using AI
3. **Signature-based Detection**: Identifies known attack patterns
4. **Threat Intelligence Integration**: Enhances detection via collaborative intelligence sharing

## Prerequisites

- Python 3.8 or higher
- Required Python packages (install via `pip install -r requirements.txt`):
  - Scapy
  - PySide6
  - scikit-learn
  - pandas
  - numpy
  - matplotlib
  - seaborn

## Quick Start Guide

### 1. Training the Model

The system uses a hybrid approach combining machine learning with signature-based detection. To train the model:

```bash
# Train with normal traffic only
python train_direct.py --normal /path/to/normal_traffic.pcap

# Train with mixed traffic (normal + some anomalies)
python train_direct.py --normal /path/to/normal_traffic.pcap --mixed /path/to/mixed_traffic.pcap

# Train with all traffic types
python train_direct.py --normal /path/to/normal_traffic.pcap \
                      --mixed /path/to/mixed_traffic.pcap \
                      --malware /path/to/malware_traffic.pcap
```

The training process:
1. Analyzes network traffic from PCAP files
2. Extracts relevant features
3. Trains an Isolation Forest model
4. Saves the model and components to `data/models/`

### 2. Verifying the Model

After training, verify the model's performance:

```bash
python verify_model.py /path/to/test_traffic.pcap --model data/models/anomaly_detector.pkl
```

This will generate:
- Performance metrics (precision, recall, F1 score)
- ROC curve visualization
- Confusion matrix
- Detailed JSON report

Results are saved in:
- `verification_logs/` - JSON reports
- `verification_logs/plots/` - Visualizations

### 3. Using the System

#### Real-time Monitoring

To start real-time network monitoring:

```bash
python main.py --interface eth0
```

The system will:
1. Capture network traffic
2. Analyze packets in real-time
3. Detect anomalies using both ML and signature-based methods
4. Display alerts in the GUI

#### Offline Analysis

To analyze a PCAP file:

```bash
python main.py --pcap /path/to/traffic.pcap
```

## Understanding the Results

### Training Logs

Training logs are stored in `training_logs/` and include:
- Dataset statistics
- Feature importance scores
- Training parameters
- Model performance metrics

### Verification Results

Verification results include:

1. **Performance Metrics**:
   - Precision: Accuracy of anomaly detection
   - Recall: Ability to detect all anomalies
   - F1 Score: Balance between precision and recall

2. **Visualizations**:
   - ROC Curve: Shows detection accuracy at different thresholds
   - Confusion Matrix: Shows true/false positives/negatives

3. **Detailed Reports**:
   - JSON files with comprehensive metrics
   - Feature importance analysis
   - Attack type distribution

## Attack Detection Capabilities

The system can detect various types of attacks:

1. **Denial of Service (DoS)**
   - Detects high packet rates
   - Identifies unusual traffic patterns

2. **Port Scanning**
   - Monitors unique destination ports
   - Detects scanning patterns

3. **DNS Amplification**
   - Analyzes DNS query/response ratios
   - Detects potential amplification attacks

4. **TCP SYN Flood**
   - Monitors TCP SYN packet rates
   - Identifies connection flooding

5. **DNS Tunneling**
   - Analyzes DNS packet lengths
   - Detects unusual DNS patterns

6. **HTTP Flood**
   - Monitors HTTP request rates
   - Identifies web server attacks

## Best Practices

1. **Training Data**:
   - Use clean, normal traffic for initial training
   - Include known attack patterns for better detection
   - Regularly update training data

2. **Model Verification**:
   - Verify model performance before deployment
   - Monitor false positive rates
   - Adjust thresholds based on verification results

3. **System Maintenance**:
   - Regularly update threat signatures
   - Retrain model with new data
   - Monitor system performance

## Troubleshooting

Common issues and solutions:

1. **High False Positive Rate**:
   - Adjust anomaly threshold
   - Retrain with more normal traffic
   - Review feature importance

2. **Missed Detections**:
   - Update training data
   - Adjust detection thresholds
   - Review attack signatures

3. **Performance Issues**:
   - Check system resources
   - Optimize packet processing
   - Adjust buffer sizes

## Support and Updates

For issues, feature requests, or updates:
1. Check the documentation
2. Review training logs
3. Analyze verification results
4. Contact support if needed

## License

[Your License Information] 