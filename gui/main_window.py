from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTabWidget, QLabel, QPushButton, QComboBox,
                             QTableWidget, QTableWidgetItem, QTextEdit)
from PySide6.QtCore import Qt, QTimer
import pyqtgraph as pg
import networkx as nx
from datetime import datetime
import json
from scapy.arch import get_if_list
from scapy.sendrecv import sniff
from ..core.packet_analyzer import PacketAnalyzer
import logging

logger = logging.getLogger(__name__)

class MainWindow(QMainWindow):
    def __init__(self, ids_system):
        super().__init__()
        self.ids_system = ids_system
        self.setWindowTitle("Network Intrusion Detection System")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Create different tabs
        self.dashboard_tab = self._create_dashboard_tab()
        self.alerts_tab = self._create_alerts_tab()
        self.network_tab = self._create_network_tab()
        self.analysis_tab = self._create_analysis_tab()
        self.threat_intel_tab = self._create_threat_intel_tab()
        
        tabs.addTab(self.dashboard_tab, "Dashboard")
        tabs.addTab(self.alerts_tab, "Alerts")
        tabs.addTab(self.network_tab, "Network View")
        tabs.addTab(self.analysis_tab, "Analysis")
        tabs.addTab(self.threat_intel_tab, "Threat Intelligence")
        
        # Create status bar
        self.statusBar().showMessage("Ready")
        
        # Set up update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(1000)  # Update every second
        
        # Initialize graphs
        self._init_graphs()
        
        # Initialize capture state
        self.is_capturing = False
    
    def _create_dashboard_tab(self):
        """Create the dashboard tab with real-time statistics."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create interface selector and capture controls
        control_layout = QHBoxLayout()
        
        # Interface selector
        interface_label = QLabel("Network Interface:")
        self.interface_combo = QComboBox()
        self._populate_interfaces()
        self.interface_combo.currentTextChanged.connect(self._on_interface_changed)
        
        # Capture control button
        self.capture_button = QPushButton("Start Capture")
        self.capture_button.clicked.connect(self._toggle_capture)
        
        control_layout.addWidget(interface_label)
        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(self.capture_button)
        control_layout.addStretch()
        
        # Create graphs
        self.packet_rate_plot = pg.PlotWidget(title="Packet Rate")
        self.attack_distribution_plot = pg.PlotWidget(title="Attack Distribution")
        
        # Create statistics widgets
        stats_layout = QHBoxLayout()
        self.total_packets_label = QLabel("Total Packets: 0")
        self.active_flows_label = QLabel("Active Flows: 0")
        self.alerts_count_label = QLabel("Active Alerts: 0")
        
        stats_layout.addWidget(self.total_packets_label)
        stats_layout.addWidget(self.active_flows_label)
        stats_layout.addWidget(self.alerts_count_label)
        
        # Add widgets to layout
        layout.addLayout(control_layout)
        layout.addLayout(stats_layout)
        layout.addWidget(self.packet_rate_plot)
        layout.addWidget(self.attack_distribution_plot)
        
        return tab
    
    def _toggle_capture(self):
        """Toggle packet capture on/off."""
        if not self.is_capturing:
            try:
                # Start capture
                self.ids_system.packet_analyzer.start_capture()
                self.is_capturing = True
                self.capture_button.setText("Stop Capture")
                self.statusBar().showMessage("Capturing packets...")
            except Exception as e:
                self.statusBar().showMessage(f"Error starting capture: {str(e)}")
        else:
            try:
                # Stop capture
                self.ids_system.packet_analyzer.stop_capture()
                self.is_capturing = False
                self.capture_button.setText("Start Capture")
                self.statusBar().showMessage("Capture stopped")
            except Exception as e:
                self.statusBar().showMessage(f"Error stopping capture: {str(e)}")
    
    def _populate_interfaces(self):
        """Populate the interface combo box with available network interfaces."""
        interfaces = get_if_list()
        self.interface_combo.clear()
        self.interface_combo.addItems(interfaces)
        
        # Set the current interface if it exists
        if self.ids_system.interface in interfaces:
            self.interface_combo.setCurrentText(self.ids_system.interface)
    
    def _on_interface_changed(self, interface):
        """Handle interface change."""
        if interface and interface != self.ids_system.interface:
            try:
                # Stop current capture if running
                if self.is_capturing:
                    self.ids_system.packet_analyzer.stop_capture()
                    self.is_capturing = False
                    self.capture_button.setText("Start Capture")
                
                # Update interface
                self.ids_system.interface = interface
                self.ids_system.packet_analyzer = PacketAnalyzer(interface)
                
                self.statusBar().showMessage(f"Switched to interface: {interface}")
            except Exception as e:
                self.statusBar().showMessage(f"Error switching interface: {str(e)}")
    
    def _create_alerts_tab(self):
        """Create the alerts tab with detailed alert information."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(5)
        self.alerts_table.setHorizontalHeaderLabels([
            "Timestamp", "Type", "Confidence", "Severity", "Details"
        ])
        
        # Create alert details text area
        self.alert_details = QTextEdit()
        self.alert_details.setReadOnly(True)
        
        # Add widgets to layout
        layout.addWidget(self.alerts_table)
        layout.addWidget(QLabel("Alert Details:"))
        layout.addWidget(self.alert_details)
        
        return tab
    
    def _create_network_tab(self):
        """Create the network visualization tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create network graph
        self.network_graph = pg.GraphicsLayoutWidget()
        self.network_view = self.network_graph.addViewBox()
        self.network_view.setAspectLocked()
        
        # Create controls
        controls_layout = QHBoxLayout()
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Force Directed", "Circular", "Spring"])
        self.layout_combo.currentTextChanged.connect(self._update_network_view)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._update_network_view)
        
        controls_layout.addWidget(QLabel("Layout:"))
        controls_layout.addWidget(self.layout_combo)
        controls_layout.addWidget(self.refresh_button)
        controls_layout.addStretch()
        
        # Add widgets to layout
        layout.addLayout(controls_layout)
        layout.addWidget(self.network_graph)
        
        return tab
    
    def _create_analysis_tab(self):
        """Create the analysis tab with detailed statistics."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create protocol distribution plot
        self.protocol_plot = pg.PlotWidget(title="Protocol Distribution")
        
        # Create port distribution plot
        self.port_plot = pg.PlotWidget(title="Port Distribution")
        
        # Create flow statistics
        self.flow_stats = QTableWidget()
        self.flow_stats.setColumnCount(4)
        self.flow_stats.setHorizontalHeaderLabels([
            "Source IP", "Destination IP", "Protocol", "Packets"
        ])
        
        # Add widgets to layout
        layout.addWidget(self.protocol_plot)
        layout.addWidget(self.port_plot)
        layout.addWidget(QLabel("Flow Statistics:"))
        layout.addWidget(self.flow_stats)
        
        return tab
    
    def _create_threat_intel_tab(self):
        """Create the threat intelligence tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create threat patterns table
        self.threat_patterns_table = QTableWidget()
        self.threat_patterns_table.setColumnCount(4)
        self.threat_patterns_table.setHorizontalHeaderLabels([
            "Type", "Confidence", "Last Updated", "Details"
        ])
        
        # Create confirmed attacks table
        self.confirmed_attacks_table = QTableWidget()
        self.confirmed_attacks_table.setColumnCount(5)
        self.confirmed_attacks_table.setHorizontalHeaderLabels([
            "Timestamp", "Type", "Confidence", "Severity", "Details"
        ])
        
        # Create threat intelligence status
        status_layout = QHBoxLayout()
        self.threat_intel_status = QLabel("Threat Intelligence Status: Not Connected")
        self.sync_button = QPushButton("Sync Now")
        self.sync_button.clicked.connect(self._sync_threat_intel)
        status_layout.addWidget(self.threat_intel_status)
        status_layout.addWidget(self.sync_button)
        status_layout.addStretch()
        
        # Add widgets to layout
        layout.addLayout(status_layout)
        layout.addWidget(QLabel("Known Threat Patterns:"))
        layout.addWidget(self.threat_patterns_table)
        layout.addWidget(QLabel("Confirmed Attacks:"))
        layout.addWidget(self.confirmed_attacks_table)
        
        return tab
    
    def _sync_threat_intel(self):
        """Manually trigger threat intelligence synchronization."""
        try:
            # Force sync of threat patterns
            self.ids_system.threat_intelligence._sync_patterns()
            self.statusBar().showMessage("Threat intelligence synchronized")
            self._update_threat_intel_display()
        except Exception as e:
            self.statusBar().showMessage(f"Error syncing threat intelligence: {str(e)}")
    
    def _update_threat_intel_display(self):
        """Update the threat intelligence display."""
        try:
            # Update threat patterns table
            patterns = self.ids_system.threat_intelligence.get_attack_patterns()
            self.threat_patterns_table.setRowCount(len(patterns))
            for i, pattern in enumerate(patterns):
                self.threat_patterns_table.setItem(i, 0, QTableWidgetItem(pattern['type']))
                self.threat_patterns_table.setItem(i, 1, QTableWidgetItem(f"{pattern.get('confidence', 'N/A')}"))
                self.threat_patterns_table.setItem(i, 2, QTableWidgetItem(pattern.get('last_updated', 'N/A')))
                self.threat_patterns_table.setItem(i, 3, QTableWidgetItem(json.dumps(pattern.get('details', {}))))
            
            # Update confirmed attacks table
            confirmed_attacks = self.ids_system.get_confirmed_attacks()
            self.confirmed_attacks_table.setRowCount(len(confirmed_attacks))
            for i, attack in enumerate(confirmed_attacks):
                self.confirmed_attacks_table.setItem(i, 0, QTableWidgetItem(attack['timestamp']))
                self.confirmed_attacks_table.setItem(i, 1, QTableWidgetItem(attack['type']))
                self.confirmed_attacks_table.setItem(i, 2, QTableWidgetItem(f"{attack['confidence']:.2f}"))
                self.confirmed_attacks_table.setItem(i, 3, QTableWidgetItem(attack['severity']))
                self.confirmed_attacks_table.setItem(i, 4, QTableWidgetItem(json.dumps(attack['details'])))
            
            # Update status
            if self.ids_system.threat_intelligence.api_key and self.ids_system.threat_intelligence.server_url:
                self.threat_intel_status.setText("Threat Intelligence Status: Connected")
            else:
                self.threat_intel_status.setText("Threat Intelligence Status: Not Configured")
                
        except Exception as e:
            self.statusBar().showMessage(f"Error updating threat intelligence display: {str(e)}")
    
    def _init_graphs(self):
        """Initialize the graphs with empty data."""
        # Packet rate plot
        self.packet_rate_plot.setLabel('left', 'Packets/second')
        self.packet_rate_plot.setLabel('bottom', 'Time')
        self.packet_rate_curve = self.packet_rate_plot.plot(pen='b')
        
        # Attack distribution plot
        self.attack_distribution_plot.setLabel('left', 'Count')
        self.attack_distribution_plot.setLabel('bottom', 'Attack Type')
        
        # Protocol distribution plot
        self.protocol_plot.setLabel('left', 'Count')
        self.protocol_plot.setLabel('bottom', 'Protocol')
        
        # Port distribution plot
        self.port_plot.setLabel('left', 'Count')
        self.port_plot.setLabel('bottom', 'Port')
    
    def update_display(self):
        """Update all displays with current data."""
        try:
            # Get current features and alerts
            features = self.ids_system.packet_analyzer.get_features()
            alerts = self.ids_system.get_alerts()
            
            # Update dashboard
            self._update_dashboard(features, alerts)
            
            # Update alerts tab
            self._update_alerts(alerts)
            
            # Update network view
            self._update_network_view(features)
            
            # Update analysis tab
            self._update_analysis(features)
            
            # Update threat intelligence tab
            self._update_threat_intel_display()
            
        except Exception as e:
            self.statusBar().showMessage(f"Error updating display: {str(e)}")
    
    def _update_dashboard(self, features, alerts):
        """Update the dashboard with current statistics."""
        if not features.empty:
            # Update packet rate plot
            self.packet_rate_curve.setData(
                features['timestamp'].values,
                features['packets_per_second'].values
            )
            
            # Update statistics labels
            self.total_packets_label.setText(f"Total Packets: {features['packet_count'].sum()}")
            self.active_flows_label.setText(f"Active Flows: {features['active_flows'].iloc[-1]}")
            self.alerts_count_label.setText(f"Active Alerts: {len(alerts)}")
            
            # Update attack distribution
            attack_types = [alert['type'] for alert in alerts]
            attack_counts = {attack: attack_types.count(attack) for attack in set(attack_types)}
            
            self.attack_distribution_plot.clear()
            if attack_counts:
                x = list(range(len(attack_counts)))
                self.attack_distribution_plot.setXRange(-0.5, len(attack_counts) - 0.5)
                # Create a bar graph item
                bg = pg.BarGraphItem(x=x, height=list(attack_counts.values()), width=0.6)
                self.attack_distribution_plot.addItem(bg)
                # Set x-axis labels
                ax = self.attack_distribution_plot.getAxis('bottom')
                ax.setTicks([[(i, attack) for i, attack in enumerate(attack_counts.keys())]])
    
    def _update_alerts(self, alerts):
        """Update the alerts table with current alerts."""
        self.alerts_table.setRowCount(len(alerts))
        for i, alert in enumerate(alerts):
            self.alerts_table.setItem(i, 0, QTableWidgetItem(alert['timestamp']))
            self.alerts_table.setItem(i, 1, QTableWidgetItem(alert['type']))
            self.alerts_table.setItem(i, 2, QTableWidgetItem(f"{alert['confidence']:.2f}"))
            self.alerts_table.setItem(i, 3, QTableWidgetItem(alert['severity']))
            self.alerts_table.setItem(i, 4, QTableWidgetItem(json.dumps(alert['details'])))
    
    def _update_network_view(self, features=None):
        """Update the network visualization."""
        try:
            # Get raw packet data from the packet buffer
            packet_buffer = self.ids_system.packet_analyzer.packet_buffer
            
            if not packet_buffer:
                self.statusBar().showMessage("No network data available")
                return
            
            # Create network graph
            G = nx.Graph()
            
            # Add nodes and edges from packet buffer
            for packet in packet_buffer:
                if 'src_ip' in packet and 'dst_ip' in packet:
                    src_ip = str(packet['src_ip'])
                    dst_ip = str(packet['dst_ip'])
                    G.add_edge(src_ip, dst_ip)
            
            if not G.edges():
                self.statusBar().showMessage("No network connections to display")
                return
            
            # Apply selected layout
            layout_name = self.layout_combo.currentText()
            if layout_name == "Force Directed":
                pos = nx.spring_layout(G, k=1, iterations=50)
            elif layout_name == "Circular":
                pos = nx.circular_layout(G)
            else:  # Spring
                pos = nx.spring_layout(G)
            
            # Clear current view
            self.network_view.clear()
            
            # Draw edges first (so they appear behind nodes)
            for edge in G.edges():
                x1, y1 = pos[edge[0]]
                x2, y2 = pos[edge[1]]
                line = pg.PlotDataItem(
                    x=[x1, x2],
                    y=[y1, y2],
                    pen=pg.mkPen(color='w', width=1)
                )
                self.network_view.addItem(line)
            
            # Draw nodes
            for node, (x, y) in pos.items():
                # Create node with different colors based on connection count
                degree = G.degree(node)
                if degree > 5:
                    color = 'r'  # Red for highly connected nodes
                elif degree > 2:
                    color = 'y'  # Yellow for moderately connected nodes
                else:
                    color = 'g'  # Green for nodes with few connections
                    
                node_item = pg.PlotDataItem(
                    x=[x],
                    y=[y],
                    symbol='o',
                    symbolSize=10 + degree * 2,  # Size based on connections
                    symbolBrush=color,
                    symbolPen=None
                )
                self.network_view.addItem(node_item)
                
                # Add IP label
                text = pg.TextItem(
                    text=node,
                    color='w',
                    anchor=(0.5, 0.5)
                )
                text.setPos(x, y)
                self.network_view.addItem(text)
            
            # Auto-scale the view
            self.network_view.autoRange()
            
        except Exception as e:
            self.statusBar().showMessage(f"Error updating network view: {str(e)}")
            logger.error(f"Error in network view: {str(e)}")
    
    def _update_analysis(self, features):
        """Update the analysis tab with current statistics."""
        if not features.empty:
            # Update protocol distribution
            if 'protocol_distribution' in features.columns:
                protocols = features['protocol_distribution'].iloc[-1]
                self.protocol_plot.clear()
                x = list(range(len(protocols)))
                self.protocol_plot.setXRange(-0.5, len(protocols) - 0.5)
                # Create a bar graph item
                bg = pg.BarGraphItem(x=x, height=list(protocols.values()), width=0.6)
                self.protocol_plot.addItem(bg)
                # Set x-axis labels
                ax = self.protocol_plot.getAxis('bottom')
                ax.setTicks([[(i, proto) for i, proto in enumerate(protocols.keys())]])
            
            # Update port distribution
            if 'port_distribution' in features.columns:
                ports = features['port_distribution'].iloc[-1]
                self.port_plot.clear()
                x = list(range(len(ports)))
                self.port_plot.setXRange(-0.5, len(ports) - 0.5)
                # Create a bar graph item
                bg = pg.BarGraphItem(x=x, height=list(ports.values()), width=0.6)
                self.port_plot.addItem(bg)
                # Set x-axis labels
                ax = self.port_plot.getAxis('bottom')
                ax.setTicks([[(i, str(port)) for i, port in enumerate(ports.keys())]])
            
            # Update flow statistics
            if 'src_ip' in features.columns and 'dst_ip' in features.columns:
                flows = features.groupby(['src_ip', 'dst_ip', 'protocol']).size().reset_index()
                self.flow_stats.setRowCount(len(flows))
                for i, (_, row) in enumerate(flows.iterrows()):
                    self.flow_stats.setItem(i, 0, QTableWidgetItem(row['src_ip']))
                    self.flow_stats.setItem(i, 1, QTableWidgetItem(row['dst_ip']))
                    self.flow_stats.setItem(i, 2, QTableWidgetItem(str(row['protocol'])))
                    self.flow_stats.setItem(i, 3, QTableWidgetItem(str(row[0]))) 