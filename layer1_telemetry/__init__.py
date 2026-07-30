"""
=============================================================================
LAYER 1: TELEMETRY, EVENT COLLECTION & DATA LOADING
Package Initialization
=============================================================================
"""

from .data_loader import (
    load_edge_iiot_dataset,
    load_individual_attack_csv,
    load_mixed_attack_test,
    partition_data_for_fl,
    build_edge_iiot_threat_dataset,
    build_training_dataset,
    list_available_raw_attack_files,
    list_available_normal_sensor_files,
    FEATURE_NAMES,
)
from .fake_incident import SCENARIOS, SCENARIO_PROFILES
from .domain_ddos_icmp import get_ddos_icmp_domain_data
from .domain_sql_injection import get_sql_injection_domain_data
from .domain_port_scanning import get_port_scanning_domain_data
from .domain_ransomware import get_ransomware_domain_data
from .domain_backdoor import get_backdoor_domain_data
from .domain_fingerprinting import get_fingerprinting_domain_data
from .domain_mitm import get_mitm_domain_data
from .domain_password import get_password_domain_data
from .domain_uploading import get_uploading_domain_data
from .domain_vulnerability_scanner import get_vulnerability_scanner_domain_data
from .domain_xss import get_xss_domain_data

# Layer 0 preprocessor — re-exported here for convenience
from layer0_preprocessing import DataPreprocessor

