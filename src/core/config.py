"""Configuration loader and utility functions."""

import yaml
import os
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv


def load_config(config_path: str = None) -> Dict[str, Any]:
    """Load configuration from YAML file with environment variable substitution."""
    if config_path is None:
        config_path = os.getenv('HONEYPOT_CONFIG', '/app/config/honeypot_config.yaml')
    
    # Load environment variables
    load_dotenv()
    
    with open(config_path, 'r') as f:
        config_text = f.read()
    
    # Replace environment variables
    config_text = os.path.expandvars(config_text)
    
    config = yaml.safe_load(config_text)
    return config


def get_log_dir(config: Dict[str, Any]) -> Path:
    """Get log directory path."""
    log_dir = Path(config.get('global', {}).get('log_dir', './logs'))
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def get_data_dir(config: Dict[str, Any]) -> Path:
    """Get data directory path."""
    data_dir = Path(config.get('global', {}).get('data_dir', './data'))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir
