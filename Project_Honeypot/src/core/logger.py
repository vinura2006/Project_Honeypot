"""
Core logging module for honeypot system.
Provides structured JSON logging with multiple output destinations.
"""

import logging
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from pythonjsonlogger import jsonlogger
import asyncio
from logging.handlers import RotatingFileHandler


class HoneypotLogger:
    """Centralized logging system for all honeypot events."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.log_dir = Path(config.get('global', {}).get('log_dir', './logs'))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.loggers = {}
        
    def get_logger(self, name: str, log_file: Optional[str] = None) -> logging.Logger:
        """Get or create a logger for a specific honeypot service."""
        if name in self.loggers:
            return self.loggers[name]
        
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        
        # Console handler with color
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # JSON file handler
        if log_file is None:
            log_file = f"{name}.json"
        
        file_path = self.log_dir / log_file
        file_handler = RotatingFileHandler(
            file_path,
            maxBytes=50*1024*1024,  # 50MB
            backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        
        # Custom JSON formatter
        json_formatter = jsonlogger.JsonFormatter(
            '%(timestamp)s %(name)s %(levelname)s %(message)s'
        )
        file_handler.setFormatter(json_formatter)
        logger.addHandler(file_handler)
        
        self.loggers[name] = logger
        return logger
    
    async def log_event(self, service: str, event_type: str, data: Dict[str, Any]):
        """Log a honeypot event asynchronously."""
        logger = self.get_logger(service)
        
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'service': service,
            'event_type': event_type,
            **data
        }
        
        # Log at appropriate level based on event type
        if event_type in ['attack_detected', 'exploit_attempt', 'suspicious_activity']:
            logger.warning(json.dumps(event))
        elif event_type in ['critical_threat', 'system_compromise']:
            logger.error(json.dumps(event))
        else:
            logger.info(json.dumps(event))
    
    def log_connection(self, service: str, source_ip: str, source_port: int, 
                      destination_port: int, additional_data: Dict = None):
        """Log a connection event."""
        data = {
            'source_ip': source_ip,
            'source_port': source_port,
            'destination_port': destination_port,
            'timestamp': datetime.utcnow().isoformat()
        }
        if additional_data:
            data.update(additional_data)
        
        logger = self.get_logger(service)
        logger.info(json.dumps(data))
    
    def log_credentials(self, service: str, source_ip: str, username: str, 
                       password: str, success: bool = False):
        """Log credential attempt."""
        data = {
            'event_type': 'credential_attempt',
            'source_ip': source_ip,
            'username': username,
            'password': password,
            'success': success,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger = self.get_logger(service)
        logger.warning(json.dumps(data))
    
    def log_command(self, service: str, source_ip: str, command: str, 
                   session_id: str = None):
        """Log command execution."""
        data = {
            'event_type': 'command_execution',
            'source_ip': source_ip,
            'command': command,
            'session_id': session_id,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger = self.get_logger(service)
        logger.info(json.dumps(data))
    
    def log_payload(self, service: str, source_ip: str, payload: str, 
                   payload_type: str = 'unknown'):
        """Log attack payload."""
        data = {
            'event_type': 'payload_received',
            'source_ip': source_ip,
            'payload': payload[:1000],  # Limit payload size
            'payload_type': payload_type,
            'payload_size': len(payload),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger = self.get_logger(service)
        logger.warning(json.dumps(data))


# Global logger instance
_logger_instance: Optional[HoneypotLogger] = None


def initialize_logger(config: Dict[str, Any]) -> HoneypotLogger:
    """Initialize the global logger instance."""
    global _logger_instance
    _logger_instance = HoneypotLogger(config)
    return _logger_instance


def get_logger_instance() -> HoneypotLogger:
    """Get the global logger instance."""
    if _logger_instance is None:
        raise RuntimeError("Logger not initialized. Call initialize_logger first.")
    return _logger_instance
