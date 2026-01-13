"""
Database Honeypot simulating MySQL and PostgreSQL protocols.
Logs authentication attempts and SQL queries.
"""

import asyncio
from datetime import datetime
from typing import Dict, Any
import struct


class DatabaseHoneypot:
    """Simple database protocol honeypot."""
    
    def __init__(self, config: Dict[str, Any], logger, db, threat_intel, rate_limiter, alerting):
        self.config = config.get('database_honeypot', {})
        self.enabled = self.config.get('enabled', True)
        
        self.mysql_config = self.config.get('mysql', {})
        self.mysql_port = self.mysql_config.get('port', 3306)
        
        self.postgres_config = self.config.get('postgres', {})
        self.postgres_port = self.postgres_config.get('port', 5432)
        
        self.host = '0.0.0.0'
        
        self.logger = logger
        self.db = db
        self.threat_intel = threat_intel
        self.rate_limiter = rate_limiter
        self.alerting = alerting
        
        self.mysql_server = None
        self.postgres_server = None
    
    async def start(self):
        """Start database honeypots."""
        if not self.enabled:
            print("[DB] Honeypot disabled in configuration")
            return
        
        # Start MySQL honeypot
        self.mysql_server = await asyncio.start_server(
            self.handle_mysql_connection,
            self.host,
            self.mysql_port
        )
        print(f"[MySQL] Honeypot running on {self.host}:{self.mysql_port}")
        
        # Start PostgreSQL honeypot  
        self.postgres_server = await asyncio.start_server(
            self.handle_postgres_connection,
            self.host,
            self.postgres_port
        )
        print(f"[PostgreSQL] Honeypot running on {self.host}:{self.postgres_port}")
    
    async def handle_mysql_connection(self, reader, writer):
        """Handle MySQL protocol connection."""
        addr = writer.get_extra_info('peername')
        client_ip = addr[0] if addr else 'unknown'
        
        print(f"[MySQL] Connection from {client_ip}")
        
        # Check rate limit
        allowed, reason = await self.rate_limiter.check_rate_limit(client_ip)
        if not allowed:
            writer.close()
            await writer.wait_closed()
            return
        
        try:
            # Send MySQL handshake
            handshake = self._create_mysql_handshake()
            writer.write(handshake)
            await writer.drain()
            
            # Read client response (contains auth data)
            data = await reader.read(4096)
            
            if data:
                username, password = self._parse_mysql_auth(data)
                
                # Enrich IP
                ip_info = await self.threat_intel.enrich_ip(client_ip)
                
                # Log authentication attempt
                event_data = {
                    'service': 'mysql',
                    'event_type': 'credential_attempt',
                    'source_ip': client_ip,
                    'username': username,
                    'password': password,
                    'timestamp': datetime.utcnow().isoformat(),
                    **ip_info
                }
                
                await self.logger.log_event('mysql', 'credential_attempt', event_data)
                await self.db.log_attack(event_data)
                
                # Send authentication failure
                error_packet = self._create_mysql_error("Access denied")
                writer.write(error_packet)
                await writer.drain()
        
        except Exception as e:
            print(f"[MySQL] Connection error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def handle_postgres_connection(self, reader, writer):
        """Handle PostgreSQL protocol connection."""
        addr = writer.get_extra_info('peername')
        client_ip = addr[0] if addr else 'unknown'
        
        print(f"[PostgreSQL] Connection from {client_ip}")
        
        # Check rate limit
        allowed, reason = await self.rate_limiter.check_rate_limit(client_ip)
        if not allowed:
            writer.close()
            await writer.wait_closed()
            return
        
        try:
            # Read startup message
            data = await reader.read(4096)
            
            if len(data) >= 8:
                username, database = self._parse_postgres_startup(data)
                
                # Enrich IP
                ip_info = await self.threat_intel.enrich_ip(client_ip)
                
                # Log connection attempt
                event_data = {
                    'service': 'postgresql',
                    'event_type': 'connection_attempt',
                    'source_ip': client_ip,
                    'username': username,
                    'database': database,
                    'timestamp': datetime.utcnow().isoformat(),
                    **ip_info
                }
                
                await self.logger.log_event('postgresql', 'connection_attempt', event_data)
                await self.db.log_attack(event_data)
                
                # Request password
                auth_request = b'R\x00\x00\x00\x08\x00\x00\x00\x03'  # MD5 auth
                writer.write(auth_request)
                await writer.drain()
                
                # Read password response
                pwd_data = await reader.read(4096)
                if pwd_data:
                    event_data['event_type'] = 'credential_attempt'
                    event_data['password'] = 'md5_hash'
                    await self.logger.log_event('postgresql', 'credential_attempt', event_data)
                    await self.db.log_attack(event_data)
                
                # Send error
                error_msg = b'E\x00\x00\x00\x26SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00'
                writer.write(error_msg)
                await writer.drain()
        
        except Exception as e:
            print(f"[PostgreSQL] Connection error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    def _create_mysql_handshake(self) -> bytes:
        """Create MySQL initial handshake packet."""
        # Simplified handshake
        protocol_version = 10
        server_version = b"8.0.32-MySQL\x00"
        thread_id = struct.pack('<I', 1)
        salt = b'12345678'
        
        packet = bytes([protocol_version]) + server_version + thread_id + salt
        length = len(packet)
        header = struct.pack('<I', length)[0:3] + b'\x00'  # packet number 0
        
        return header + packet
    
    def _parse_mysql_auth(self, data: bytes) -> tuple:
        """Parse MySQL authentication packet."""
        try:
            # Skip header (4 bytes)
            if len(data) < 36:
                return ('unknown', '')
            
            # Skip capability flags, max packet, charset (4+4+1+23 = 32 bytes)
            offset = 36
            
            # Read username (null-terminated)
            username_end = data.find(b'\x00', offset)
            if username_end == -1:
                return ('unknown', '')
            
            username = data[offset:username_end].decode('utf-8', errors='ignore')
            return (username, 'hashed')
        
        except Exception as e:
            return ('parse_error', '')
    
    def _parse_postgres_startup(self, data: bytes) -> tuple:
        """Parse PostgreSQL startup message."""
        try:
            # Skip length and protocol version (8 bytes)
            if len(data) < 12:
                return ('unknown', 'unknown')
            
            params = data[8:].decode('utf-8', errors='ignore').split('\x00')
            username = 'unknown'
            database = 'unknown'
            
            for i in range(0, len(params) - 1, 2):
                if params[i] == 'user':
                    username = params[i + 1]
                elif params[i] == 'database':
                    database = params[i + 1]
            
            return (username, database)
        
        except Exception as e:
            return ('parse_error', 'parse_error')
    
    def _create_mysql_error(self, message: str) -> bytes:
        """Create MySQL error packet."""
        error_code = struct.pack('<H', 1045)  # Access denied
        sql_state = b'#28000'
        error_msg = message.encode('utf-8')
        
        packet = b'\xff' + error_code + sql_state + error_msg
        length = len(packet)
        header = struct.pack('<I', length)[0:3] + b'\x02'  # packet number 2
        
        return header + packet
    
    async def stop(self):
        """Stop database honeypots."""
        if self.mysql_server:
            self.mysql_server.close()
            await self.mysql_server.wait_closed()
        
        if self.postgres_server:
            self.postgres_server.close()
            await self.postgres_server.wait_closed()
        
        print("[DB] Honeypots stopped")


async def run_database_honeypot(config, logger, db, threat_intel, rate_limiter, alerting):
    """Standalone function to run database honeypot."""
    honeypot = DatabaseHoneypot(config, logger, db, threat_intel, rate_limiter, alerting)
    await honeypot.start()
    
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        await honeypot.stop()
