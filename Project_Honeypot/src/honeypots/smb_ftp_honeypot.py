"""
SMB and FTP Honeypot for file sharing attacks.
"""

import asyncio
from datetime import datetime
from typing import Dict, Any
import os


class FTPHoneypot:
    """Simple FTP honeypot."""
    
    def __init__(self, config, logger, db, threat_intel, rate_limiter, alerting):
        self.config = config.get('ftp', {})
        self.port = self.config.get('port', 2121)
        self.host = self.config.get('host', '0.0.0.0')
        self.banner = self.config.get('banner', '220 Pure-FTPd')
        
        self.logger = logger
        self.db = db
        self.threat_intel = threat_intel
        self.rate_limiter = rate_limiter
        self.alerting = alerting
        
        self.server = None
    
    async def start(self):
        """Start FTP honeypot."""
        self.server = await asyncio.start_server(
            self.handle_connection,
            self.host,
            self.port
        )
        print(f"[FTP] Honeypot running on {self.host}:{self.port}")
    
    async def handle_connection(self, reader, writer):
        """Handle FTP connection."""
        addr = writer.get_extra_info('peername')
        client_ip = addr[0] if addr else 'unknown'
        
        print(f"[FTP] Connection from {client_ip}")
        
        # Check rate limit
        allowed, reason = await self.rate_limiter.check_rate_limit(client_ip)
        if not allowed:
            writer.close()
            await writer.wait_closed()
            return
        
        try:
            # Send welcome banner
            writer.write(f"{self.banner}\r\n".encode())
            await writer.drain()
            
            username = None
            
            while True:
                data = await asyncio.wait_for(reader.readline(), timeout=30.0)
                if not data:
                    break
                
                command = data.decode('utf-8', errors='ignore').strip()
                print(f"[FTP] {client_ip}: {command}")
                
                # Log command
                event_data = {
                    'service': 'ftp',
                    'event_type': 'ftp_command',
                    'source_ip': client_ip,
                    'command': command,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                await self.logger.log_event('ftp', 'ftp_command', event_data)
                await self.db.log_attack(event_data)
                
                # Parse command
                parts = command.split(' ', 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ''
                
                if cmd == 'USER':
                    username = arg
                    writer.write(b"331 User name okay, need password\r\n")
                
                elif cmd == 'PASS':
                    # Log credentials
                    ip_info = await self.threat_intel.enrich_ip(client_ip)
                    cred_event = {
                        'service': 'ftp',
                        'event_type': 'credential_attempt',
                        'source_ip': client_ip,
                        'username': username or 'anonymous',
                        'password': arg,
                        'timestamp': datetime.utcnow().isoformat(),
                        **ip_info
                    }
                    
                    await self.logger.log_event('ftp', 'credential_attempt', cred_event)
                    await self.db.log_attack(cred_event)
                    
                    # Always reject
                    writer.write(b"530 Login incorrect\r\n")
                
                elif cmd == 'QUIT':
                    writer.write(b"221 Goodbye\r\n")
                    break
                
                else:
                    writer.write(b"502 Command not implemented\r\n")
                
                await writer.drain()
        
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            print(f"[FTP] Connection error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def stop(self):
        """Stop FTP honeypot."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print("[FTP] Honeypot stopped")


class SMBFTPHoneypot:
    """Combined SMB/FTP honeypot manager."""
    
    def __init__(self, config: Dict[str, Any], logger, db, threat_intel, rate_limiter, alerting):
        self.config = config.get('smb_ftp', {})
        self.enabled = self.config.get('enabled', True)
        
        self.logger = logger
        self.db = db
        self.threat_intel = threat_intel
        self.rate_limiter = rate_limiter
        self.alerting = alerting
        
        self.ftp_honeypot = FTPHoneypot(
            self.config, logger, db, threat_intel, rate_limiter, alerting
        )
    
    async def start(self):
        """Start both SMB and FTP honeypots."""
        if not self.enabled:
            print("[SMB/FTP] Honeypot disabled in configuration")
            return
        
        # Start FTP
        await self.ftp_honeypot.start()
        
        # Note: SMB is complex and would require additional libraries
        # This is a simplified implementation
        print("[SMB] Note: Full SMB implementation requires additional setup")
    
    async def stop(self):
        """Stop honeypots."""
        await self.ftp_honeypot.stop()


async def run_smb_ftp_honeypot(config, logger, db, threat_intel, rate_limiter, alerting):
    """Standalone function to run SMB/FTP honeypot."""
    honeypot = SMBFTPHoneypot(config, logger, db, threat_intel, rate_limiter, alerting)
    await honeypot.start()
    
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        await honeypot.stop()
