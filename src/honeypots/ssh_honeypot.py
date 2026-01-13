"""
SSH Honeypot implementation using asyncssh.
Captures credentials, commands, and session activity.
"""

import asyncio
import asyncssh
from datetime import datetime
from typing import Dict, Any, Optional
import io
import uuid
import json
from pathlib import Path


class SSHServer(asyncssh.SSHServer):
    """Custom SSH server for honeypot."""
    
    def __init__(self, logger, db, threat_intel, rate_limiter, alerting):
        self.logger = logger
        self.db = db
        self.threat_intel = threat_intel
        self.rate_limiter = rate_limiter
        self.alerting = alerting
        self.client_ip = None
        self.session_id = str(uuid.uuid4())
    
    def connection_made(self, conn):
        """Called when a client connects."""
        self.client_ip = conn.get_extra_info('peername')[0]
        print(f'[SSH] Connection from {self.client_ip}')
    
    def connection_lost(self, exc):
        """Called when connection is closed."""
        print(f'[SSH] Connection closed from {self.client_ip}')
    
    def begin_auth(self, username):
        """Begin authentication process."""
        return True
    
    def password_auth_supported(self):
        """Enable password authentication."""
        return True
    
    def  public_key_auth_supported(self):
        """Disable public key authentication."""
        return False
    
    async def validate_password(self, username, password):
        """
        Always reject passwords but log the attempt.
        """
        # Check rate limit
        allowed, reason = await self.rate_limiter.check_rate_limit(self.client_ip)
        if not allowed:
            return False
        
        # Enrich IP information
        ip_info = await self.threat_intel.enrich_ip(self.client_ip)
        
        # Log the credential attempt
        event_data = {
            'service': 'ssh',
            'event_type': 'credential_attempt',
            'source_ip': self.client_ip,
            'username': username,
            'password': password,
            'session_id': self.session_id,
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            **ip_info
        }
        
        # Log to file and database
        await self.logger.log_event('ssh', 'credential_attempt', event_data)
        await self.db.log_attack(event_data)
        
        # Send alert for known threats
        if ip_info.get('is_known_threat'):
            await self.alerting.alert_attack_detected(event_data)
        
        # Always reject to keep them trying
        return False


class  SSHSessionHandler(asyncssh.SSHServerSession):
    """Handle SSH session and command execution."""
    
    def __init__(self, logger, db, session_id, client_ip):
        self.logger = logger
        self.db = db
        self.session_id = session_id
        self.client_ip = client_ip
        self._input = ''
        self.command_count = 0
    
    def connection_made(self, chan):
        """Called when session channel is created."""
        self._chan = chan
    
    def shell_requested(self):
        """Handle shell request."""
        return True
    
    def exec_requested(self, command):
        """Handle command execution."""
        asyncio.create_task(self._log_command(command))
        return True
    
    def data_received(self, data, datatype):
        """Handle data received from client."""
        self._input += data
        
        # Echo back (simulate real shell)
        self._chan.write(data)
        
        # Check for newline (command submitted)
        if '\r' in data or '\n' in data:
            command = self._input.strip()
            if command:
                asyncio.create_task(self._log_command(command))
                # Send fake response
                self._send_fake_response(command)
            self._input = ''
            self._chan.write('$ ')
    
    async def _log_command(self, command):
        """Log executed command."""
        self.command_count += 1
        
        event_data = {
            'service': 'ssh',
            'event_type': 'command_execution',
            'source_ip': self.client_ip,
            'command': command,
            'session_id': self.session_id,
            'timestamp': datetime.utcnow().isoformat(),
            'command_number': self.command_count
        }
        
        await self.logger.log_event('ssh', 'command_execution', event_data)
        await self.db.log_attack(event_data)
    
    def _send_fake_response(self, command):
        """Send fake command responses."""
        cmd_lower = command.lower().strip()
        
        responses = {
            'whoami': 'root\r\n',
            'pwd': '/root\r\n',
            'id': 'uid=0(root) gid=0(root) groups=0(root)\r\n',
            'uname -a': 'Linux honeypot 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux\r\n',
            'ls': 'Desktop  Documents  Downloads  Music  Pictures  Videos\r\n',
            'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n',
        }
        
        # Check for matching command
        for cmd_pattern, response in responses.items():
            if cmd_pattern in cmd_lower:
                self._chan.write(response)
                return
        
        # Default response
        if cmd_lower.startswith('cd '):
            return  # Just accept cd commands silently
        
        self._chan.write(f'bash: {command.split()[0] if command else "command"}: command not found\r\n')


class SSHHoneypot:
    """SSH Honeypot server."""
    
    def __init__(self, config: Dict[str, Any], logger, db, threat_intel, rate_limiter, alerting):
        self.config = config.get('ssh', {})
        self.enabled = self.config.get('enabled', True)
        self.port = self.config.get('port', 2222)
        self.host = self.config.get('host', '0.0.0.0')
        self.banner = self.config.get('banner', 'SSH-2.0-OpenSSH_8.2p1')
        
        self.logger = logger
        self.db = db
        self.threat_intel = threat_intel
        self.rate_limiter = rate_limiter
        self.alerting = alerting
        
        self.server = None
        self.sessions = {}
    
    async def start(self):
        """Start the SSH honeypot server."""
        if not self.enabled:
            print("[SSH] Honeypot disabled in configuration")
            return
        
        # Generate host key if it doesn't exist
        host_key_path = Path('/app/data/ssh_host_key')
        if not host_key_path.exists():
            host_key_path.parent.mkdir(parents=True, exist_ok=True)
            # Generate key
            key = asyncssh.generate_private_key('ssh-rsa')
            host_key_path.write_bytes(key.export_private_key())
        
        def server_factory():
            return SSHServer(
                self.logger,
                self.db,
                self.threat_intel,
                self.rate_limiter,
                self.alerting
            )
        
        try:
            self.server = await asyncssh.create_server(
                server_factory,
                self.host,
                self.port,
                server_host_keys=[str(host_key_path)],
                server_version=self.banner
            )
            
            print(f"[SSH] Honeypot running on {self.host}:{self.port}")
        except Exception as e:
            print(f"[SSH] Failed to start honeypot: {e}")
    
    async def stop(self):
        """Stop the SSH honeypot server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print("[SSH] Honeypot stopped")


async def run_ssh_honeypot(config, logger, db, threat_intel, rate_limiter, alerting):
    """Standalone function to run SSH honeypot."""
    honeypot = SSHHoneypot(config, logger, db, threat_intel, rate_limiter, alerting)
    await honeypot.start()
    
    try:
        # Keep running
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        await honeypot.stop()
