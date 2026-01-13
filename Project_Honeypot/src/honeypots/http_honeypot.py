"""
HTTP/HTTPS Honeypot with vulnerable endpoints.
Simulates common web vulnerabilities to attract attackers.
"""

import asyncio
from aiohttp import web
import ssl
from datetime import datetime
from typing import Dict, Any
import uuid
import json


class HTTPHoneypot:
    """HTTP/HTTPS honeypot server with vulnerable endpoints."""
    
    def __init__(self, config: Dict[str, Any], logger, db, threat_intel, rate_limiter, alerting):
        self.config = config.get('http', {})
        self.enabled = self.config.get('enabled', True)
        self.port = self.config.get('port', 8080)
        self.ssl_port = self.config.get('ssl_port', 8443)
        self.host = self.config.get('host', '0.0.0.0')
        self.server_header = self.config.get('server_header', 'Apache/2.4.41')
        
        self.logger = logger
        self.db = db
        self.threat_intel = threat_intel
        self.rate_limiter = rate_limiter
        self.alerting = alerting
        
        self.app = None
        self.runner = None
    
    async def start(self):
        """Start the HTTP honeypot server."""
        if not self.enabled:
            print("[HTTP] Honeypot disabled in configuration")
            return
        
        self.app = web.Application(middlewares=[self._middleware])
        
        # Register routes
        self.app.router.add_route('*', '/admin', self.admin_endpoint)
        self.app.router.add_route('*', '/admin/login', self.admin_login)
        self.app.router.add_route('*', '/phpmyadmin', self.phpmyadmin)
        self.app.router.add_route('*', '/phpmyadmin/index.php', self.phpmyadmin)
        self.app.router.add_route('*', '/api/v1/users', self.api_users)
        self.app.router.add_route('*', '/api/v1/auth', self.api_auth)
        self.app.router.add_route('*', '/.git/config', self.git_config)
        self.app.router.add_route('*', '/.env', self.env_file)
        self.app.router.add_route('*', '/wp-admin', self.wordpress_admin)
        self.app.router.add_route('*', '/wp-login.php', self.wordpress_login)
        self.app.router.add_route('*', '/{path:.*}', self.catch_all)
        
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        
        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()
        
        print(f"[HTTP] Honeypot running on {self.host}:{self.port}")
    
    @web.middleware
    async def _middleware(self, request, handler):
        """Middleware to log all requests."""
        client_ip = request.remote
        
        # Check rate limit
        allowed, reason = await self.rate_limiter.check_rate_limit(client_ip)
        if not allowed:
            return web.Response(status=429, text="Too Many Requests")
        
        # Get request data
        try:
            body = await request.text()
        except:
            body = ""
        
        # Enrich IP
        ip_info = await self.threat_intel.enrich_ip(client_ip)
        
        # Log request
        event_data = {
            'service': 'http',
            'event_type': 'http_request',
            'source_ip': client_ip,
            'method': request.method,
            'path': request.path,
            'query_string': request.query_string,
            'headers': dict(request.headers),
            'payload': body[:1000]  # Limit size
,
            'timestamp': datetime.utcnow().isoformat(),
            **ip_info
        }
        
        await self.logger.log_event('http', 'http_request', event_data)
        await self.db.log_attack(event_data)
        
        # Detect potential exploits
        if self._is_exploit_attempt(request, body):
            event_data['event_type'] = 'exploit_attempt'
            event_data['payload_type'] = self._detect_exploit_type(request, body)
            await self.logger.log_event('http', 'exploit_attempt', event_data)
            await self.db.log_attack(event_data)
            await self.alerting.alert_attack_detected(event_data)
        
        # Add custom server header
        response = await handler(request)
        response.headers['Server'] = self.server_header
        return response
    
    def _is_exploit_attempt(self, request, body: str) -> bool:
        """Detect common exploit patterns."""
        exploit_patterns = [
            'union select', 'or 1=1', "' or '1'='1",
            '<script>', 'javascript:', 'onerror=',
            '../', '..\\', '/etc/passwd', 'cmd.exe',
            'wget ', 'curl ', 'bash -i',
        ]
        
        full_text = f"{request.path} {request.query_string} {body}".lower()
        return any(pattern in full_text for pattern in exploit_patterns)
    
    def _detect_exploit_type(self, request, body: str) -> str:
        """Identify exploit type."""
        full_text = f"{request.path} {request.query_string} {body}".lower()
        
        if 'union select' in full_text or "' or '" in full_text:
            return 'sql_injection'
        if '<script>' in full_text or 'javascript:' in full_text:
            return 'xss'
        if '../' in full_text or '..\\' in full_text:
            return 'path_traversal'
        if 'wget' in full_text or 'curl' in full_text:
            return 'command_injection'
        
        return 'unknown'
    
    async def admin_endpoint(self, request):
        """Fake admin panel."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Admin Panel</title></head>
        <body>
            <h1>Administrator Login</h1>
            <form method="POST" action="/admin/login">
                <input type="text" name="username" placeholder="Username"><br>
                <input type="password" name="password" placeholder="Password"><br>
                <input type="submit" value="Login">
            </form>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')
    
    async def admin_login(self, request):
        """Handle admin login attempts."""
        if request.method == 'POST':
            data = await request.post()
            username = data.get('username', '')
            password = data.get('password', '')
            
            # Log credentials
            event_data = {
                'service': 'http',
                'event_type': 'credential_attempt',
                'source_ip': request.remote,
                'username': username,
                'password': password,
                'endpoint': '/admin/login',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            await self.logger.log_event('http', 'credential_attempt', event_data)
            await self.db.log_attack(event_data)
            
            return web.Response(text="<html><body><h1>Invalid credentials</h1></body></html>", 
                              content_type='text/html', status=401)
        
        return await self.admin_endpoint(request)
    
    async def phpmyadmin(self, request):
        """Fake phpMyAdmin."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>phpMyAdmin</title></head>
        <body>
            <h1>phpMyAdmin 4.9.5</h1>
            <form method="POST">
                <input type="text" name="pma_username" placeholder="Username"><br>
                <input type="password" name="pma_password" placeholder="Password"><br>
                <select name="server"><option value="1">localhost</option></select><br>
                <input type="submit" value="Go">
            </form>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')
    
    async def api_users(self, request):
        """Fake API endpoint for users."""
        fake_users = [
            {"id": 1, "username": "admin", "email": "admin@example.com"},
            {"id": 2, "username": "user", "email": "user@example.com"}
        ]
        return web.json_response(fake_users)
    
    async def api_auth(self, request):
        """Fake API authentication."""
        if request.method == 'POST':
            try:
                data = await request.json()
                username = data.get('username', '')
                password = data.get('password', '')
                
                # Log attempt
                event_data = {
                    'service': 'http',
                    'event_type': 'api_auth_attempt',
                    'source_ip': request.remote,
                    'username': username,
                    'endpoint': '/api/v1/auth',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                await self.logger.log_event('http', 'api_auth_attempt', event_data)
                await self.db.log_attack(event_data)
            except:
                pass
            
            return web.json_response({'error': 'Invalid credentials'}, status=401)
        
        return web.json_response({'error': 'Method not allowed'}, status=405)
    
    async def git_config(self, request):
        """Fake exposed .git/config."""
        config = """[core]
\trepositoryformatversion = 0
\tfilemode = true
[remote "origin"]
\turl = https://github.com/company/secretproject.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
"""
        return web.Response(text=config, content_type='text/plain')
    
    async def env_file(self, request):
        """Fake exposed .env file."""
        env = """APP_KEY=base64:fake_key_here
DB_HOST=localhost
DB_DATABASE=production
DB_USERNAME=admin
DB_PASSWORD=fake_password_123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
        return web.Response(text=env, content_type='text/plain')
    
    async def wordpress_admin(self, request):
        """Fake WordPress admin."""
        return web.Response(text="<html><body><h1>WordPress Login</h1></body></html>", 
                          content_type='text/html')
    
    async def wordpress_login(self, request):
        """Fake WordPress login."""
        return await self.wordpress_admin(request)
    
    async def catch_all(self, request):
        """Catch all other requests."""
        return web.Response(text="404 Not Found", status=404)
    
    async def stop(self):
        """Stop the HTTP honeypot."""
        if self.runner:
            await self.runner.cleanup()
            print("[HTTP] Honeypot stopped")


async def run_http_honeypot(config, logger, db, threat_intel, rate_limiter, alerting):
    """Standalone function to run HTTP honeypot."""
    honeypot = HTTPHoneypot(config, logger, db, threat_intel, rate_limiter, alerting)
    await honeypot.start()
    
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        await honeypot.stop()
