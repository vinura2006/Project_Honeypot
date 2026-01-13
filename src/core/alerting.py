"""
Alerting system for high-severity honeypot events.
Supports email, Slack, and webhook notifications.
"""

import asyncio
import aiohttp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List
from datetime import datetime, timedelta
from collections import defaultdict
import json


class AlertingSystem:
    """Multi-channel alert dispatch system."""
    
    # Alert severity levels
    SEVERITY_LOW = "low"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_HIGH = "high"
    SEVERITY_CRITICAL = "critical"
    
    SEVERITY_PRIORITY = {
        SEVERITY_LOW: 1,
        SEVERITY_MEDIUM: 2,
        SEVERITY_HIGH: 3,
        SEVERITY_CRITICAL: 4
    }
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('alerts', {})
        self.severity_threshold = self.config.get('severity_threshold', 'high')
        self.threshold_priority = self.SEVERITY_PRIORITY.get(self.severity_threshold, 3)
        
        # Email configuration
        self.email_config = self.config.get('email', {})
        self.email_enabled = self.email_config.get('enabled', False)
        
        # Slack configuration
        self.slack_config = self.config.get('slack', {})
        self.slack_enabled = self.slack_config.get('enabled', False)
        
        # Webhook configuration
        self.webhook_config = self.config.get('webhook', {})
        self.webhook_enabled = self.webhook_config.get('enabled', False)
        
        # Alert deduplication
        self.recent_alerts = defaultdict(list)
        self.dedup_window = 300  # 5 minutes
    
    async def send_alert(self, title: str, message: str, severity: str = SEVERITY_MEDIUM, 
                        metadata: Dict = None):
        """Send an alert through configured channels."""
        # Check severity threshold
        if self.SEVERITY_PRIORITY.get(severity, 0) < self.threshold_priority:
            return  # Below threshold, skip
        
        # Check for duplicate alerts
        if self._is_duplicate(title, message):
            return
        
        # Prepare alert data
        alert_data = {
            'title': title,
            'message': message,
            'severity': severity,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {}
        }
        
        # Send through all enabled channels
        tasks = []
        
        if self.email_enabled:
            tasks.append(self._send_email_alert(alert_data))
        
        if self.slack_enabled:
            tasks.append(self._send_slack_alert(alert_data))
        
        if self.webhook_enabled:
            tasks.append(self._send_webhook_alert(alert_data))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _send_email_alert(self, alert_data: Dict):
        """Send alert via email."""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{alert_data['severity'].upper()}] Honeypot Alert: {alert_data['title']}"
            msg['From'] = self.email_config.get('from')
            msg['To'] = ', '.join(self.email_config.get('to', []))
            
            # Create email body
            text = f"""
Honeypot Security Alert

Severity: {alert_data['severity'].upper()}
Time: {alert_data['timestamp']}
Title: {alert_data['title']}

Message:
{alert_data['message']}

Metadata:
{json.dumps(alert_data['metadata'], indent=2)}

---
This is an automated alert from the Honeypot Security System.
"""
            
            html = f"""
<html>
<head></head>
<body>
  <h2>🚨 Honeypot Security Alert</h2>
  <p><strong>Severity:</strong> <span style="color: {'red' if alert_data['severity'] == 'critical' else 'orange'};">{alert_data['severity'].upper()}</span></p>
  <p><strong>Time:</strong> {alert_data['timestamp']}</p>
  <p><strong>Title:</strong> {alert_data['title']}</p>
  <p><strong>Message:</strong></p>
  <pre>{alert_data['message']}</pre>
  <hr>
  <p><em>This is an automated alert from the Honeypot Security System.</em></p>
</body>
</html>
"""
            
            part1 = MIMEText(text, 'plain')
            part2 = MIMEText(html, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            await asyncio.get_event_loop().run_in_executor(
                None,
                self._smtp_send,
                msg
            )
            
        except Exception as e:
            print(f"Failed to send email alert: {e}")
    
    def _smtp_send(self, msg):
        """Send email using SMTP (blocking operation)."""
        smtp_host = self.email_config.get('smtp_host')
        smtp_port = self.email_config.get('smtp_port', 587)
        username = self.email_config.get('username')
        password = self.email_config.get('password')
        
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
    
    async def _send_slack_alert(self, alert_data: Dict):
        """Send alert via Slack webhook."""
        try:
            webhook_url = self.slack_config.get('webhook_url')
            
            # Color code by severity
            color_map = {
                self.SEVERITY_LOW: '#36a64f',
                self.SEVERITY_MEDIUM: '#ff9900',
                self.SEVERITY_HIGH: '#ff6600',
                self.SEVERITY_CRITICAL: '#ff0000'
            }
            
            payload = {
                "attachments": [{
                    "color": color_map.get(alert_data['severity'], '#808080'),
                    "title": f"🚨 {alert_data['title']}",
                    "text": alert_data['message'],
                    "fields": [
                        {
                            "title": "Severity",
                            "value": alert_data['severity'].upper(),
                            "short": True
                        },
                        {
                            "title": "Time",
                            "value": alert_data['timestamp'],
                            "short": True
                        }
                    ],
                    "footer": "Honeypot Security System",
                    "ts": int(datetime.utcnow().timestamp())
                }]
            }
            
            # Add metadata fields
            if alert_data['metadata']:
                for key, value in list(alert_data['metadata'].items())[:5]:  # Limit to 5
                    payload["attachments"][0]["fields"].append({
                        "title": key.replace('_', ' ').title(),
                        "value": str(value),
                        "short": True
                    })
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status != 200:
                        print(f"Slack webhook returned status {response.status}")
        
        except Exception as e:
            print(f"Failed to send Slack alert: {e}")
    
    async def _send_webhook_alert(self, alert_data: Dict):
        """Send alert via custom webhook."""
        try:
            webhook_url = self.webhook_config.get('url')
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=alert_data) as response:
                    if response.status not in [200, 201, 202]:
                        print(f"Webhook returned status {response.status}")
        
        except Exception as e:
            print(f"Failed to send webhook alert: {e}")
    
    def _is_duplicate(self, title: str, message: str) -> bool:
        """Check if this alert was recently sent (deduplication)."""
        now = datetime.utcnow()
        alert_key = f"{title}:{message[:100]}"
        
        # Clean old alerts
        self.recent_alerts[alert_key] = [
            ts for ts in self.recent_alerts[alert_key]
            if (now - ts).total_seconds() < self.dedup_window
        ]
        
        # Check if duplicate
        if self.recent_alerts[alert_key]:
            return True
        
        # Record this alert
        self.recent_alerts[alert_key].append(now)
        return False
    
    async def alert_attack_detected(self, attack_data: Dict):
        """Convenience method for attack alerts."""
        title = f"Attack Detected from {attack_data.get('source_ip')}"
        message = f"Service: {attack_data.get('service')}\n"
        message += f"Type: {attack_data.get('event_type')}\n"
        
        if attack_data.get('username'):
            message += f"Username: {attack_data.get('username')}\n"
        
        if attack_data.get('country'):
            message += f"Location: {attack_data.get('city')}, {attack_data.get('country')}\n"
        
        severity = self.SEVERITY_MEDIUM
        if attack_data.get('is_known_threat'):
            severity = self.SEVERITY_HIGH
        if attack_data.get('threat_score', 0) >= 75:
            severity = self.SEVERITY_CRITICAL
        
        await self.send_alert(title, message, severity, attack_data)
    
    async def alert_mass_attack(self, ip_address: str, attack_count: int):
        """Alert for mass attack from single IP."""
        title = f"Mass Attack Detected"
        message = f"IP {ip_address} has made {attack_count} attack attempts"
        
        await self.send_alert(title, message, self.SEVERITY_HIGH, {
            'ip_address': ip_address,
            'attack_count': attack_count
        })


# Global alerting instance
_alerting_instance = None


def initialize_alerting(config: Dict[str, Any]) -> AlertingSystem:
    """Initialize the global alerting system instance."""
    global _alerting_instance
    _alerting_instance = AlertingSystem(config)
    return _alerting_instance


def get_alerting_instance() -> AlertingSystem:
    """Get the global alerting system instance."""
    if _alerting_instance is None:
        raise RuntimeError("Alerting system not initialized.")
    return _alerting_instance
