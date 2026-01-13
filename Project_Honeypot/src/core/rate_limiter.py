"""
Rate limiting module to prevent resource exhaustion.
Uses token bucket algorithm for connection throttling.
"""

import asyncio
from typing import Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict
import time


class RateLimiter:
    """Token bucket rate limiter for connection management."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('rate_limiting', {})
        self.enabled = self.config.get('enabled', True)
        self.max_connections = self.config.get('max_connections_per_ip', 10)
        self.time_window = self.config.get('time_window', 60)  # seconds
        self.auto_block_threshold = self.config.get('auto_block_threshold', 50)
        self.block_duration = self.config.get('block_duration', 3600)
        
        # Track connections per IP
        self.connection_counts = defaultdict(list)
        self.total_attempts = defaultdict(int)
        self.blocked_ips = {}
        
        # Cleanup task
        self.cleanup_task = None
    
    async def check_rate_limit(self, ip_address: str) -> tuple[bool, str]:
        """
        Check if an IP address is within rate limits.
        Returns (allowed, reason)
        """
        if not self.enabled:
            return True, "rate_limiting_disabled"
        
        # Check if IP is blocked
        if ip_address in self.blocked_ips:
            block_expiry = self.blocked_ips[ip_address]
            if datetime.utcnow() < block_expiry:
                return False, "ip_blocked"
            else:
                # Block expired
                del self.blocked_ips[ip_address]
        
        # Get current time
        now = time.time()
        
        # Clean old connection timestamps
        self.connection_counts[ip_address] = [
            ts for ts in self.connection_counts[ip_address]
            if now - ts < self.time_window
        ]
        
        # Check connection count
        current_connections = len(self.connection_counts[ip_address])
        
        if current_connections >= self.max_connections:
            # Increment total attempts for auto-blocking
            self.total_attempts[ip_address] += 1
            
            # Check if should auto-block
            if self.total_attempts[ip_address] >= self.auto_block_threshold:
                await self.block_ip(ip_address, "auto_block_threshold_exceeded")
                return False, "auto_blocked"
            
            return False, "rate_limit_exceeded"
        
        # Allow connection and record timestamp
        self.connection_counts[ip_address].append(now)
        return True, "allowed"
    
    async def block_ip(self, ip_address: str, reason: str = "manual"):
        """Block an IP address for the configured duration."""
        expiry = datetime.utcnow() + timedelta(seconds=self.block_duration)
        self.blocked_ips[ip_address] = expiry
        print(f"[RateLimiter] Blocked IP {ip_address} until {expiry} (reason: {reason})")
    
    async def unblock_ip(self, ip_address: str):
        """Manually unblock an IP address."""
        if ip_address in self.blocked_ips:
            del self.blocked_ips[ip_address]
            print(f"[RateLimiter] Unblocked IP {ip_address}")
    
    def is_blocked(self, ip_address: str) -> bool:
        """Check if an IP is currently blocked."""
        if ip_address not in self.blocked_ips:
            return False
        
        if datetime.utcnow() >= self.blocked_ips[ip_address]:
            del self.blocked_ips[ip_address]
            return False
        
        return True
    
    async def cleanup_old_data(self):
        """Periodically clean up old tracking data."""
        while True:
            await asyncio.sleep(300)  # Run every 5 minutes
            
            now = time.time()
            
            # Clean old connection timestamps
            for ip in list(self.connection_counts.keys()):
                self.connection_counts[ip] = [
                    ts for ts in self.connection_counts[ip]
                    if now - ts < self.time_window
                ]
                
                if not self.connection_counts[ip]:
                    del self.connection_counts[ip]
            
            # Clean expired blocks
            for ip in list(self.blocked_ips.keys()):
                if datetime.utcnow() >= self.blocked_ips[ip]:
                    del self.blocked_ips[ip]
    
    async def start(self):
        """Start the rate limiter cleanup task."""
        if self.cleanup_task is None:
            self.cleanup_task = asyncio.create_task(self.cleanup_old_data())
    
    async def stop(self):
        """Stop the rate limiter cleanup task."""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current rate limiter statistics."""
        return {
            'total_tracked_ips': len(self.connection_counts),
            'blocked_ips': len(self.blocked_ips),
            'enabled': self.enabled,
            'max_connections_per_ip': self.max_connections,
            'time_window': self.time_window
        }


# Global rate limiter instance
_rate_limiter_instance = None


def initialize_rate_limiter(config: Dict[str, Any]) -> RateLimiter:
    """Initialize the global rate limiter instance."""
    global _rate_limiter_instance
    _rate_limiter_instance = RateLimiter(config)
    return _rate_limiter_instance


def get_rate_limiter_instance() -> RateLimiter:
    """Get the global rate limiter instance."""
    if _rate_limiter_instance is None:
        raise RuntimeError("Rate limiter not initialized.")
    return _rate_limiter_instance
