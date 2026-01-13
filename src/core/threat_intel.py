"""
Threat intelligence integration for IP geolocation and reputation lookups.
"""

import asyncio
import aiohttp
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import geoip2.database
import geoip2.errors
from pathlib import Path
import hashlib


class ThreatIntelligence:
    """Threat intelligence and IP enrichment service."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.threat_config = config.get('threat_intel', {})
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        # Initialize GeoIP
        self.geoip_enabled = self.threat_config.get('geoip', {}).get('enabled', True)
        self.geoip_reader = None
        if self.geoip_enabled:
            db_path = self.threat_config.get('geoip', {}).get('db_path')
            if db_path and Path(db_path).exists():
                try:
                    self.geoip_reader = geoip2.database.Reader(db_path)
                except Exception as e:
                    print(f"Failed to initialize GeoIP: {e}")
                    self.geoip_enabled = False
        
        # API keys
        self.virustotal_api_key = self.threat_config.get('virustotal', {}).get('api_key')
        self.virustotal_enabled = self.threat_config.get('virustotal', {}).get('enabled', False)
        
        self.abuseipdb_api_key = self.threat_config.get('abuseipdb', {}).get('api_key')
        self.abuseipdb_enabled = self.threat_config.get('abuseipdb', {}).get('enabled', False)
        self.abuseipdb_threshold = self.threat_config.get('abuseipdb', {}).get('report_threshold', 75)
    
    async def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Enrich IP address with geolocation and threat intelligence.
        Returns a dictionary with all available information.
        """
        # Check cache
        cache_key = f"ip_{ip_address}"
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if datetime.utcnow() - cached_time < timedelta(seconds=self.cache_ttl):
                return cached_data
        
        enriched_data = {
            'ip_address': ip_address,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Get geolocation
        geo_data = await self._get_geolocation(ip_address)
        enriched_data.update(geo_data)
        
        # Get threat intelligence
        threat_data = await self._get_threat_intelligence(ip_address)
        enriched_data.update(threat_data)
        
        # Calculate overall threat score
        enriched_data['threat_score'] = self._calculate_threat_score(enriched_data)
        
        # Cache the result
        self.cache[cache_key] = (enriched_data, datetime.utcnow())
        
        return enriched_data
    
    async def _get_geolocation(self, ip_address: str) -> Dict[str, Any]:
        """Get geolocation data for an IP address."""
        if not self.geoip_enabled or not self.geoip_reader:
            return {
                'country': None,
                'city': None,
                'latitude': None,
                'longitude': None,
                'isp': None
            }
        
        try:
            response = self.geoip_reader.city(ip_address)
            return {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': str(response.location.latitude) if response.location.latitude else None,
                'longitude': str(response.location.longitude) if response.location.longitude else None,
                'postal_code': response.postal.code,
                'timezone': response.location.time_zone
            }
        except geoip2.errors.AddressNotFoundError:
            return {
                'country': 'Unknown',
                'city': 'Unknown',
                'latitude': None,
                'longitude': None
            }
        except Exception as e:
            print(f"GeoIP lookup error: {e}")
            return {}
    
    async def _get_threat_intelligence(self, ip_address: str) -> Dict[str, Any]:
        """Get threat intelligence from various sources."""
        threat_data = {
            'is_known_threat': False,
            'threat_tags': [],
            'virustotal_score': None,
            'abuseipdb_score': None
        }
        
        # VirusTotal lookup
        if self.virustotal_enabled and self.virustotal_api_key:
            vt_data = await self._virustotal_lookup(ip_address)
            if vt_data:
                threat_data['virustotal_score'] = vt_data.get('malicious_score', 0)
                if vt_data.get('malicious_score', 0) > 0:
                    threat_data['is_known_threat'] = True
                    threat_data['threat_tags'].extend(vt_data.get('tags', []))
        
        # AbuseIPDB lookup
        if self.abuseipdb_enabled and self.abuseipdb_api_key:
            abuse_data = await self._abuseipdb_lookup(ip_address)
            if abuse_data:
                threat_data['abuseipdb_score'] = abuse_data.get('abuse_confidence_score', 0)
                if abuse_data.get('abuse_confidence_score', 0) >= self.abuseipdb_threshold:
                    threat_data['is_known_threat'] = True
                    threat_data['threat_tags'].extend(abuse_data.get('usage_type', []))
        
        return threat_data
    
    async def _virustotal_lookup(self, ip_address: str) -> Optional[Dict]:
        """Lookup IP reputation on VirusTotal."""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            'x-apikey': self.virustotal_api_key
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        return {
                            'malicious_score': stats.get('malicious', 0),
                            'suspicious_score': stats.get('suspicious', 0),
                            'tags': data.get('data', {}).get('attributes', {}).get('tags', [])
                        }
        except Exception as e:
            print(f"VirusTotal API error: {e}")
        
        return None
    
    async def _abuseipdb_lookup(self, ip_address: str) -> Optional[Dict]:
        """Lookup IP reputation on AbuseIPDB."""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': self.abuseipdb_api_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'abuse_confidence_score': data.get('data', {}).get('abuseConfidenceScore', 0),
                            'total_reports': data.get('data', {}).get('totalReports', 0),
                            'usage_type': [data.get('data', {}).get('usageType', 'Unknown')],
                            'country_code': data.get('data', {}).get('countryCode')
                        }
        except Exception as e:
            print(f"AbuseIPDB API error: {e}")
        
        return None
    
    def _calculate_threat_score(self, enriched_data: Dict) -> int:
        """Calculate overall threat score (0-100)."""
        score = 0
        
        # Base score from known threat
        if enriched_data.get('is_known_threat'):
            score += 50
        
        # VirusTotal contribution
        vt_score = enriched_data.get('virustotal_score', 0)
        if vt_score:
            score += min(vt_score * 5, 25)  # Max 25 points
        
        # AbuseIPDB contribution
        abuse_score = enriched_data.get('abuseipdb_score', 0)
        if abuse_score:
            score += min(abuse_score / 4, 25)  # Max 25 points
        
        return min(int(score), 100)
    
    def fingerprint_attacker(self, attack_data: Dict[str, Any]) -> str:
        """
        Generate a fingerprint for an attacker based on behavioral patterns.
        Returns a unique hash representing the attacker's characteristics.
        """
        fingerprint_data = [
            attack_data.get('source_ip', ''),
            attack_data.get('username', ''),
            attack_data.get('user_agent', ''),
            str(attack_data.get('attack_patterns', [])),
        ]
        
        fingerprint_string = '|'.join(fingerprint_data)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    def analyze_behavior(self, attacks: list) -> Dict[str, Any]:
        """
        Analyze attack patterns to identify behavior characteristics.
        """
        if not attacks:
            return {}
        
        # Group by IP
        ip_groups = {}
        for attack in attacks:
            ip = attack.get('source_ip')
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append(attack)
        
        behaviors = {}
        for ip, ip_attacks in ip_groups.items():
            behaviors[ip] = {
                'total_attempts': len(ip_attacks),
                'unique_services': len(set(a.get('service') for a in ip_attacks)),
                'credential_attempts': sum(1 for a in ip_attacks if a.get('username')),
                'payload_attempts': sum(1 for a in ip_attacks if a.get('payload')),
                'time_span': self._calculate_time_span(ip_attacks),
                'attack_rate': self._calculate_attack_rate(ip_attacks)
            }
        
        return behaviors
    
    def _calculate_time_span(self, attacks: list) -> float:
        """Calculate time span of attacks in seconds."""
        if len(attacks) < 2:
            return 0
        
        timestamps = [
            datetime.fromisoformat(a.get('timestamp'))
            for a in attacks if a.get('timestamp')
        ]
        
        if len(timestamps) < 2:
            return 0
        
        return (max(timestamps) - min(timestamps)).total_seconds()
    
    def _calculate_attack_rate(self, attacks: list) -> float:
        """Calculate attacks per minute."""
        time_span = self._calculate_time_span(attacks)
        if time_span == 0:
            return 0
        
        return (len(attacks) / time_span) * 60
    
    def __del__(self):
        """Cleanup GeoIP reader."""
        if self.geoip_reader:
            self.geoip_reader.close()


# Global threat intelligence instance
_threat_intel_instance: Optional[ThreatIntelligence] = None


def initialize_threat_intel(config: Dict[str, Any]) -> ThreatIntelligence:
    """Initialize the global threat intelligence instance."""
    global _threat_intel_instance
    _threat_intel_instance = ThreatIntelligence(config)
    return _threat_intel_instance


def get_threat_intel_instance() -> ThreatIntelligence:
    """Get the global threat intelligence instance."""
    if _threat_intel_instance is None:
        raise RuntimeError("Threat intelligence not initialized.")
    return _threat_intel_instance
