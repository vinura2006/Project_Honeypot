"""
Database models and operations for honeypot data storage.
Uses async SQLAlchemy for PostgreSQL interaction.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON, Index
from sqlalchemy import select, func, and_, or_
import asyncio

Base = declarative_base()


class AttackLog(Base):
    """Model for storing attack events."""
    __tablename__ = 'attack_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    service = Column(String(50), index=True)
    event_type = Column(String(100), index=True)
    source_ip = Column(String(45), index=True)  # IPv6 compatible
    source_port = Column(Integer)
    destination_port = Column(Integer)
    
    # Credential data
    username = Column(String(255))
    password = Column(String(255))
    
    # Command/payload data
    command = Column(Text)
    payload = Column(Text)
    payload_type = Column(String(50))
    
    # Geolocation
    country = Column(String(100))
    city = Column(String(100))
    latitude = Column(String(20))
    longitude = Column(String(20))
    
    # Threat intelligence
    threat_score = Column(Integer, default=0)
    is_known_threat = Column(Boolean, default=False)
    threat_tags = Column(JSON)
    
    # Session tracking
    session_id = Column(String(100))
    
    # Additional metadata
    metadata = Column(JSON)
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_timestamp_service', 'timestamp', 'service'),
        Index('idx_source_ip_timestamp', 'source_ip', 'timestamp'),
        Index('idx_event_type_timestamp', 'event_type', 'timestamp'),
    )


class Session(Base):
    """Model for tracking attacker sessions."""
    __tablename__ = 'sessions'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100), unique=True, index=True)
    service = Column(String(50))
    source_ip = Column(String(45), index=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    duration = Column(Integer)  # seconds
    
    # Session metadata
    commands_executed = Column(Integer, default=0)
    files_accessed = Column(Integer, default=0)
    authentication_attempts = Column(Integer, default=0)
    successful_auth = Column(Boolean, default=False)
    
    session_data = Column(JSON)


class BlockedIP(Base):
    """Model for tracking blocked IPs."""
    __tablename__ = 'blocked_ips'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), unique=True, index=True)
    blocked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    reason = Column(String(255))
    block_count = Column(Integer, default=1)
    is_permanent = Column(Boolean, default=False)


class DatabaseManager:
    """Async database operations manager."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        db_config = config.get('database', {})
        
        # Build connection string
        self.connection_string = (
            f"postgresql+asyncpg://{db_config.get('user')}:"
            f"{db_config.get('password')}@{db_config.get('host')}:"
            f"{db_config.get('port')}/{db_config.get('name')}"
        )
        
        self.engine = create_async_engine(
            self.connection_string,
            echo=False,
            pool_size=20,
            max_overflow=10
        )
        
        self.async_session = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
    
    async def init_db(self):
        """Initialize database tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    async def log_attack(self, event_data: Dict[str, Any]) -> int:
        """Store an attack event in the database."""
        async with self.async_session() as session:
            attack_log = AttackLog(
                timestamp=datetime.fromisoformat(event_data.get('timestamp', datetime.utcnow().isoformat())),
                service=event_data.get('service'),
                event_type=event_data.get('event_type'),
                source_ip=event_data.get('source_ip'),
                source_port=event_data.get('source_port'),
                destination_port=event_data.get('destination_port'),
                username=event_data.get('username'),
                password=event_data.get('password'),
                command=event_data.get('command'),
                payload=event_data.get('payload'),
                payload_type=event_data.get('payload_type'),
                country=event_data.get('country'),
                city=event_data.get('city'),
                latitude=event_data.get('latitude'),
                longitude=event_data.get('longitude'),
                threat_score=event_data.get('threat_score', 0),
                is_known_threat=event_data.get('is_known_threat', False),
                threat_tags=event_data.get('threat_tags'),
                session_id=event_data.get('session_id'),
                metadata=event_data.get('metadata')
            )
            
            session.add(attack_log)
            await session.commit()
            return attack_log.id
    
    async def get_recent_attacks(self, limit: int = 100, service: str = None) -> List[Dict]:
        """Get recent attacks with optional service filter."""
        async with self.async_session() as session:
            query = select(AttackLog).order_by(AttackLog.timestamp.desc()).limit(limit)
            
            if service:
                query = query.where(AttackLog.service == service)
            
            result = await session.execute(query)
            attacks = result.scalars().all()
            
            return [self._attack_to_dict(attack) for attack in attacks]
    
    async def get_attack_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get attack statistics for the specified time period."""
        async with self.async_session() as session:
            since = datetime.utcnow() - datetime.timedelta(hours=hours)
            
            # Total attacks
            total_query = select(func.count(AttackLog.id)).where(AttackLog.timestamp >= since)
            total_result = await session.execute(total_query)
            total_attacks = total_result.scalar()
            
            # Attacks by service
            service_query = select(
                AttackLog.service,
                func.count(AttackLog.id).label('count')
            ).where(AttackLog.timestamp >= since).group_by(AttackLog.service)
            service_result = await session.execute(service_query)
            by_service = {row[0]: row[1] for row in service_result}
            
            # Top attacking IPs
            ip_query = select(
                AttackLog.source_ip,
                func.count(AttackLog.id).label('count')
            ).where(AttackLog.timestamp >= since).group_by(
                AttackLog.source_ip
            ).order_by(func.count(AttackLog.id).desc()).limit(10)
            ip_result = await session.execute(ip_query)
            top_ips = [{'ip': row[0], 'count': row[1]} for row in ip_result]
            
            # Top countries
            country_query = select(
                AttackLog.country,
                func.count(AttackLog.id).label('count')
            ).where(
                and_(AttackLog.timestamp >= since, AttackLog.country.isnot(None))
            ).group_by(AttackLog.country).order_by(func.count(AttackLog.id).desc()).limit(10)
            country_result = await session.execute(country_query)
            top_countries = [{'country': row[0], 'count': row[1]} for row in country_result]
            
            return {
                'total_attacks': total_attacks,
                'by_service': by_service,
                'top_ips': top_ips,
                'top_countries': top_countries,
                'time_period_hours': hours
            }
    
    async def block_ip(self, ip_address: str, reason: str, duration: int = 3600, permanent: bool = False):
        """Add an IP to the blocked list."""
        async with self.async_session() as session:
            # Check if already blocked
            result = await session.execute(
                select(BlockedIP).where(BlockedIP.ip_address == ip_address)
            )
            existing = result.scalar_one_or_none()
            
            if existing:
                existing.block_count += 1
                existing.blocked_at = datetime.utcnow()
                if not permanent:
                    existing.expires_at = datetime.utcnow() + datetime.timedelta(seconds=duration)
            else:
                blocked_ip = BlockedIP(
                    ip_address=ip_address,
                    reason=reason,
                    is_permanent=permanent,
                    expires_at=None if permanent else datetime.utcnow() + datetime.timedelta(seconds=duration)
                )
                session.add(blocked_ip)
            
            await session.commit()
    
    async def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if an IP is currently blocked."""
        async with self.async_session() as session:
            result = await session.execute(
                select(BlockedIP).where(
                    and_(
                        BlockedIP.ip_address == ip_address,
                        or_(
                            BlockedIP.is_permanent == True,
                            BlockedIP.expires_at > datetime.utcnow()
                        )
                    )
                )
            )
            return result.scalar_one_or_none() is not None
    
    def _attack_to_dict(self, attack: AttackLog) -> Dict:
        """Convert AttackLog model to dictionary."""
        return {
            'id': attack.id,
            'timestamp': attack.timestamp.isoformat() if attack.timestamp else None,
            'service': attack.service,
            'event_type': attack.event_type,
            'source_ip': attack.source_ip,
            'source_port': attack.source_port,
            'destination_port': attack.destination_port,
            'username': attack.username,
            'password': attack.password,
            'command': attack.command,
            'payload': attack.payload,
            'payload_type': attack.payload_type,
            'country': attack.country,
            'city': attack.city,
            'latitude': attack.latitude,
            'longitude': attack.longitude,
            'threat_score': attack.threat_score,
            'is_known_threat': attack.is_known_threat,
            'threat_tags': attack.threat_tags,
            'session_id': attack.session_id,
            'metadata': attack.metadata
        }


# Global database instance
_db_instance: Optional[DatabaseManager] = None


def initialize_database(config: Dict[str, Any]) -> DatabaseManager:
    """Initialize the global database instance."""
    global _db_instance
    _db_instance = DatabaseManager(config)
    return _db_instance


def get_database_instance() -> DatabaseManager:
    """Get the global database instance."""
    if _db_instance is None:
        raise RuntimeError("Database not initialized. Call initialize_database first.")
    return _db_instance
