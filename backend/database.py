from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

SQLALCHEMY_DATABASE_URL = "sqlite:///./fuzzer.db"
# check_same_thread=False is needed for SQLite when used with FastAPI
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), index=True)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="target")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    profile_type = Column(String)
    total_findings = Column(Integer, default=0)
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    vuln_type = Column(String(100))
    severity = Column(String(20)) # Critical, High, Moderate, Low
    score = Column(Float) # CVSS Score
    payload = Column(Text)
    payload_hash = Column(String(64))
    raw_request = Column(Text)
    raw_response = Column(Text)

    scan = relationship("Scan", back_populates="findings")

class Payload(Base):
    __tablename__ = "payloads"

    id = Column(Integer, primary_key=True, index=True)
    data_type = Column(String(50)) # 'Integer', 'String', 'Path', 'JSON', 'XML', 'Boolean'
    payload_text = Column(Text)
    attack_vector = Column(String(50)) # 'SQLi', 'XSS', 'LFI', 'Command Injection'
    risk_level = Column(String(20)) # 'High', 'Medium', 'Low'
