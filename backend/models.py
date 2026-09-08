from sqlalchemy import Column, Integer, String, Text, ForeignKey
from database import Base


# --------------------------------------------------
# USER TABLE
# --------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(
        String,
        unique=True,
        index=True,
        nullable=False
    )

    password_hash = Column(
        String,
        nullable=False
    )


# --------------------------------------------------
# SECURITY SCAN REPORT TABLE
# --------------------------------------------------

class ScanReport(Base):
    __tablename__ = "scan_reports"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    # User who performed the scan
    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    # Domain that was scanned
    domain = Column(
        String,
        nullable=False,
        index=True
    )

    # HTTP status code
    status_code = Column(
        Integer,
        nullable=True
    )

    # HTTPS enabled or not
    https_enabled = Column(
        String,
        nullable=False
    )

    # Number of detected security protections
    protections_detected = Column(
        Integer,
        nullable=False
    )

    # Total protections checked
    protections_total = Column(
        Integer,
        nullable=False,
        default=5
    )

    # Security score
    security_score = Column(
        Integer,
        nullable=False
    )

    # Overall status: Good / Needs Improvement / Poor
    status = Column(
        String,
        nullable=False
    )

    # Store detailed scan information
    findings = Column(
        Text,
        nullable=True
    )