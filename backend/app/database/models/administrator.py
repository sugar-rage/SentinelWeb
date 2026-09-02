from sqlalchemy import CheckConstraint, Column, Integer, String
from sqlalchemy.orm import relationship
from app.database.database import Base


class Administrator(Base):
    __tablename__ = "administrators"
    __table_args__ = (
        CheckConstraint(
            "role IN ('user', 'admin', 'security_analyst', 'developer')",
            name="ck_administrators_role",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user", index=True)
    sessions = relationship("SessionLog", back_populates="user", passive_deletes=True)
    security_events = relationship("SecurityAuditLog", back_populates="user", passive_deletes=True)
