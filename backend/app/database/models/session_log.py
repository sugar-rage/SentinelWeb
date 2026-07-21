from sqlalchemy import Column,Integer,String,DateTime
from sqlalchemy.orm import relationship
from app.database.database import Base

class SessionLog(Base):
    __tablename__ = "session_logs"
    id=Column(Integer,primary_key=True,index=True)
    user_id=Column(Integer,nullable=False)
    ip_address=Column(String(45),nullable=False)
    session_start=Column(DateTime)
    session_end=Column(DateTime)
    session_status=Column(String(20))
    requests=relationship("RequestLog",back_populates="session",cascade="all, delete")