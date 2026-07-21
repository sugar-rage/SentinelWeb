"""
Create all database tables defined in the ORM models.

Run once:  python create_tables.py
"""

from app.database.database import Base, engine

# Import all models so Base.metadata discovers every table
from app.database.models import Administrator, SessionLog, RequestLog, AttackLog

Base.metadata.create_all(bind=engine)

print("Tables created successfully!")
print("Tables:", list(Base.metadata.tables.keys()))