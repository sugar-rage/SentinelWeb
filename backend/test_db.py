from app.database.database import engine
import sys

try:
    connection = engine.connect()
    print("Connected to PostgreSQL successfully!")
    connection.close()
    sys.exit(0)
except Exception as e:
    print("Connection failed!")
    print(e)
    sys.exit(1)
