from app.database.database import engine

try:
    connection = engine.connect()
    print("Connected to PostgreSQL successfully!")
    connection.close()
except Exception as e:
    print("Connection failed!")
    print(e)