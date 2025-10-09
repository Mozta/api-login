import psycopg2

NAME_DB = "example2"
USER_DB = "postgres"
PASSWORD_DB = "admin"
HOST_DB = "localhost"
PORT_DB = "5432"

conn = psycopg2.connect(
    f"dbname={NAME_DB} user={USER_DB} password={PASSWORD_DB} host={HOST_DB} port={PORT_DB}"
)
cursor = conn.cursor()

# Example function to create a table
def create_table():
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL
    );
    """)
    conn.commit()
    cursor.close()
    conn.close()

print("Connected to the database successfully.")

create_table()