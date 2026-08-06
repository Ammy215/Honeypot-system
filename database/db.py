import sqlite3
import os
import logging
from pathlib import Path
from typing import Optional
import config

logger = logging.getLogger("honeypot.database")


class DatabaseConnection:
    """Thread-safe SQLite connection manager"""
    
    def __init__(self, db_path: str = config.DATABASE_PATH):
        self.db_path = db_path
        self._ensure_directory()
    
    def _ensure_directory(self):
        """Create data directory if it doesn't exist"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
    
    def get_connection(self) -> sqlite3.Connection:
        """Get a new database connection"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        return conn
    
    def execute_query(self, query: str, params: tuple = ()) -> list:
        """Execute a SELECT query and return results"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = cursor.fetchall()
            return results
        except Exception as e:
            logger.error(f"Query execution error: {e}")
            return []
        finally:
            conn.close()
    
    def execute_update(self, query: str, params: tuple = ()) -> int:
        """Execute an INSERT/UPDATE/DELETE query and return affected rows"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.lastrowid if cursor.lastrowid else cursor.rowcount
        except Exception as e:
            logger.error(f"Update execution error: {e}")
            conn.rollback()
            return 0
        finally:
            conn.close()
    
    def execute_many(self, query: str, params_list: list) -> int:
        """Execute multiple statements in a batch"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.executemany(query, params_list)
            conn.commit()
            return cursor.rowcount
        except Exception as e:
            logger.error(f"Batch execution error: {e}")
            conn.rollback()
            return 0
        finally:
            conn.close()


# Global database instance
db = DatabaseConnection()


def init_db():
    """Initialize database with schema"""
    logger.info("Initializing database...")
    
    # Read schema file
    schema_path = Path(__file__).parent / "schema.sql"
    with open(schema_path, 'r') as f:
        schema_sql = f.read()
    
    # Execute schema
    conn = db.get_connection()
    try:
        cursor = conn.cursor()
        cursor.executescript(schema_sql)
        conn.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise
    finally:
        conn.close()


def get_or_create_attacker(ip_address: str) -> int:
    """Get attacker_id or create new attacker record"""
    # Check if attacker exists
    query = "SELECT id FROM attackers WHERE ip_address = ?"
    results = db.execute_query(query, (ip_address,))
    
    if results:
        return results[0]['id']
    
    # Create new attacker
    query = """
        INSERT INTO attackers (ip_address, first_seen, last_seen, total_connections)
        VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0)
    """
    attacker_id = db.execute_update(query, (ip_address,))
    logger.info(f"New attacker registered: {ip_address} (ID: {attacker_id})")
    
    # Trigger auto-enrichment for new attacker (non-blocking)
    try:
        from honeypot.intelligence.enrichment import auto_enrich_new_attacker
        import threading
        
        # Run enrichment in background thread
        enrichment_thread = threading.Thread(
            target=auto_enrich_new_attacker,
            args=(ip_address,),
            daemon=True
        )
        enrichment_thread.start()
    except Exception as e:
        logger.debug(f"Auto-enrichment skipped for {ip_address}: {e}")
    
    return attacker_id


def log_connection(ip_address: str, source_port: int, destination_port: int, 
                   service_name: str, raw_data: str = None) -> int:
    """Log a connection attempt"""
    attacker_id = get_or_create_attacker(ip_address)
    
    query = """
        INSERT INTO connections 
        (attacker_id, ip_address, source_port, destination_port, service_name, raw_data)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    connection_id = db.execute_update(
        query, 
        (attacker_id, ip_address, source_port, destination_port, service_name, raw_data)
    )
    
    # Update attacker stats
    update_query = """
        UPDATE attackers 
        SET total_connections = total_connections + 1,
            last_seen = CURRENT_TIMESTAMP
        WHERE id = ?
    """
    db.execute_update(update_query, (attacker_id,))
    
    logger.info(f"Connection logged: {ip_address}:{source_port} -> {service_name}:{destination_port}")
    return connection_id


def update_service_stats(service_name: str, port: int):
    """Update service statistics"""
    # Check if service exists
    query = "SELECT id FROM service_stats WHERE service_name = ? AND port = ?"
    results = db.execute_query(query, (service_name, port))
    
    if results:
        # Update existing
        update_query = """
            UPDATE service_stats 
            SET total_connections = total_connections + 1,
                last_activity = CURRENT_TIMESTAMP
            WHERE service_name = ? AND port = ?
        """
        db.execute_update(update_query, (service_name, port))
    else:
        # Create new
        insert_query = """
            INSERT INTO service_stats 
            (service_name, port, total_connections, last_activity)
            VALUES (?, ?, 1, CURRENT_TIMESTAMP)
        """
        db.execute_update(insert_query, (service_name, port))
