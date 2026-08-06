"""
Production Database Manager - Enhanced with connection pooling and security
"""

import sqlite3
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from threading import Lock
import config

logger = logging.getLogger("honeypot.database.production")


class ConnectionPool:
    """Thread-safe connection pool for SQLite"""
    
    def __init__(self, db_path: str, pool_size: int = 5):
        self.db_path = db_path
        self.pool_size = pool_size
        self.connections = []
        self.lock = Lock()
        self.logger = logger
        
        # Enable WAL mode for better concurrent access
        self._enable_wal_mode()
    
    def _enable_wal_mode(self):
        """Enable Write-Ahead Logging for better concurrency"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA cache_size=10000')
            conn.execute('PRAGMA temp_store=MEMORY')
            conn.close()
            self.logger.info("WAL mode enabled for better performance")
        except Exception as e:
            self.logger.error(f"Error enabling WAL mode: {e}")
    
    @contextmanager
    def get_connection(self):
        """Get connection from pool (context manager)"""
        conn = None
        
        with self.lock:
            if self.connections:
                conn = self.connections.pop()
            else:
                conn = self._create_connection()
        
        try:
            yield conn
        finally:
            with self.lock:
                if len(self.connections) < self.pool_size:
                    self.connections.append(conn)
                else:
                    conn.close()
    
    def _create_connection(self) -> sqlite3.Connection:
        """Create new database connection"""
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=30.0
        )
        conn.row_factory = sqlite3.Row
        
        # Enable foreign keys
        conn.execute('PRAGMA foreign_keys=ON')
        
        return conn
    
    def close_all(self):
        """Close all connections in pool"""
        with self.lock:
            for conn in self.connections:
                try:
                    conn.close()
                except:
                    pass
            self.connections.clear()


class ProductionDatabaseManager:
    """Production-grade database manager with enhanced security"""
    
    def __init__(self, db_path: str = config.DATABASE_PATH, pool_size: int = 5):
        self.db_path = db_path
        self.logger = logger
        
        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Create connection pool
        self.pool = ConnectionPool(db_path, pool_size)
        
        # Query statistics
        self.query_count = 0
        self.error_count = 0
    
    def execute_query(self, query: str, params: tuple = (), 
                     timeout: float = 30.0) -> List[sqlite3.Row]:
        """
        Execute SELECT query with validation and timeout
        
        Args:
            query: SQL query string
            params: Query parameters (use ? placeholders)
            timeout: Query timeout in seconds
        
        Returns:
            List of result rows
        """
        self.query_count += 1
        
        # Validate query (prevent dangerous operations in SELECT)
        if not self._validate_select_query(query):
            self.logger.error(f"Invalid SELECT query blocked: {query[:100]}")
            self.error_count += 1
            return []
        
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                results = cursor.fetchall()
                return results
                
        except sqlite3.OperationalError as e:
            self.logger.error(f"Query timeout or lock: {e}")
            self.error_count += 1
            return []
            
        except Exception as e:
            self.logger.error(f"Query execution error: {e}")
            self.logger.debug(f"Query: {query[:200]}")
            self.error_count += 1
            return []
    
    def execute_update(self, query: str, params: tuple = ()) -> int:
        """
        Execute INSERT/UPDATE/DELETE query safely
        
        Args:
            query: SQL query string
            params: Query parameters
        
        Returns:
            Last row ID or row count
        """
        self.query_count += 1
        
        # Validate query
        if not self._validate_write_query(query):
            self.logger.error(f"Invalid WRITE query blocked: {query[:100]}")
            self.error_count += 1
            return 0
        
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()
                
                result = cursor.lastrowid if cursor.lastrowid else cursor.rowcount
                return result
                
        except Exception as e:
            self.logger.error(f"Update execution error: {e}")
            self.logger.debug(f"Query: {query[:200]}")
            self.error_count += 1
            
            # Attempt rollback
            try:
                conn.rollback()
            except:
                pass
            
            return 0
    
    def execute_many(self, query: str, params_list: List[tuple]) -> int:
        """
        Execute batch statements safely
        
        Args:
            query: SQL query string
            params_list: List of parameter tuples
        
        Returns:
            Number of rows affected
        """
        self.query_count += 1
        
        if not params_list:
            return 0
        
        # Validate query
        if not self._validate_write_query(query):
            self.logger.error(f"Invalid BATCH query blocked: {query[:100]}")
            self.error_count += 1
            return 0
        
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.executemany(query, params_list)
                conn.commit()
                return cursor.rowcount
                
        except Exception as e:
            self.logger.error(f"Batch execution error: {e}")
            self.error_count += 1
            
            try:
                conn.rollback()
            except:
                pass
            
            return 0
    
    def execute_transaction(self, queries: List[tuple]) -> bool:
        """
        Execute multiple queries in a transaction
        
        Args:
            queries: List of (query, params) tuples
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()
                
                for query, params in queries:
                    cursor.execute(query, params)
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Transaction error: {e}")
            try:
                conn.rollback()
            except:
                pass
            return False
    
    def _validate_select_query(self, query: str) -> bool:
        """Validate SELECT query for safety"""
        query_upper = query.strip().upper()
        
        # Must start with SELECT
        if not query_upper.startswith('SELECT'):
            return False
        
        # Block dangerous keywords
        dangerous = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER', 'CREATE', 
                    'EXEC', 'EXECUTE', 'PRAGMA']
        
        for keyword in dangerous:
            if keyword in query_upper:
                return False
        
        return True
    
    def _validate_write_query(self, query: str) -> bool:
        """Validate INSERT/UPDATE/DELETE query"""
        query_upper = query.strip().upper()
        
        # Must start with INSERT, UPDATE, or DELETE
        allowed_starts = ['INSERT', 'UPDATE', 'DELETE']
        if not any(query_upper.startswith(start) for start in allowed_starts):
            return False
        
        # Block dangerous keywords
        dangerous = ['DROP', 'ALTER', 'CREATE', 'EXEC', 'EXECUTE']
        
        for keyword in dangerous:
            if keyword in query_upper:
                return False
        
        return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        stats = {
            'total_queries': self.query_count,
            'errors': self.error_count,
            'success_rate': (self.query_count - self.error_count) / max(self.query_count, 1) * 100
        }
        
        # Get table statistics
        try:
            tables_query = """
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
            """
            tables = self.execute_query(tables_query)
            
            table_stats = {}
            for table in tables:
                count_query = f"SELECT COUNT(*) as count FROM {table['name']}"
                result = self.execute_query(count_query)
                if result:
                    table_stats[table['name']] = result[0]['count']
            
            stats['tables'] = table_stats
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
        
        return stats
    
    def backup_database(self, backup_path: str) -> bool:
        """Create database backup"""
        try:
            import shutil
            
            # Use SQLite backup API for safe backup
            with self.pool.get_connection() as source_conn:
                backup_conn = sqlite3.connect(backup_path)
                source_conn.backup(backup_conn)
                backup_conn.close()
            
            self.logger.info(f"Database backed up to: {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Backup error: {e}")
            return False
    
    def vacuum_database(self) -> bool:
        """Optimize database (reclaim space)"""
        try:
            with self.pool.get_connection() as conn:
                conn.execute('VACUUM')
                conn.commit()
            
            self.logger.info("Database optimized with VACUUM")
            return True
            
        except Exception as e:
            self.logger.error(f"VACUUM error: {e}")
            return False
    
    def check_integrity(self) -> bool:
        """Check database integrity"""
        try:
            result = self.execute_query('PRAGMA integrity_check')
            
            if result and result[0][0] == 'ok':
                self.logger.info("Database integrity check: OK")
                return True
            else:
                self.logger.error(f"Database integrity check failed: {result}")
                return False
                
        except Exception as e:
            self.logger.error(f"Integrity check error: {e}")
            return False
    
    def close(self):
        """Close all database connections"""
        self.pool.close_all()
        self.logger.info("Database connections closed")


# Global production database instance
db_production = ProductionDatabaseManager()
