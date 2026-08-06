import socket
import time
from typing import Tuple
import config
from honeypot.core.base_service import BaseHoneypotService
from database.db import log_connection, update_service_stats, db, get_or_create_attacker


class TelnetHoneypot(BaseHoneypotService):
    """Fake Telnet service honeypot"""
    
    def __init__(self, port: int = 2323, host: str = "0.0.0.0"):
        super().__init__(port, "Telnet", host)
        self.banner = config.BANNERS["Telnet"]
    
    def get_banner(self) -> bytes:
        """Return Telnet login prompt"""
        return self.banner.encode('utf-8')
    
    def handle_connection(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle Telnet connection attempt"""
        ip_address = address[0]
        source_port = address[1]
        start_time = time.time()
        
        self.logger.info(f"Telnet connection from {ip_address}:{source_port}")
        
        # Send Telnet banner and login prompt
        banner_sent = self.send_safe(client_socket, self.get_banner())
        if not banner_sent:
            return
        
        # Log connection
        log_connection(
            ip_address=ip_address,
            source_port=source_port,
            destination_port=self.port,
            service_name=self.service_name,
            raw_data="Telnet connection established"
        )
        
        # Track login attempts
        login_attempts = 0
        username = None
        
        try:
            # Wait for username
            username_data = self.recv_safe(client_socket, 1024)
            if username_data:
                username = username_data.strip()
                self.logger.info(f"Telnet username from {ip_address}: {username}")
                
                # Send password prompt
                password_prompt = "Password: "
                self.send_safe(client_socket, password_prompt.encode('utf-8'))
                
                # Wait for password
                password_data = self.recv_safe(client_socket, 1024)
                if password_data:
                    password = password_data.strip()
                    login_attempts += 1
                    
                    self.logger.warning(
                        f"Telnet login attempt from {ip_address}: "
                        f"user={username}, pass={password}"
                    )
                    
                    # Log to database
                    self._log_login_attempt(ip_address, username, password, login_attempts)
                    
                    # Run detection checks
                    from database.queries.login_attempts import check_and_alert_after_login
                    check_and_alert_after_login(ip_address, self.service_name, username, password)
                    
                    # Delay before responding (frustrate automated tools)
                    time.sleep(2)
                    
                    # Always reject login
                    failure_msg = "\r\nLogin incorrect\r\n\r\n"
                    self.send_safe(client_socket, failure_msg.encode('utf-8'))
                    
                    # Give one more attempt
                    if login_attempts < 2:
                        # Send login prompt again
                        self.send_safe(client_socket, self.get_banner())
                        
                        # Second attempt
                        username_data2 = self.recv_safe(client_socket, 1024)
                        if username_data2:
                            username = username_data2.strip()
                            self.send_safe(client_socket, b"Password: ")
                            
                            password_data2 = self.recv_safe(client_socket, 1024)
                            if password_data2:
                                password = password_data2.strip()
                                login_attempts += 1
                                
                                self.logger.warning(
                                    f"Telnet login attempt #{login_attempts} from {ip_address}: "
                                    f"user={username}, pass={password}"
                                )
                                
                                self._log_login_attempt(ip_address, username, password, login_attempts)
                                time.sleep(2)
                                
                                # Run detection checks
                                from database.queries.login_attempts import check_and_alert_after_login
                                check_and_alert_after_login(ip_address, self.service_name, username, password)
                                
                                # Final rejection
                                self.send_safe(client_socket, b"\r\nLogin incorrect\r\n\r\n")
        
        except Exception as e:
            self.logger.error(f"Telnet handler error from {ip_address}: {e}")
        
        # Update service stats
        update_service_stats(self.service_name, self.port)
        
        # Calculate duration
        duration = time.time() - start_time
        self.logger.info(
            f"Telnet connection from {ip_address} closed after {duration:.2f}s "
            f"({login_attempts} login attempts)"
        )
        
        # Close connection
        try:
            client_socket.close()
        except:
            pass
    
    def _log_login_attempt(self, ip_address: str, username: str, password: str, attempt_number: int):
        """Log login attempt to database"""
        attacker_id = get_or_create_attacker(ip_address)
        
        # Calculate time since last attempt
        last_attempt_query = """
            SELECT timestamp FROM login_attempts 
            WHERE ip_address = ? AND service_name = ?
            ORDER BY timestamp DESC LIMIT 1
        """
        last_attempts = db.execute_query(last_attempt_query, (ip_address, self.service_name))
        
        time_since_last = None
        if last_attempts:
            from datetime import datetime
            last_time = datetime.fromisoformat(last_attempts[0]['timestamp'])
            now = datetime.now()
            time_since_last = (now - last_time).total_seconds()
        
        # Insert login attempt
        query = """
            INSERT INTO login_attempts 
            (attacker_id, ip_address, service_name, username, password_attempt, 
             attempt_number, time_since_last_attempt)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        db.execute_update(
            query,
            (attacker_id, ip_address, self.service_name, username, password, 
             attempt_number, time_since_last)
        )
        
        # Update attacker stats
        update_query = """
            UPDATE attackers 
            SET total_login_attempts = total_login_attempts + 1,
                last_seen = CURRENT_TIMESTAMP
            WHERE id = ?
        """
        db.execute_update(update_query, (attacker_id,))
        
        # Update service stats
        update_service_query = """
            UPDATE service_stats 
            SET total_login_attempts = total_login_attempts + 1
            WHERE service_name = ? AND port = ?
        """
        db.execute_update(update_service_query, (self.service_name, self.port))
