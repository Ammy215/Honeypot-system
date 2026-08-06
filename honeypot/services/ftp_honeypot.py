import socket
import time
from typing import Tuple
import config
from honeypot.core.base_service import BaseHoneypotService
from database.db import log_connection, update_service_stats, db, get_or_create_attacker


class FTPHoneypot(BaseHoneypotService):
    """Fake FTP service honeypot"""
    
    def __init__(self, port: int = 2121, host: str = "0.0.0.0"):
        super().__init__(port, "FTP", host)
        self.banner = config.BANNERS["FTP"]
    
    def get_banner(self) -> bytes:
        """Return FTP banner"""
        return f"{self.banner}\r\n".encode('utf-8')
    
    def handle_connection(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle FTP connection attempt"""
        ip_address = address[0]
        source_port = address[1]
        start_time = time.time()
        
        self.logger.info(f"FTP connection from {ip_address}:{source_port}")
        
        # Send FTP welcome banner
        banner_sent = self.send_safe(client_socket, self.get_banner())
        if not banner_sent:
            return
        
        # Log connection
        log_connection(
            ip_address=ip_address,
            source_port=source_port,
            destination_port=self.port,
            service_name=self.service_name,
            raw_data="FTP connection established"
        )
        
        # Track login attempts for this session
        login_attempts = 0
        username = None
        
        try:
            # Handle FTP commands
            while login_attempts < config.MAX_LOGIN_ATTEMPTS_PER_SESSION:
                data = self.recv_safe(client_socket, 4096)
                
                if not data:
                    break
                
                command = data.strip().upper()
                self.logger.debug(f"FTP command from {ip_address}: {command}")
                
                # USER command
                if command.startswith("USER "):
                    username = data.strip()[5:].strip()
                    self.logger.info(f"FTP USER attempt from {ip_address}: {username}")
                    
                    response = f"331 Password required for {username}\r\n"
                    self.send_safe(client_socket, response.encode('utf-8'))
                
                # PASS command
                elif command.startswith("PASS "):
                    password = data.strip()[5:].strip()
                    login_attempts += 1
                    
                    self.logger.warning(
                        f"FTP login attempt #{login_attempts} from {ip_address}: "
                        f"user={username}, pass={password}"
                    )
                    
                    # Log to database
                    self._log_login_attempt(ip_address, username, password, login_attempts)
                    
                    # Run detection checks
                    from database.queries.login_attempts import check_and_alert_after_login
                    check_and_alert_after_login(ip_address, self.service_name, username, password)
                    
                    # Delay before responding (frustrate automated tools)
                    time.sleep(2)
                    
                    if login_attempts >= 3:
                        # Too many failures
                        response = "421 Too many login failures. Connection closing.\r\n"
                        self.send_safe(client_socket, response.encode('utf-8'))
                        break
                    else:
                        # Always reject
                        response = "530 Login incorrect.\r\n"
                        self.send_safe(client_socket, response.encode('utf-8'))
                
                # QUIT command
                elif command.startswith("QUIT"):
                    response = "221 Goodbye.\r\n"
                    self.send_safe(client_socket, response.encode('utf-8'))
                    break
                
                # SYST command (system type)
                elif command.startswith("SYST"):
                    response = "215 UNIX Type: L8\r\n"
                    self.send_safe(client_socket, response.encode('utf-8'))
                
                # HELP command
                elif command.startswith("HELP"):
                    response = "214 The following commands are recognized:\r\n USER PASS QUIT SYST HELP\r\n214 Help OK.\r\n"
                    self.send_safe(client_socket, response.encode('utf-8'))
                
                # Unknown command
                else:
                    response = "500 Unknown command.\r\n"
                    self.send_safe(client_socket, response.encode('utf-8'))
        
        except Exception as e:
            self.logger.error(f"FTP handler error from {ip_address}: {e}")
        
        # Update service stats
        update_service_stats(self.service_name, self.port)
        
        # Calculate duration
        duration = time.time() - start_time
        self.logger.info(
            f"FTP connection from {ip_address} closed after {duration:.2f}s "
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
