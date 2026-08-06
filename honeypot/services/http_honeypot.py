import socket
import time
from typing import Tuple
import config
from honeypot.core.base_service import BaseHoneypotService
from database.db import log_connection, update_service_stats, db, get_or_create_attacker


class HTTPHoneypot(BaseHoneypotService):
    """Fake HTTP service honeypot - simulates admin panels"""
    
    def __init__(self, port: int = 8080, host: str = "0.0.0.0"):
        super().__init__(port, "HTTP", host)
    
    def get_banner(self) -> bytes:
        """Return HTTP server header"""
        return b"Server: Apache/2.4.41 (Ubuntu)\r\n"
    
    def handle_connection(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle HTTP connection attempt"""
        ip_address = address[0]
        source_port = address[1]
        start_time = time.time()
        
        self.logger.info(f"HTTP connection from {ip_address}:{source_port}")
        
        try:
            # Receive HTTP request
            request_data = self.recv_safe(client_socket, 8192)
            
            if not request_data:
                return
            
            self.logger.debug(f"HTTP request from {ip_address}: {request_data[:200]}")
            
            # Parse request
            lines = request_data.split('\n')
            if not lines:
                return
            
            request_line = lines[0].strip()
            parts = request_line.split()
            
            if len(parts) < 2:
                return
            
            method = parts[0].upper()
            path = parts[1]
            
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            user_agent = headers.get('user-agent', 'Unknown')
            
            # Log connection with path and user-agent
            raw_data = f"{method} {path} | UA: {user_agent}"
            log_connection(
                ip_address=ip_address,
                source_port=source_port,
                destination_port=self.port,
                service_name=self.service_name,
                raw_data=raw_data
            )
            
            # Handle different paths
            if path.startswith('/admin') or path == '/admin':
                self._handle_admin_page(client_socket, ip_address, method, request_data)
            elif path.startswith('/phpmyadmin'):
                self._handle_phpmyadmin(client_socket, ip_address)
            elif path.startswith('/wp-admin') or path.startswith('/wp-login'):
                self._handle_wordpress(client_socket, ip_address, method, request_data)
            else:
                # Generic 404 for other paths - log as reconnaissance
                self.logger.warning(f"HTTP path reconnaissance from {ip_address}: {path}")
                self._send_404(client_socket)
            
            # Update service stats
            update_service_stats(self.service_name, self.port)
        
        except Exception as e:
            self.logger.error(f"HTTP handler error from {ip_address}: {e}")
        
        # Calculate duration
        duration = time.time() - start_time
        self.logger.info(f"HTTP connection from {ip_address} closed after {duration:.2f}s")
        
        # Close connection
        try:
            client_socket.close()
        except:
            pass
    
    def _handle_admin_page(self, client_socket: socket.socket, ip_address: str, 
                           method: str, request_data: str):
        """Handle /admin page requests"""
        
        if method == "GET":
            # Serve fake admin login page
            html = self._get_admin_login_html()
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(html)}\r\n"
                "Server: Apache/2.4.41 (Ubuntu)\r\n"
                "Connection: close\r\n"
                "\r\n" + html
            )
            self.send_safe(client_socket, response.encode('utf-8'))
            self.logger.info(f"Served fake admin login page to {ip_address}")
        
        elif method == "POST":
            # Parse POST data for credentials
            username, password = self._parse_post_credentials(request_data)
            
            if username or password:
                self.logger.warning(
                    f"HTTP admin login attempt from {ip_address}: "
                    f"user={username}, pass={password}"
                )
                
                # Log to database
                self._log_login_attempt(ip_address, username, password)
                
                # Run detection checks
                from database.queries.login_attempts import check_and_alert_after_login
                check_and_alert_after_login(ip_address, self.service_name, username, password)
            
            # Always return failure
            html = self._get_login_failure_html()
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(html)}\r\n"
                "Server: Apache/2.4.41 (Ubuntu)\r\n"
                "Connection: close\r\n"
                "\r\n" + html
            )
            self.send_safe(client_socket, response.encode('utf-8'))
    
    def _handle_phpmyadmin(self, client_socket: socket.socket, ip_address: str):
        """Handle phpMyAdmin access attempts"""
        self.logger.warning(f"phpMyAdmin access attempt from {ip_address}")
        
        html = """<!DOCTYPE html>
<html>
<head><title>phpMyAdmin</title></head>
<body>
<h1>phpMyAdmin</h1>
<p>Access denied. This system is monitored.</p>
</body>
</html>"""
        
        response = (
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(html)}\r\n"
            "Server: Apache/2.4.41 (Ubuntu)\r\n"
            "Connection: close\r\n"
            "\r\n" + html
        )
        self.send_safe(client_socket, response.encode('utf-8'))
    
    def _handle_wordpress(self, client_socket: socket.socket, ip_address: str,
                         method: str, request_data: str):
        """Handle WordPress admin access attempts"""
        
        if method == "POST":
            username, password = self._parse_post_credentials(request_data)
            if username or password:
                self.logger.warning(
                    f"WordPress login attempt from {ip_address}: "
                    f"user={username}, pass={password}"
                )
                self._log_login_attempt(ip_address, username, password)
                
                # Run detection checks
                from database.queries.login_attempts import check_and_alert_after_login
                check_and_alert_after_login(ip_address, self.service_name, username, password)
        
        html = """<!DOCTYPE html>
<html>
<head><title>WordPress Login</title></head>
<body>
<h1>Login Failed</h1>
<p>Invalid username or password.</p>
</body>
</html>"""
        
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(html)}\r\n"
            "Server: Apache/2.4.41 (Ubuntu)\r\n"
            "Connection: close\r\n"
            "\r\n" + html
        )
        self.send_safe(client_socket, response.encode('utf-8'))
    
    def _send_404(self, client_socket: socket.socket):
        """Send 404 Not Found response"""
        html = """<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>404 Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body>
</html>"""
        
        response = (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(html)}\r\n"
            "Server: Apache/2.4.41 (Ubuntu)\r\n"
            "Connection: close\r\n"
            "\r\n" + html
        )
        self.send_safe(client_socket, response.encode('utf-8'))
    
    def _get_admin_login_html(self) -> str:
        """Generate fake admin login page HTML"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; }
        .login-box { width: 300px; margin: 100px auto; padding: 30px; 
                     background: white; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h2 { text-align: center; color: #333; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; 
                border-radius: 3px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; 
                 border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Admin Login</h2>
        <form method="POST" action="/admin">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>"""
    
    def _get_login_failure_html(self) -> str:
        """Generate login failure page"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Login Failed</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; }
        .error-box { width: 300px; margin: 100px auto; padding: 30px; 
                     background: white; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h2 { color: #d9534f; text-align: center; }
        p { text-align: center; color: #666; }
        a { display: block; text-align: center; margin-top: 20px; color: #007bff; }
    </style>
</head>
<body>
    <div class="error-box">
        <h2>Login Failed</h2>
        <p>Invalid credentials. Please try again.</p>
        <a href="/admin">← Back to Login</a>
    </div>
</body>
</html>"""
    
    def _parse_post_credentials(self, request_data: str) -> tuple:
        """Parse username and password from POST data"""
        username = None
        password = None
        
        # Find POST body
        if '\r\n\r\n' in request_data:
            body = request_data.split('\r\n\r\n', 1)[1]
        elif '\n\n' in request_data:
            body = request_data.split('\n\n', 1)[1]
        else:
            return username, password
        
        # Parse form data
        pairs = body.split('&')
        for pair in pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)
                # URL decode
                value = value.replace('+', ' ')
                if key == 'username' or key == 'log':
                    username = value
                elif key == 'password' or key == 'pwd':
                    password = value
        
        return username, password
    
    def _log_login_attempt(self, ip_address: str, username: str, password: str):
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
        
        # Count attempts for this IP
        count_query = """
            SELECT COUNT(*) as cnt FROM login_attempts 
            WHERE ip_address = ? AND service_name = ?
        """
        count_result = db.execute_query(count_query, (ip_address, self.service_name))
        attempt_number = count_result[0]['cnt'] + 1 if count_result else 1
        
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
