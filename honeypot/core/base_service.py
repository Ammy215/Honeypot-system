import socket
import threading
import logging
from abc import ABC, abstractmethod
from typing import Tuple
import time

import config

class BaseHoneypotService(ABC):
    """Abstract base class for all honeypot services"""

    def __init__(self, port: int, service_name: str, host: str = "0.0.0.0"):
        self.port = port
        self.service_name = service_name
        self.host = host
        self.server_socket = None
        self.running = False
        self.connection_count = 0
        self.logger = logging.getLogger(f"honeypot.{service_name}")
        self.thread = None
        self._active_connections_by_ip = {}
        self._connections_lock = threading.Lock()
    
    def start(self):
        """Start the honeypot service in a separate thread"""
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.logger.info(f"{self.service_name} honeypot thread started")
    
    def _run(self):
        """Internal run method executed in thread"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(100)
            self.running = True
            self.logger.info(f"{self.service_name} honeypot listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    # Accept incoming connection
                    client_socket, address = self.server_socket.accept()

                    if not self._register_connection(address[0]):
                        self.logger.warning(
                            f"Rejected connection from {address[0]}: "
                            f"per-IP connection limit ({config.MAX_CONNECTIONS_PER_IP}) reached"
                        )
                        try:
                            client_socket.close()
                        except OSError:
                            pass
                        continue

                    client_socket.settimeout(30)  # 30 second timeout

                    # Handle connection in separate thread
                    handler_thread = threading.Thread(
                        target=self._handle_connection_wrapper,
                        args=(client_socket, address),
                        daemon=True
                    )
                    handler_thread.start()
                    self.connection_count += 1

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept error: {e}")
        
        except Exception as e:
            self.logger.error(f"Server socket error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            self.logger.info(f"{self.service_name} honeypot stopped")
    
    def _handle_connection_wrapper(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Wrapper to handle exceptions in connection handler"""
        try:
            self.handle_connection(client_socket, address)
        except Exception as e:
            self.logger.error(f"Connection handler error from {address[0]}: {e}")
        finally:
            self._release_connection(address[0])
            try:
                client_socket.close()
            except OSError:
                pass

    def _register_connection(self, ip: str) -> bool:
        """Track an active connection for an IP, rejecting it if over the per-IP cap"""
        with self._connections_lock:
            count = self._active_connections_by_ip.get(ip, 0)
            if count >= config.MAX_CONNECTIONS_PER_IP:
                return False
            self._active_connections_by_ip[ip] = count + 1
            return True

    def _release_connection(self, ip: str):
        """Release a tracked connection slot for an IP"""
        with self._connections_lock:
            count = self._active_connections_by_ip.get(ip, 0)
            if count <= 1:
                self._active_connections_by_ip.pop(ip, None)
            else:
                self._active_connections_by_ip[ip] = count - 1
    
    def stop(self):
        """Stop the honeypot service"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.logger.info(f"{self.service_name} honeypot shutdown initiated")
    
    @abstractmethod
    def handle_connection(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle incoming connection - must be implemented by subclass"""
        pass
    
    @abstractmethod
    def get_banner(self) -> bytes:
        """Get service banner - must be implemented by subclass"""
        pass
    
    def send_safe(self, client_socket: socket.socket, data: bytes) -> bool:
        """Safely send data to client"""
        try:
            client_socket.sendall(data)
            return True
        except Exception as e:
            self.logger.error(f"Send error: {e}")
            return False
    
    def recv_safe(self, client_socket: socket.socket, buffer_size: int = 4096) -> str:
        """Safely receive data from client"""
        try:
            data = client_socket.recv(buffer_size)
            return data.decode('utf-8', errors='ignore')
        except socket.timeout:
            return ""
        except Exception as e:
            self.logger.error(f"Receive error: {e}")
            return ""
