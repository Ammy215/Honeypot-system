import socket
import time
from typing import Tuple
import config
from honeypot.core.base_service import BaseHoneypotService
from database.db import log_connection, update_service_stats


class SSHHoneypot(BaseHoneypotService):
    """Fake SSH service honeypot"""
    
    def __init__(self, port: int = 2222, host: str = "0.0.0.0"):
        super().__init__(port, "SSH", host)
        self.banner = config.BANNERS["SSH"]
    
    def get_banner(self) -> bytes:
        """Return SSH banner"""
        return f"{self.banner}\r\n".encode('utf-8')
    
    def handle_connection(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle SSH connection attempt"""
        ip_address = address[0]
        source_port = address[1]
        start_time = time.time()
        
        self.logger.info(f"SSH connection from {ip_address}:{source_port}")
        
        # Send fake SSH banner immediately
        banner_sent = self.send_safe(client_socket, self.get_banner())
        
        if not banner_sent:
            return
        
        # Collect any data sent by the client
        raw_data_parts = []
        
        try:
            # Wait for client data (SSH client identification, key exchange, etc.)
            for _ in range(3):  # Accept up to 3 packets
                data = self.recv_safe(client_socket, 4096)
                if data:
                    raw_data_parts.append(data)
                    self.logger.debug(f"Received from {ip_address}: {data[:100]}")
                else:
                    break
                
                # Small delay between reads
                time.sleep(0.1)
        
        except Exception as e:
            self.logger.error(f"Error reading SSH data from {ip_address}: {e}")
        
        # Combine all received data
        raw_data = "".join(raw_data_parts) if raw_data_parts else None
        
        # Log connection to database
        log_connection(
            ip_address=ip_address,
            source_port=source_port,
            destination_port=self.port,
            service_name=self.service_name,
            raw_data=raw_data
        )
        
        # Update service statistics
        update_service_stats(self.service_name, self.port)
        
        # Calculate connection duration
        duration = time.time() - start_time
        self.logger.info(f"SSH connection from {ip_address} closed after {duration:.2f}s")
        
        # Close connection
        try:
            client_socket.close()
        except:
            pass
