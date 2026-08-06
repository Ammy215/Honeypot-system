import logging
import time
import signal
import sys
from typing import List, Dict
import config
from honeypot.services.ssh_honeypot import SSHHoneypot
from honeypot.services.ftp_honeypot import FTPHoneypot
from honeypot.services.telnet_honeypot import TelnetHoneypot
from honeypot.services.http_honeypot import HTTPHoneypot


class HoneypotServer:
    """Main server manager that coordinates all honeypot services"""
    
    def __init__(self):
        self.services = []
        self.running = False
        self.logger = logging.getLogger("honeypot.server")
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)
    
    def initialize_services(self):
        """Initialize all enabled honeypot services"""
        self.logger.info("Initializing honeypot services...")
        
        # SSH Honeypot
        if config.SERVICES["SSH"]["enabled"]:
            ssh_port = config.SERVICES["SSH"]["port"]
            ssh_service = SSHHoneypot(port=ssh_port, host=config.HONEYPOT_HOST)
            self.services.append(ssh_service)
            self.logger.info(f"SSH honeypot initialized on port {ssh_port}")
        
        # FTP Honeypot
        if config.SERVICES["FTP"]["enabled"]:
            ftp_port = config.SERVICES["FTP"]["port"]
            ftp_service = FTPHoneypot(port=ftp_port, host=config.HONEYPOT_HOST)
            self.services.append(ftp_service)
            self.logger.info(f"FTP honeypot initialized on port {ftp_port}")
        
        # HTTP Honeypot
        if config.SERVICES["HTTP"]["enabled"]:
            http_port = config.SERVICES["HTTP"]["port"]
            http_service = HTTPHoneypot(port=http_port, host=config.HONEYPOT_HOST)
            self.services.append(http_service)
            self.logger.info(f"HTTP honeypot initialized on port {http_port}")
        
        # Telnet Honeypot
        if config.SERVICES["Telnet"]["enabled"]:
            telnet_port = config.SERVICES["Telnet"]["port"]
            telnet_service = TelnetHoneypot(port=telnet_port, host=config.HONEYPOT_HOST)
            self.services.append(telnet_service)
            self.logger.info(f"Telnet honeypot initialized on port {telnet_port}")
        
        self.logger.info(f"Initialized {len(self.services)} honeypot service(s)")
    
    def start(self):
        """Start all honeypot services"""
        if not self.services:
            self.logger.error("No services to start. Call initialize_services() first.")
            return
        
        self.logger.info("Starting honeypot services...")
        self.running = True
        
        # Start all services
        for service in self.services:
            try:
                service.start()
                self.logger.info(f"{service.service_name} service started successfully")
            except Exception as e:
                self.logger.error(f"Failed to start {service.service_name}: {e}")
        
        self.logger.info("All honeypot services started")
        self.logger.info("Press Ctrl+C to stop")
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
                # Optionally log stats periodically
                if int(time.time()) % 300 == 0:  # Every 5 minutes
                    self._log_stats()
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
            self.stop()
    
    def stop(self):
        """Stop all honeypot services"""
        self.logger.info("Stopping all honeypot services...")
        self.running = False
        
        for service in self.services:
            try:
                service.stop()
                self.logger.info(f"{service.service_name} service stopped")
            except Exception as e:
                self.logger.error(f"Error stopping {service.service_name}: {e}")
        
        self.logger.info("All services stopped")
    
    def _log_stats(self):
        """Log statistics for all services"""
        self.logger.info("=== Service Statistics ===")
        for service in self.services:
            self.logger.info(
                f"{service.service_name}: "
                f"{service.connection_count} total connections, "
                f"Port {service.port}, "
                f"Status: {'RUNNING' if service.running else 'STOPPED'}"
            )
    
    def get_service_status(self) -> List[Dict]:
        """Get status of all services"""
        status = []
        for service in self.services:
            status.append({
                "name": service.service_name,
                "port": service.port,
                "running": service.running,
                "connections": service.connection_count
            })
        return status
