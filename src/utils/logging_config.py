"""Configuration du logging"""
import logging
import sys

def setup_logging():
    """Configure le système de logging"""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('scan_detection.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

    # Réduire le niveau de log pour les modules externes
    logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
