"""Gestionnaire de paquets principal"""
import time
import logging
from scapy.all import IP
from ..detectors.tcp_detector import TCPDetector
from ..detectors.udp_detector import UDPDetector
from ..detectors.icmp_detector import ICMPDetector

class PacketHandler:
    def __init__(self):
        self.tcp_detector = TCPDetector()
        self.udp_detector = UDPDetector()
        self.icmp_detector = ICMPDetector()

    def handle_packet(self, pkt):
        """Traite un paquet reçu"""
        try:
            # Vérifier si le paquet a une couche IP
            if not pkt.haslayer(IP):
                return

            current_time = time.time()

            # Vérifier chaque type de scan
            if self.tcp_detector.detect(pkt, current_time):
                return

            if self.udp_detector.detect(pkt, current_time):
                return

            if self.icmp_detector.detect(pkt, current_time):
                return

        except Exception as e:
            if "Layer [IP] not found" not in str(e):
                logging.error(f"Erreur lors du traitement du paquet : {str(e)}")
            # Pour le debug, on peut logger le résumé du paquet problématique
            logging.debug(f"Paquet problématique : {pkt.summary()}")
