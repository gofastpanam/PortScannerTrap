"""Module de détection des scans UDP"""
from scapy.all import IP, UDP, ICMP, send
import logging

class UDPDetector:
    def __init__(self):
        self.last_log_time = {}
        self.MIN_LOG_INTERVAL = 1

    def detect(self, pkt, current_time):
        """Détecte les scans UDP"""
        if not pkt.haslayer(UDP):
            return False

        ip_src = pkt[IP].src
        udp_dport = pkt[UDP].dport

        # Rate limiting
        if ip_src not in self.last_log_time:
            self.last_log_time[ip_src] = 0

        if current_time - self.last_log_time[ip_src] < self.MIN_LOG_INTERVAL:
            return False

        self.last_log_time[ip_src] = current_time

        if len(pkt[UDP].payload) == 0:
            logging.warning(f"SCAN UDP détecté depuis {ip_src} vers le port {udp_dport}")
            self._send_icmp_unreachable(pkt, ip_src)
            return True

        return False

    def _send_icmp_unreachable(self, pkt, ip_src):
        """Envoie un ICMP Port Unreachable en réponse"""
        try:
            icmp_response = IP(dst=ip_src, src=pkt[IP].dst)/ICMP(type=3, code=3)
            send(icmp_response, verbose=0)
            logging.debug(f"ICMP Port Unreachable envoyé à {ip_src}")
        except Exception as e:
            logging.error(f"Erreur lors de l'envoi de l'ICMP: {str(e)}")
