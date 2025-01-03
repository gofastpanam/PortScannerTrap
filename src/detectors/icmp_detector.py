"""Module de détection des scans ICMP"""
from scapy.all import IP, ICMP, send
import logging

class ICMPDetector:
    def __init__(self):
        self.last_log_time = {}
        self.MIN_LOG_INTERVAL = 1

    def detect(self, pkt, current_time):
        """Détecte les scans ICMP"""
        if not pkt.haslayer(ICMP):
            return False

        ip_src = pkt[IP].src
        icmp_type = pkt[ICMP].type

        # Rate limiting
        if ip_src not in self.last_log_time:
            self.last_log_time[ip_src] = 0

        if current_time - self.last_log_time[ip_src] < self.MIN_LOG_INTERVAL:
            return False

        self.last_log_time[ip_src] = current_time

        if icmp_type == 8:  # Echo Request
            logging.warning(f"PING SCAN détecté depuis {ip_src}")
            self._send_echo_reply(pkt, ip_src)
            return True

        elif icmp_type == 13:  # Timestamp Request
            logging.warning(f"SCAN ICMP TIMESTAMP détecté depuis {ip_src}")
            return True

        elif icmp_type == 17:  # Address Mask Request
            logging.warning(f"SCAN ICMP ADDRESS MASK détecté depuis {ip_src}")
            return True

        return False

    def _send_echo_reply(self, pkt, ip_src):
        """Envoie un ICMP Echo Reply en réponse"""
        try:
            icmp_reply = IP(dst=ip_src, src=pkt[IP].dst)/ICMP(type=0, code=0)
            send(icmp_reply, verbose=0)
            logging.debug(f"ICMP Echo Reply envoyé à {ip_src}")
        except Exception as e:
            logging.error(f"Erreur lors de l'envoi de l'ICMP Reply: {str(e)}")
