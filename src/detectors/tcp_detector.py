"""Module de détection des scans TCP"""
from scapy.all import IP, TCP, send
import logging

class TCPDetector:
    def __init__(self):
        self.last_log_time = {}
        self.MIN_LOG_INTERVAL = 1  # 1 seconde entre les logs

    def get_tcp_flags_str(self, flags):
        """Convertit les flags TCP en chaîne lisible"""
        flag_chars = {
            0x01: 'F',  # FIN
            0x02: 'S',  # SYN
            0x04: 'R',  # RST
            0x08: 'P',  # PSH
            0x10: 'A',  # ACK
            0x20: 'U',  # URG
            0x40: 'E',  # ECE
            0x80: 'C'   # CWR
        }
        return ''.join(f for b, f in flag_chars.items() if flags & b)

    def detect(self, pkt, current_time):
        """Détecte les scans TCP"""
        if not pkt.haslayer(TCP):
            return False

        ip_src = pkt[IP].src
        tcp_dport = pkt[TCP].dport
        tcp_sport = pkt[TCP].sport
        tcp_flags = int(pkt[TCP].flags)

        # Rate limiting
        if ip_src not in self.last_log_time:
            self.last_log_time[ip_src] = 0

        if current_time - self.last_log_time[ip_src] < self.MIN_LOG_INTERVAL:
            return False

        self.last_log_time[ip_src] = current_time

        # Log du paquet TCP
        flags_str = self.get_tcp_flags_str(tcp_flags)
        logging.debug(
            f"TCP Paquet - Src: {ip_src}:{tcp_sport} -> "
            f"Dst: {pkt[IP].dst}:{tcp_dport} "
            f"Flags: {flags_str} (0x{tcp_flags:02x})"
        )

        return self._handle_scan(pkt, tcp_flags, ip_src, tcp_sport, tcp_dport, flags_str)

    def _handle_scan(self, pkt, tcp_flags, ip_src, tcp_sport, tcp_dport, flags_str):
        """Gère les différents types de scans TCP"""
        if tcp_flags == 0x02:  # SYN scan
            logging.warning(
                f"SCAN SYN détecté depuis {ip_src}:{tcp_sport} vers le port {tcp_dport} "
                f"[Flags: {flags_str}]"
            )
            self._send_rst_ack(pkt, ip_src, tcp_sport, tcp_dport)
            return True

        elif tcp_flags == 0x01:  # FIN scan
            logging.warning(f"SCAN FIN détecté depuis {ip_src}:{tcp_sport} vers le port {tcp_dport}")
            return True

        elif tcp_flags == 0x29:  # XMAS scan
            logging.warning(f"SCAN XMAS détecté depuis {ip_src}:{tcp_sport} vers le port {tcp_dport}")
            return True

        elif tcp_flags == 0x00:  # NULL scan
            logging.warning(f"SCAN NULL détecté depuis {ip_src}:{tcp_sport} vers le port {tcp_dport}")
            return True

        elif tcp_flags == 0x10:  # ACK scan
            logging.warning(f"SCAN ACK détecté depuis {ip_src}:{tcp_sport} vers le port {tcp_dport}")
            return True

        return False

    def _send_rst_ack(self, pkt, ip_src, tcp_sport, tcp_dport):
        """Envoie un paquet RST+ACK en réponse"""
        try:
            rst = IP(dst=ip_src, src=pkt[IP].dst)/TCP(
                dport=tcp_sport,
                sport=tcp_dport,
                flags="RA",
                seq=0,
                ack=pkt[TCP].seq + 1
            )
            send(rst, verbose=0)
            logging.debug(f"RST+ACK envoyé à {ip_src}:{tcp_sport}")
        except Exception as e:
            logging.error(f"Erreur lors de l'envoi du RST: {str(e)}")
