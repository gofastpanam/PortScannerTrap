#!/usr/bin/env python3
"""
Port Scanner Trap - Détecteur de scans de ports
"""

import logging
from scapy.all import sniff
import sys
import signal

from src.utils.network import is_admin, setup_interface
from src.utils.logging_config import setup_logging
from src.handlers.packet_handler import PacketHandler

def signal_handler(sig, frame):
    """Gère l'arrêt propre du programme"""
    logging.info("Arrêt du programme...")
    sys.exit(0)

def main():
    """Fonction principale"""
    # Vérifier les privilèges administrateur
    if not is_admin():
        logging.error("Ce programme nécessite des privilèges administrateur")
        sys.exit(1)

    # Configurer le logging
    setup_logging()
    logging.info("Démarrage de la détection de scans...")

    # Configurer l'interface réseau
    iface = setup_interface()
    if not iface:
        logging.error("Impossible de configurer l'interface réseau")
        sys.exit(1)

    # Initialiser le gestionnaire de paquets
    packet_handler = PacketHandler()

    # Configurer le gestionnaire de signal pour Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Filtre BPF plus précis pour les scans
    bpf_filter = (
        "ip and ("
        "tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst|tcp-push|tcp-ack|tcp-urg) != 0 or "
        "udp or "
        "icmp"
        ")"
    )
    logging.debug(f"Filtre BPF utilisé : {bpf_filter}")

    # Démarrer la capture
    logging.info("Détection de scans démarrée. Appuyez sur Ctrl+C pour arrêter.")
    logging.info(f"Interface de capture : {iface}")

    try:
        sniff(
            iface=iface,
            prn=packet_handler.handle_packet,
            store=0,
            filter=bpf_filter
        )
    except Exception as e:
        logging.error(f"Erreur lors de la capture : {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
