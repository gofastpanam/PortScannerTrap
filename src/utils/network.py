"""Utilitaires réseau"""
import logging
from scapy.all import get_working_ifaces
import ctypes

def is_admin():
    """Vérifie si le programme a les droits administrateur"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def setup_interface():
    """Configure l'interface réseau pour la capture"""
    try:
        # Obtenir toutes les interfaces disponibles
        interfaces = get_working_ifaces()
        if not interfaces:
            logging.error("Aucune interface réseau trouvée")
            return None

        # Préférer les interfaces physiques et actives
        for iface in interfaces:
            if hasattr(iface, 'name') and hasattr(iface, 'description'):
                logging.debug(f"Interface trouvée: {iface.name} - {iface.description}")
                if "Ethernet" in iface.description or "Wi-Fi" in iface.description:
                    logging.info(f"Interface configurée : {iface.name}")
                    logging.info(f"Description : {iface.description}")
                    return iface.name

        # Si aucune interface préférée n'est trouvée, utiliser la première disponible
        iface = interfaces[0]
        logging.info(f"Interface configurée : {iface.name}")
        logging.info(f"Description : {iface.description}")
        return iface.name

    except Exception as e:
        logging.error(f"Erreur lors de la configuration de l'interface : {str(e)}")
        return None
