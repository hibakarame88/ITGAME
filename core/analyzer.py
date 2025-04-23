#!/usr/bin/env python3
import pyshark
import argparse
import json
import sys
import os
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, DefaultDict
from collections import defaultdict
import re

@dataclass
class HostInfo:
    """Structure de données représentant les informations d'un hôte réseau"""
    mac: Optional[str] = None
    ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    
    def clean_values(self):
        """Nettoie les valeurs de tous les champs en supprimant les séquences d'échappement ANSI"""
        ansi_pattern = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        
        if self.hostname:
            self.hostname = ansi_pattern.sub('', self.hostname).strip()
        if self.username:
            self.username = ansi_pattern.sub('', self.username).strip()
        if self.mac:
            self.mac = ansi_pattern.sub('', self.mac).strip()
        if self.ip:
            self.ip = ansi_pattern.sub('', self.ip).strip()


class PacketProcessor:
    """Traitement des différents types de paquets réseau"""
    
    @staticmethod
    def process_dhcp(packet, hosts_info: DefaultDict[str, HostInfo]) -> bool:
        """Traite les paquets DHCP pour extraire les informations de l'hôte"""
        try:
            if not (hasattr(packet, 'eth') and hasattr(packet, 'ip')):
                return False
                
            mac = packet.eth.src
            ip = None
            hostname = None
            
            # Extraire l'adresse IP (demandée ou assignée)
            if hasattr(packet.dhcp, 'ip_your') and packet.dhcp.ip_your != '0.0.0.0':
                ip = packet.dhcp.ip_your
            elif hasattr(packet.dhcp, 'ip_client') and packet.dhcp.ip_client != '0.0.0.0':
                ip = packet.dhcp.ip_client
            elif hasattr(packet, 'ip'):
                ip = packet.ip.src
            
            # Extraire le nom d'hôte des options DHCP
            if hasattr(packet.dhcp, 'option_hostname'):
                hostname = packet.dhcp.option_hostname
            elif hasattr(packet, 'dhcp'):
                for field_name in dir(packet.dhcp):
                    if 'hostname' in field_name.lower() and getattr(packet.dhcp, field_name):
                        hostname = getattr(packet.dhcp, field_name)
                        break
            
            # Mettre à jour les informations de l'hôte
            if mac:
                host = hosts_info[mac]
                host.mac = mac
                if ip:
                    host.ip = ip
                if hostname:
                    host.hostname = hostname
                return True
                
        except AttributeError as e:
            print(f"Erreur lors du traitement du paquet DHCP: {e}")
        
        return False
    
    @staticmethod
    def process_http(packet, hosts_info: DefaultDict[str, HostInfo]) -> bool:
        """Traite les paquets HTTP pour extraire les informations de l'hôte"""
        try:
            if not (hasattr(packet, 'eth') and hasattr(packet, 'ip')):
                return False
                
            mac = packet.eth.src
            ip = packet.ip.src
            
            # Mettre à jour les informations de l'hôte
            host = hosts_info[mac]
            host.mac = mac
            host.ip = ip
            
            # Essayer d'extraire le nom d'utilisateur des en-têtes HTTP ou cookies
            if hasattr(packet.http, 'cookie'):
                cookie = packet.http.cookie
                if 'username=' in cookie:
                    username = cookie.split('username=')[1].split(';')[0]
                    host.username = username
                    return True
                    
        except AttributeError as e:
            print(f"Erreur lors du traitement du paquet HTTP: {e}")
        
        return False
    
    @staticmethod
    def process_kerberos(packet, hosts_info: DefaultDict[str, HostInfo]) -> bool:
        """Traite les paquets Kerberos pour extraire le nom d'utilisateur et le nom NetBIOS"""
        try:
            if not (hasattr(packet, 'eth') and hasattr(packet, 'ip')):
                return False
                
            mac = packet.eth.src
            ip = packet.ip.src
            
            # Mettre à jour les informations de l'hôte
            host = hosts_info[mac]
            host.mac = mac
            host.ip = ip
            
            updated = False
            
            # Extraire le CNameString Kerberos (nom d'utilisateur)
            if hasattr(packet.kerberos, 'CNameString'):
                cname = packet.kerberos.CNameString
                if cname.endswith('$'):
                    # C'est un compte d'ordinateur, définir comme hostname si non défini
                    if not host.hostname:
                        host.hostname = cname
                        updated = True
                else:
                    # C'est probablement un compte utilisateur
                    host.username = cname
                    updated = True
            
            # Extraire le nom NetBIOS des adresses Kerberos
            if hasattr(packet.kerberos, 'addresses'):
                for field in dir(packet.kerberos):
                    if field.startswith('addr_'):
                        addr_type_field = f"{field.replace('addr_', 'addr_type_')}"
                        if hasattr(packet.kerberos, addr_type_field) and getattr(packet.kerberos, addr_type_field) == '20':
                            netbios_name = getattr(packet.kerberos, field)
                            if netbios_name:
                                netbios_name = netbios_name.split('<')[0].strip()
                                host.hostname = netbios_name
                                updated = True
                                break
            
            # Approche alternative pour les paquets plus complexes
            raw_data = str(packet)
            if 'NetBIOS Name:' in raw_data:
                try:
                    netbios_part = raw_data.split('NetBIOS Name:')[1].split('(')[0].strip()
                    netbios_name = netbios_part.split('<')[0].strip()
                    if netbios_name and len(netbios_name) > 1:
                        host.hostname = netbios_name
                        updated = True
                except Exception as e:
                    print(f"Erreur lors de l'extraction NetBIOS des données brutes: {e}")
            
            # Rechercher des champs Kerberos supplémentaires pouvant contenir des informations utilisateur
            for field in dir(packet.kerberos):
                if field.lower().startswith('cname') and not field == 'CNameString':
                    value = getattr(packet.kerberos, field)
                    if value and not value.endswith('$') and not host.username:
                        host.username = value
                        updated = True
            
            return updated
                
        except AttributeError as e:
            print(f"Erreur lors du traitement du paquet Kerberos: {e}")
        
        return False


class NetworkAnalyzer:
    """Analyseur de réseau principal pour la capture et l'analyse des paquets"""
    
    def __init__(self, interface=None, pcap_file=None, output_file=None):
        """Initialise l'analyseur réseau avec les paramètres fournis"""
        self.interface = interface
        # Utiliser data/latest.pcap comme valeur par défaut
        self.pcap_file = pcap_file or 'data/latest.pcap'
        # Utiliser data/resultat.json comme valeur par défaut
        self.output_file = output_file or 'data/resultat.json'
        self.hosts_info: DefaultDict[str, HostInfo] = defaultdict(HostInfo)
        self.display_filter = 'dhcp or http.accept_language or kerberos.CNameString and not nbns'
        
        # S'assurer que le répertoire de sortie existe
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        
    def capture_live(self, duration=60):
        """Capture des paquets depuis une interface réseau en direct"""
        try:
            capture = pyshark.LiveCapture(interface=self.interface, display_filter=self.display_filter)
            print(f"Capture sur {self.interface} pendant {duration} secondes...")
            capture.sniff(timeout=duration)
            self._process_packets(capture)
        except Exception as e:
            print(f"Erreur lors de la capture en direct: {e}")
            sys.exit(1)
        
    def analyze_pcap(self):
        """Analyse un fichier pcap existant"""
        try:
            print(f"Analyse du fichier pcap: {self.pcap_file}")
            # Vérifier si le fichier existe
            if not os.path.exists(self.pcap_file):
                print(f"Erreur: Le fichier {self.pcap_file} n'existe pas.")
                sys.exit(1)
                
            capture = pyshark.FileCapture(self.pcap_file, display_filter=self.display_filter)
            self._process_packets(capture)
        except Exception as e:
            print(f"Erreur lors de l'analyse du fichier pcap: {e}")
            sys.exit(1)
        
    def _process_packets(self, capture):
        """Traite les paquets capturés et extrait les informations pertinentes"""
        packet_count = 0
        try:
            for packet in capture:
                packet_count += 1
                
                # Traiter les différents types de paquets
                if 'DHCP' in packet:
                    PacketProcessor.process_dhcp(packet, self.hosts_info)
                
                if 'HTTP' in packet and hasattr(packet.http, 'accept_language'):
                    PacketProcessor.process_http(packet, self.hosts_info)
                    
                if 'KERBEROS' in packet:
                    PacketProcessor.process_kerberos(packet, self.hosts_info)
                    
        except KeyboardInterrupt:
            print("\nCapture interrompue par l'utilisateur")
        finally:
            print(f"Traitement de {packet_count} paquets terminé")
            self.save_results()
    
    def save_results(self):
        """Sauvegarde les résultats dans un fichier JSON avec uniquement la première entrée"""
        if not self.hosts_info:
            print("Aucun hôte trouvé.")
            # S'assurer que le répertoire existe
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            with open(self.output_file, 'w') as jsonfile:
                json.dump({}, jsonfile, indent=4)
            return

        # Obtenir uniquement la première entrée
        first_mac = next(iter(self.hosts_info))
        first_host_info = self.hosts_info[first_mac]
        
        # Nettoyer les valeurs pour supprimer les séquences d'échappement ANSI
        first_host_info.clean_values()

        # Créer un dictionnaire avec seulement la première entrée
        single_host_dict = {
            'Host Information': asdict(first_host_info)
        }

        # Écrire dans le fichier JSON
        with open(self.output_file, 'w') as jsonfile:
            json.dump(single_host_dict, jsonfile, indent=4)
            
        print(f"Résultat enregistré dans {self.output_file}")
        self._display_first_result()

    def _display_first_result(self):
        """Affiche uniquement le premier résultat dans le terminal"""
        if not self.hosts_info:
            print("\nAucun hôte trouvé.")
            return
            
        # Obtenir la première entrée
        first_mac = next(iter(self.hosts_info))
        info = self.hosts_info[first_mac]
        
        # Les valeurs sont déjà nettoyées dans save_results()
        
        print("\n--- Informations sur l'hôte réseau ---")
        print(f"Adresse MAC: {info.mac or 'N/A'}")
        print(f"Adresse IP: {info.ip or 'N/A'}")
        print(f"Nom d'hôte: {info.hostname or 'N/A'}")
        print(f"Nom d'utilisateur: {info.username or 'N/A'}")


def main():
    """Point d'entrée principal du programme"""
    parser = argparse.ArgumentParser(description='Analyseur d\'informations sur les hôtes réseau')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i', '--interface', help='Interface réseau pour la capture')
    group.add_argument('-p', '--pcap', help='Fichier PCAP à analyser (défaut: data/latest.pcap)')
    parser.add_argument('-t', '--time', type=int, default=60, help='Durée de capture en secondes (défaut: 60)')
    parser.add_argument('-o', '--output', help='Fichier JSON de sortie (défaut: data/resultat.json)')
    
    args = parser.parse_args()
    
    analyzer = NetworkAnalyzer(
        interface=args.interface,
        pcap_file=args.pcap,
        output_file=args.output
    )
    
    if args.interface:
        analyzer.capture_live(duration=args.time)
    else:
        # Par défaut, analyser le fichier pcap
        analyzer.analyze_pcap()


if __name__ == "__main__":
    main()