#!/usr/bin/env python3
"""
Scans a CIDR range on ports, generates JSON/CSV/HTML reports and optionally ECS NDJSON and CEF.
Usage: python3 soc.py 192.168.1.0/24 --ports "22,80,443" --output-format json,csv,ecs,cef --scanner-ip 10.0.0.5

Notes:
 - Responsible use: Run only in authorized environments and hosts.
 - By default, it only exports results with status == 'open' (SOC-oriented).
"""

import os
import signal
import sys
import re
import asyncio
import ipaddress
import argparse
import csv
import json
import socket
import xml.etree.ElementTree as ET
import subprocess
import platform
import time
from datetime import datetime
from typing import List, Dict, Optional, Set

'''
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
'''
    
DEFAULT_PORTS = [
    1,5,7,9,11,13,17,18,19,20,21,22,23,25,37,39,42,43,49,50,53,63,67,68,69,70,79,80,88,101,110,111,113,119,123,135,137,138,139,143,161,162,174,177,179,194,199,201,202,206,210,220,264,318,389,411,412,443,445,464,
    465,500,512,513,514,515,520,521,540,546,547,554,560,587,591,631,690,853,873,902,989,990,993,995,1026,1029,1080,1194,1214,1241,1337,1433,1434,1512,1521,1589,1701,1723,1725,
    1741,1755,1812,1813,1893,1985,2000,2002,2049,2082,2083,2302,3306,3074,3124,3127,3128,3222,3389,3478,3689,3724,3784,3785,4333,4444,4500,4662,4664,4672,4899,5000,5001,5004,5005,5060,5432,5500,5554,5600,5700,5800,5900,6000,6001,
    6112,6129,6257,6346,6347,6379,6566,6665,6669,6679,6697,6699,6881,6891,6901,6969,6970,6999,7100,7648,7649,8000,8080,8086,8087,8118,8200,8500,8866,9009,9100,9101,9103,9119,9800,9898,9988,9999,10000,11371,12035,12345,
    14567,15118,19226,19638,20000,24800,25565,25999,27374,28960,31337,45003,51400,51871
]

# Port -> basic gravity
CRITICAL_PORTS = {22,23,3389,445,5900}
HIGH_PORTS = {3306,1433,5432,1521}

# Additional categories
MALICIOUS = {1080,3127,4444,5554,8866,9898,9988,12345,27374,31337}
PEER_TO_PEER = {411,412,1214,1337,4672,6257,6346,6347,6699,6881,6999}
GAMING = {1725,2302,3074,3724,6112,6500,12035,14567,15118,25565,28960}
CHAT = {1893,6665,6669,6679,6697,6891,6901,7648,7649,9119,25999}
STREAMING = {1755,3784,3785,5001,5004,5005,5060,6970,8000,24800}

def setup_signal_handlers():
    """Configura manejadores de señales para interrupción graceful"""
    def signal_handler(sig, frame):
        print(f"\n[!] Received signal {sig}. Shutting down gracefully...")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def validate_cidr(cidr: str) -> bool:
    """
    Valida un string CIDR (IPv4 o IPv6) y proporciona feedback detallado en caso de error.
    
    Args:
        cidr: String en formato CIDR (e.g., "192.168.1.0/24")
    
    Returns:
        bool: True si es válido, False si no lo es
    """
    try:
        # Intentar crear el objeto de red
        network = ipaddress.ip_network(cidr, strict=False)
        
        # Validaciones adicionales
        if network.version == 4:
            if network.prefixlen < 8:
                print(f"[!] Advertencia: El prefijo /{network.prefixlen} es muy amplio y puede generar demasiados hosts")
            elif network.prefixlen > 30:
                print(f"[!] Advertencia: El prefijo /{network.prefixlen} es muy específico")
        
        elif network.version == 6:
            print(f"[+] IPv6 Network: {cidr}")
            print(f"    Potential hosts: {network.num_addresses}")
            print(f"[!] Note: IPv6 scanning may be slower")

        if network.num_addresses > 65536:  # Más de /16
            print(f"[!] Advertencia: La red {cidr} contiene {network.num_addresses} direcciones, esto puede tomar mucho tiempo")
            
        return True
        
    except ValueError as e:
        error_msg = str(e).lower()
        
        if "has host bits set" in error_msg:
            print(f"[!] Error CIDR: '{cidr}' tiene bits de host configurados.")
            print(f"    Hint: Perhaps you meant '{cidr.split('/')[0]}/24'?")
        elif "expected" in error_msg and "address" in error_msg:
            print(f"[!] CIDR Error: Invalid format in '{cidr}'")
            print("    Formato correcto: X.X.X.X/Y donde X es 0-255 e Y es 0-32")
        elif "prefixlen" in error_msg:
            print(f"[!] Error CIDR: Prefijo inválido en '{cidr}'")
            print("    El prefijo debe estar entre 0-32 para IPv4")
        else:
            print(f"[!] Error CIDR: '{cidr}' no es una red válida")
            print(f"    Error detallado: {e}")
        
        return False

# --- Vulnerability Scanning System ---

class VulnerabilityPlugin:
    """Base class for vulnerability detection plugins"""
    
    def __init__(self):
        self.name = "Base Plugin"
        self.version = "1.0"
        self.description = "Base vulnerability detection plugin"
    
    async def check(self, host: str, port: int, banner: str, protocol: str = "tcp") -> dict:
        """
        Override this method to implement vulnerability checks.
        
        Args:
            host: Target host
            port: Target port
            banner: Banner information from the service
            protocol: Protocol (tcp/udp)
        
        Returns:
            Dictionary with vulnerability information
        """
        return {
            "vulnerable": False,
            "confidence": 0,
            "description": "",
            "references": [],
            "remediation": ""
        }

class VulnerabilityScanner:
    """Manager for vulnerability plugins"""
    
    def __init__(self):
        self.plugins = []
        self._load_plugins()
    
    def _load_plugins(self):
        """Carga todos los plugins disponibles"""
        self.plugins = [
            SSHWeakConfigPlugin(),
            HTTPHeadersPlugin(),
            TelnetWeakAuthPlugin(),
            FTPAnonymousPlugin(),
            # Agregar más plugins aquí
        ]
        print(f"[+] Loaded {len(self.plugins)} vulnerability plugins")
    
    async def scan(self, host: str, port: int, banner: str, protocol: str = "tcp") -> list:
        """Ejecuta todos los plugins en el host y puerto"""
        results = []
        
        for plugin in self.plugins:
            try:
                result = await plugin.check(host, port, banner, protocol)
                if result["vulnerable"]:
                    result["plugin_name"] = plugin.name
                    result["plugin_version"] = plugin.version
                    results.append(result)
                    print(f"[VULN] {plugin.name} found issue on {host}:{port}")
            except Exception as e:
                print(f"[!] Plugin {plugin.name} failed: {e}")
        
        return results

# --- Implementaciones Específicas de Plugins ---

class SSHWeakConfigPlugin(VulnerabilityPlugin):
    """Detect weak SSH configurations and known vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.name = "SSH Configuration Auditor"
        self.version = "1.1"
        self.description = "Checks for weak SSH configurations and known vulnerabilities"
    
    async def check(self, host: str, port: int, banner: str, protocol: str = "tcp") -> dict:
        if port != 22 or protocol != "tcp":
            return {"vulnerable": False, "confidence": 0}
        
        issues = []
        confidence = 0
        
        # Detectar versiones vulnerables de OpenSSH
        if "OpenSSH" in banner:
            import re
            version_match = re.search(r"OpenSSH_([0-9]\.[0-9])", banner)
            if version_match:
                version = float(version_match.group(1))
                if version < 7.0:
                    issues.append(f"Outdated OpenSSH version ({version})")
                    confidence = 80
                elif version < 8.0:
                    issues.append(f"Potentially outdated OpenSSH version ({version})")
                    confidence = 60
        
        # Detectar servicios SSH sin banner (posible indicador)
        if not banner.strip():
            issues.append("No SSH banner presented")
            confidence = max(confidence, 40)
        
        return {
            "vulnerable": len(issues) > 0,
            "confidence": confidence,
            "description": "; ".join(issues) if issues else "",
            "references": [
                "https://www.openssh.com/security.html",
                "CVE-2018-1543"
            ],
            "remediation": "Update OpenSSH to latest version and review configuration"
        }

class HTTPHeadersPlugin(VulnerabilityPlugin):
    """Check for missing security headers in HTTP services"""
    
    def __init__(self):
        super().__init__()
        self.name = "HTTP Security Headers Auditor"
        self.version = "1.0"
        self.description = "Checks for missing security headers in web servers"
    
    async def check(self, host: str, port: int, banner: str, protocol: str = "tcp") -> dict:
        web_ports = {80, 443, 8080, 8000, 8888}
        if port not in web_ports or protocol != "tcp":
            return {"vulnerable": False, "confidence": 0}
        
        # Verificar si es un servicio HTTP
        if not any(method in banner.upper() for method in ['HTTP', 'GET', 'POST', 'HEAD']):
            return {"vulnerable": False, "confidence": 0}
        
        issues = []
        missing_headers = []
        
        security_headers = {
            'Strict-Transport-Security': 'HSTS header missing',
            'X-Content-Type-Options': 'Content type options missing',
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-XSS-Protection': 'XSS protection missing',
            'Content-Security-Policy': 'Content Security Policy missing'
        }
        
        banner_upper = banner.upper()
        for header, message in security_headers.items():
            if header.upper() not in banner_upper:
                missing_headers.append(message)
        
        if missing_headers:
            issues.append(f"Missing security headers: {', '.join(missing_headers)}")
        
        # Detectar servidores web específicos con versiones conocidas vulnerables
        if 'Apache' in banner and '2.4.49' in banner:
            issues.append("Apache 2.4.49 has known path traversal vulnerability")
        
        return {
            "vulnerable": len(issues) > 0,
            "confidence": 60 if issues else 0,
            "description": "; ".join(issues),
            "references": [
                "https://owasp.org/www-project-secure-headers/",
                "https://httpd.apache.org/security/vulnerabilities_24.html"
            ],
            "remediation": "Configure missing security headers in web server configuration"
        }

class TelnetWeakAuthPlugin(VulnerabilityPlugin):
    """Detect Telnet services with weak or no authentication"""
    
    def __init__(self):
        super().__init__()
        self.name = "Telnet Security Auditor"
        self.version = "1.0"
        self.description = "Checks for Telnet services with weak authentication"
    
    async def check(self, host: str, port: int, banner: str, protocol: str = "tcp") -> dict:
        if port != 23 or protocol != "tcp":
            return {"vulnerable": False, "confidence": 0}
        
        issues = []
        
        # Telnet sin cifrado es inherentemente inseguro
        issues.append("Telnet uses unencrypted communication")
        
        # Buscar indicadores de configuración débil
        weak_indicators = [
            "login:",
            "Password:",
            "Welcome",
            "Ubuntu",
            "Debian"
        ]
        
        if any(indicator in banner for indicator in weak_indicators):
            issues.append("Default or weak authentication possible")
        
        return {
            "vulnerable": True,  # Telnet es siempre considerado vulnerable
            "confidence": 90,
            "description": "; ".join(issues),
            "references": [
                "https://tools.ietf.org/html/rfc854",
                "CVE-2011-4862"
            ],
            "remediation": "Replace Telnet with SSH for secure remote access"
        }

class FTPAnonymousPlugin(VulnerabilityPlugin):
    """Detect FTP services allowing anonymous access"""
    
    def __init__(self):
        super().__init__()
        self.name = "FTP Anonymous Access Checker"
        self.version = "1.0"
        self.description = "Checks for FTP services allowing anonymous access"
    
    async def check(self, host: str, port: int, banner: str, protocol: str = "tcp") -> dict:
        if port != 21 or protocol != "tcp":
            return {"vulnerable": False, "confidence": 0}
        
        issues = []
        
        # Buscar indicadores de FTP anónimo
        anonymous_indicators = [
            "Anonymous access granted",
            "230 Login successful",
            "vsFTPd",
            "ProFTPD"
        ]
        
        if any(indicator in banner for indicator in anonymous_indicators):
            issues.append("Anonymous FTP access可能 habilitado")
        
        # Versiones específicas vulnerables
        if "vsFTPd 2.3.4" in banner:
            issues.append("vsFTPd 2.3.4 has known backdoor vulnerability")
        
        return {
            "vulnerable": len(issues) > 0,
            "confidence": 70 if issues else 0,
            "description": "; ".join(issues),
            "references": [
                "CVE-2011-2523",  # vsFTPd backdoor
                "https://security.appspot.com/vsftpd.html"
            ],
            "remediation": "Disable anonymous access and update FTP server"
        }

# --- Threat Intelligence System ---

try:
    import aiohttp
    from urllib.parse import quote
    AIOHTTP_AVAILABLE = True
except ImportError:
    aiohttp = None
    AIOHTTP_AVAILABLE = False
    print("[!] aiohttp no está instalado. Threat intelligence limitado a servicios locales.")
    print("    Instala con: pip install aiohttp")

import asyncio
import time

class ThreatIntelligence:
    """Sistema de consulta a APIs de threat intelligence"""
    
    def __init__(self, api_keys=None, cache_ttl=3600):
        self.api_keys = api_keys or {}
        self.cache_ttl = cache_ttl
        self.cache = {}
        self.session = None
        self.enabled_services = []
        
        if not AIOHTTP_AVAILABLE:
            print("[!] Threat Intelligence: aiohttp no disponible, usando solo servicios locales")
    
    async def __aenter__(self):
        if AIOHTTP_AVAILABLE:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )
        self._check_available_services()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _check_available_services(self):
        """Verifica qué servicios están disponibles basado en las API keys y dependencias"""
        self.enabled_services = []
        
        # Servicios que no requieren aiohttp
        self.enabled_services.extend(['local_checks'])
        print("[+] Threat Intelligence: Local checks enabled")
        
        # Servicios que requieren aiohttp
        if AIOHTTP_AVAILABLE:
            if self.api_keys.get('abuseipdb'):
                self.enabled_services.append('abuseipdb')
                print("[+] Threat Intelligence: AbuseIPDB enabled")
            
            if self.api_keys.get('virustotal'):
                self.enabled_services.append('virustotal')
                print("[+] Threat Intelligence: VirusTotal enabled")
            
            # Servicios gratuitos que requieren aiohttp
            self.enabled_services.extend(['ipapi', 'threatcrowd'])
            print("[+] Threat Intelligence: IP-API and ThreatCrowd enabled")
        else:
            print("[!] Threat Intelligence: aiohttp no disponible - servicios online deshabilitados")
        
        print(f"[+] Total threat intelligence services: {len(self.enabled_services)}")
    
    def _get_cached_result(self, ip: str, service: str) -> dict:
        """Obtiene resultados cacheados"""
        cache_key = f"{service}:{ip}"
        if cache_key in self.cache:
            cached_time, data = self.cache[cache_key]
            if time.time() - cached_time < self.cache_ttl:
                return data
        return None
    
    def _set_cached_result(self, ip: str, service: str, data: dict):
        """Almacena resultados en cache"""
        cache_key = f"{service}:{ip}"
        self.cache[cache_key] = (time.time(), data)
    
    async def check_ip(self, ip: str) -> dict:
        """
        Consulta todas las fuentes de threat intelligence para una IP
        """
        if not self.enabled_services:
            return {"error": "No threat intelligence services configured"}
        
        results = {
            "ip": ip,
            "services_queried": [],
            "risk_score": 0,
            "categories": [],
            "details": {}
        }
        
        # Consultar cada servicio habilitado
        tasks = []
        for service in self.enabled_services:
            tasks.append(self._query_service(service, ip))
        
        # Ejecutar consultas en paralelo (si hay aiohttp) o secuencialmente
        if AIOHTTP_AVAILABLE:
            service_results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # Modo secuencial para cuando no hay aiohttp
            service_results = []
            for task in tasks:
                try:
                    result = await task
                    service_results.append(result)
                except Exception as e:
                    service_results.append(e)
        
        # Procesar resultados
        for service, result in zip(self.enabled_services, service_results):
            if isinstance(result, Exception):
                results["details"][service] = {"error": str(result)}
                continue
            
            results["services_queried"].append(service)
            results["details"][service] = result
            
            # Calcular puntaje de riesgo basado en los resultados
            risk_info = self._calculate_risk_score(service, result)
            results["risk_score"] = max(results["risk_score"], risk_info["score"])
            results["categories"].extend(risk_info["categories"])
        
        # Eliminar categorías duplicadas
        results["categories"] = list(set(results["categories"]))
        
        return results
    
    async def _query_service(self, service: str, ip: str) -> dict:
        """Consulta un servicio específico de threat intelligence"""
        # Verificar cache primero
        cached = self._get_cached_result(ip, service)
        if cached:
            return cached
        
        try:
            if service == 'abuseipdb':
                result = await self._query_abuseipdb(ip)
            elif service == 'virustotal':
                result = await self._query_virustotal(ip)
            elif service == 'ipapi':
                result = await self._query_ipapi(ip)
            elif service == 'threatcrowd':
                result = await self._query_threatcrowd(ip)
            elif service == 'local_checks':
                result = await self._local_checks(ip)
            else:
                result = {"error": f"Unknown service: {service}"}
            
            # Almacenar en cache
            if result and "error" not in result:
                self._set_cached_result(ip, service, result)
            
            return result
            
        except Exception as e:
            return {"error": str(e)}
    
    async def _query_abuseipdb(self, ip: str) -> dict:
        """Consulta AbuseIPDB API"""
        if not AIOHTTP_AVAILABLE:
            return {"error": "aiohttp not available"}
        
        if not self.api_keys.get('abuseipdb'):
            return {"error": "No API key configured"}
        
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Key': self.api_keys['abuseipdb'],
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        try:
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data', {})
                else:
                    return {"error": f"HTTP {response.status}: {await response.text()}"}
        except Exception as e:
            return {"error": str(e)}
    
    async def _query_virustotal(self, ip: str) -> dict:
        """Consulta VirusTotal API"""
        if not AIOHTTP_AVAILABLE:
            return {"error": "aiohttp not available"}
        
        if not self.api_keys.get('virustotal'):
            return {"error": "No API key configured"}
        
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        headers = {
            'x-apikey': self.api_keys['virustotal']
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data', {})
                elif response.status == 404:
                    return {"error": "IP not found in VirusTotal"}
                else:
                    return {"error": f"HTTP {response.status}"}
        except Exception as e:
            return {"error": str(e)}
    
    async def _query_ipapi(self, ip: str) -> dict:
        """Consulta IP-API.com (geolocalización gratuita)"""
        if not AIOHTTP_AVAILABLE:
            return {"error": "aiohttp not available"}
        
        url = f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query'
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('status') == 'success':
                        return data
                    else:
                        return {"error": data.get('message', 'Unknown error')}
                else:
                    return {"error": f"HTTP {response.status}"}
        except Exception as e:
            return {"error": str(e)}
    
    async def _query_threatcrowd(self, ip: str) -> dict:
        """Consulta ThreatCrowd API"""
        if not AIOHTTP_AVAILABLE:
            return {"error": "aiohttp not available"}
        
        url = f'https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip}'
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('response_code') == '1':
                        return data
                    else:
                        return {"error": "IP not found in ThreatCrowd"}
                else:
                    return {"error": f"HTTP {response.status}"}
        except Exception as e:
            return {"error": str(e)}
    
    async def _local_checks(self, ip: str) -> dict:
        """Chequeos locales sin necesidad de API externa"""
        result = {
            "local_analysis": {
                "ip_type": self._classify_ip_type(ip),
                "private_network": self._is_private_ip(ip),
                "reserved_ip": self._is_reserved_ip(ip),
                "risk_indicators": []
            }
        }
        
        # Análisis básico de la IP
        if self._is_private_ip(ip):
            result["local_analysis"]["risk_indicators"].append("Private IP address")
        
        if self._is_reserved_ip(ip):
            result["local_analysis"]["risk_indicators"].append("Reserved IP address")
        
        # IPs locales especiales
        if ip in ["127.0.0.1", "::1", "localhost"]:
            result["local_analysis"]["risk_indicators"].append("Loopback address")
        
        # Rango de multicast
        if self._is_multicast_ip(ip):
            result["local_analysis"]["risk_indicators"].append("Multicast address")
        
        return result
    
    def _classify_ip_type(self, ip: str) -> str:
        """Clasifica el tipo de IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return "private"
            elif ip_obj.is_loopback:
                return "loopback"
            elif ip_obj.is_multicast:
                return "multicast"
            elif ip_obj.is_global:
                return "public"
            else:
                return "unknown"
        except:
            return "invalid"
    
    def _is_private_ip(self, ip: str) -> bool:
        """Verifica si es una IP privada"""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False
    
    def _is_reserved_ip(self, ip: str) -> bool:
        """Verifica si está en rangos reservados"""
        reserved_ranges = [
            "0.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "240.0.0.0/4"
        ]
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in reserved_ranges:
                if ip_obj in ipaddress.ip_network(range_str, strict=False):
                    return True
            return False
        except:
            return False
    
    def _is_multicast_ip(self, ip: str) -> bool:
        """Verifica si es una IP multicast"""
        try:
            return ipaddress.ip_address(ip).is_multicast
        except:
            return False
    
    def _calculate_risk_score(self, service: str, data: dict) -> dict:
        """Calcula puntaje de riesgo basado en datos del servicio"""
        score = 0
        categories = []
        
        if service == 'abuseipdb':
            abuse_score = data.get('abuseConfidenceScore', 0)
            score = abuse_score / 10  # Convertir a escala 0-10
            if abuse_score > 50:
                categories.append("malicious")
            if data.get('totalReports', 0) > 5:
                categories.append("reported")
            if data.get('isWhitelisted', False):
                score = max(0, score - 5)
                categories.append("whitelisted")
        
        elif service == 'virustotal':
            stats = data.get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            if total > 0:
                score = (malicious / total) * 10
            if malicious > 0:
                categories.append("malicious")
        
        elif service == 'threatcrowd':
            votes = data.get('votes', {})
            malicious = votes.get('malicious', 0)
            total = malicious + votes.get('harmless', 0)
            if total > 0:
                score = (malicious / total) * 10
            if malicious > 0:
                categories.append("malicious")
        
        elif service == 'local_checks':
            local_data = data.get('local_analysis', {})
            risk_indicators = local_data.get('risk_indicators', [])
            
            # Puntaje basado en indicadores locales
            if "Private IP address" in risk_indicators:
                score = 1  # Riesgo bajo para IPs privadas
                categories.append("private")
            if "Reserved IP address" in risk_indicators:
                score = 2
                categories.append("reserved")
            if "Multicast address" in risk_indicators:
                score = 3
                categories.append("multicast")
        
        return {
            "score": min(10, score),  # Máximo 10
            "categories": categories
        }

class ThreatIntelligenceManager:
    """Gestor para consultas de threat intelligence en lote"""
    
    def __init__(self, api_keys=None, max_concurrent=5):
        self.api_keys = api_keys
        self.max_concurrent = max_concurrent
        self.results = {}
    
    async def scan_ips(self, ips: list) -> dict:
        """Escanea múltiples IPs con límite de concurrencia"""
        if not AIOHTTP_AVAILABLE:
            # Modo local sin concurrencia
            print(f"[+] Threat Intelligence: Running local checks for {len(ips)} IPs")
            async with ThreatIntelligence(api_keys=self.api_keys) as ti:
                for ip in set(ips):
                    self.results[ip] = await ti.check_ip(ip)
            return self.results
        
        # Modo con concurrencia (cuando aiohttp está disponible)
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def scan_with_semaphore(ip):
            async with semaphore:
                async with ThreatIntelligence(api_keys=self.api_keys) as ti:
                    result = await ti.check_ip(ip)
                    return ip, result
        
        tasks = [scan_with_semaphore(ip) for ip in set(ips)]  # IPs únicas
        completed = 0
        total = len(tasks)
        
        print(f"[+] Starting threat intelligence scan for {total} unique IPs...")
        
        for task in asyncio.as_completed(tasks):
            ip, result = await task
            self.results[ip] = result
            completed += 1
            print(f"\r[+] Threat Intel: {completed}/{total} IPs processed", end="", flush=True)
        
        print(f"\n[+] Threat intelligence scan completed")
        return self.results
    
    def get_high_risk_ips(self, threshold=5) -> list:
        """Obtiene IPs con alto riesgo"""
        high_risk = []
        for ip, data in self.results.items():
            if data.get('risk_score', 0) >= threshold:
                high_risk.append({
                    'ip': ip,
                    'risk_score': data['risk_score'],
                    'categories': data.get('categories', []),
                    'services': data.get('services_queried', [])
                })
        return high_risk

def get_mac_address(ip: str) -> str:
    try:
        if platform.system().lower() == "windows":
            cmd = ["arp", "-a", ip]
        else:
            cmd = ["arp", "-n", ip]
        output = subprocess.check_output(cmd, stderr = subprocess.DEVNULL, text = True)

        # Look for typical MAC address patterns
        match = re.search(r"([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}", output)
        return match.group(0).lower() if match else "unknown"    
    except Exception:
        return "unknown"

# --- Ping funcionality ---
async def ping_host(host: str, timeout: float =1.0) -> bool:
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), host]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout = asyncio.subprocess.PIPE,
            stderr = asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout + 1)

        return process.returncode == 0

    except (asyncio.TimeoutError, subprocess.SubprocessError, OSError):
        return False

async def ping_hosts_parallel(hosts: List[str], concurrency: int = 100, timeout: float = 1.0) -> Set[tuple]:
    active_hosts = set()
    semaphore = asyncio.Semaphore(concurrency)
    
    async def ping_with_semaphore(host):
        async with semaphore:
            if await ping_host(host, timeout):
                return host
        return None
    
    print(f"[+] Scanning {len(hosts)} hosts with ping...")

    tasks = [ping_with_semaphore(host) for host in hosts]

    for completed in asyncio.as_completed(tasks):
        result = await completed
        if result:
            mac = get_mac_address(result)
            active_hosts.add((result, mac))
            print(f"\r[+] Active host: {result} - MAC: {mac}", end = "", flush = True)

    
    print(f"\n[+] Ping scan completed: {len(active_hosts)} hosts active")
    return active_hosts

# --- Scanning core ---
async def probe_banner(reader, writer, host, port, timeout):
    try:
        if port in (80,8080,8000,8888):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            await writer.drain()
        # attempt to read
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        return data.decode(errors='ignore').strip()
    except Exception:
        return ""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def scan_port(host, port, timeout, semaphore: Optional[asyncio.Semaphore] = None, mac: Optional[str] = "unknown", protocol: str = "tcp",
                    vuln_scanner: Optional[VulnerabilityScanner] = None) -> Dict:
    result = {
        "host": host,
        "mac": mac,
        "port": port,
        "protocol": protocol,
        "status": "closed",
        "banner": "",
        "severity": "info",
        "category": "",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "vulnerabilities": []
    }
    try:
        if protocol.lower() == "tcp":
            connect_coro = asyncio.open_connection(host, port)
            if semaphore:
                async with semaphore:
                    reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)
            else:
                reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)

            result["status"] = "open"
            banner = await probe_banner(reader, writer, host, port, timeout=1.0)
            result["banner"] = banner

            if vuln_scanner and banner:
                try:
                    vuln_results = await vuln_scanner.scan(host, port, banner, protocol)
                    result["vulnerabilities"] = vuln_results

                    if vuln_results and result["severity"] in ["info", "medium"]:
                        result["severity"] = "high"
                except Exception as e:
                    print(f"[!] Vulnerability scan failed for {host}: {port}: {e}")

        elif protocol.lower() == "udp":
            try:
                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                
                # Enviar datos de prueba (dependiendo del puerto)
                probe_data = b""
                if port == 53:  # DNS
                    probe_data = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01"
                elif port == 123:  # NTP
                    probe_data = b"\x1b" + 47 * b"\x00"
                
                await loop.sock_sendto(sock, probe_data, (host, port))
                
                try:
                    # Intentar recibir respuesta
                    data, addr = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 1024), 
                        timeout=timeout
                    )
                    result["status"] = "open"
                    result["banner"] = data.hex()[:100]  # Guardar primeros bytes en hex
                except asyncio.TimeoutError:
                    # Sin respuesta podría significar open|filtered
                    result["status"] = "open|filtered"
                    
            except ConnectionRefusedError:
                result["status"] = "closed"
            except Exception as e:
                result["status"] = f"error: {e}"
            finally:
                sock.close()
        pass

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        pass
    except Exception as e:
        result["status"] = f"error: {e}"

    if result["status"] == "open":
        # Port category classification (adjust according to SOC policies)
        if port in MALICIOUS:
            result["category"] = "malicious"
            result["severity"] = "critical"
        elif port in CRITICAL_PORTS:
            result["category"] = "critical_common"
            result["severity"] = "critical"
        elif port in HIGH_PORTS:
            result["category"] = "high_common"
            result["severity"] = "high"
        elif port in PEER_TO_PEER:
            result["category"] = "peer_to_peer"
            result["severity"] = "high"
        elif port in GAMING:
            result["category"] = "gaming"
            result["severity"] = "info"
        elif port in CHAT:
            result["category"] = "chat"
            result["severity"] = "medium"
        elif port in STREAMING:
            result["category"] = "streaming"
            result["severity"] = "medium"
        else:
            result["category"] = "other"
            result["severity"] = "medium"

    return result

async def _progress_updater(total: int, progress_q: asyncio.Queue,label: str = "", width: int = 40):
    if total <= 0:
        return
    completed = 0
    while True:
        item = await progress_q.get()
        if item is None:                    
            progress_q.task_done()
            break
        completed += int(item)
        pct = completed / total
        filled = int(pct * width)
        bar = '█' * filled + '-' * (width - filled)
        prefix = f"[{label}] " if label else ""
        print(f"\r{prefix}Progress: |{bar}| {completed}/{total} ({pct*100:.2f}%)", end='', flush=True)
        progress_q.task_done()
    print()

# scan_hosts with workers and progress queue
async def scan_hosts(cidr: str, ports: List[int], concurrency=200, timeout=2, show_progress=True, ping_first=True, ping_concurrency=100, ping_timeout=1.0, protocol="tcp",
                     vuln_scanner: Optional[VulnerabilityScanner] = None):
    
    net = ipaddress.ip_network(cidr, strict=False)
    all_hosts = [str(h) for h in net.hosts()]

    host_macs = {}

    #--- Fase 1: Ping ---
    if ping_first:
        active_hosts_set = await ping_hosts_parallel(all_hosts, concurrency=ping_concurrency, timeout=ping_timeout)
        hosts = [host for host, mac in active_hosts_set]
        host_macs = {host: mac for host, mac in active_hosts_set}
        if not hosts:
            print("[+] No active hosts found with ping.")
            return []
    else:
        hosts = all_hosts
        host_macs = {}
    
    print(f"[+] Scanning {len(hosts)} active hosts on {len(ports)} ports...")

    total_tasks = len(hosts) * len(ports)
    job_q: asyncio.Queue = asyncio.Queue()

    for host in hosts:
        mac = host_macs.get(host, "unknown")
        for port in ports:
            job_q.put_nowait((host, port, mac))

    results: List[Dict] = []
    progress_q: asyncio.Queue = asyncio.Queue()

    async def worker():
        while True:
            try:
                host, port, mac = job_q.get_nowait()
            except asyncio.QueueEmpty:
                break
            res = await scan_port(host, port, timeout, mac = mac, protocol=protocol, vuln_scanner = vuln_scanner)
            results.append(res)
            if show_progress:
                await progress_q.put(1)
            job_q.task_done()

    n_workers = min(concurrency, total_tasks) if total_tasks > 0 else 0
    workers = [asyncio.create_task(worker()) for _ in range(n_workers)]

    progress_task = None
    if show_progress and total_tasks > 0:
        label = f"{protocol.upper()}"
        progress_task = asyncio.create_task(_progress_updater(total_tasks, progress_q, label=label))

    if workers:
        await asyncio.gather(*workers)

    if show_progress and progress_task:
        await progress_q.put(None)
        await progress_task
    return results

# --- Exports: TXT/JSON/CSV/XHTML ---

def save_json(results, filename="scan_results.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

def save_csv(results, filename="scan_results.csv"):
    keys = ["host", "mac", "port", "status", "severity", "banner", "timestamp", "vulnerabilities_count", "vulnerabilities_info",
            "ti_risk_score", "ti_categories", "ti_services"]
    
    with open(filename, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in results:
            vuln_count = len(r.get("vulnerabilities", []))
            vuln_info = "; ".join([
                f"{v.get('plugin_name', 'Unknown')}({v.get('confidence', 0)}%)" 
                for v in r.get("vulnerabilities", [])
            ])
        # Campos de threat intelligence
        ti_data = r.get("threat_intelligence", {})
        ti_risk = ti_data.get("risk_score", 0)
        ti_categories = ", ".join(ti_data.get("categories", []))
        ti_services = ", ".join(ti_data.get("services_queried", []))

        row = {
            "host": r.get("host", ""),
            "mac": r.get("mac", ""),
            "port": r.get("port", ""),
            "status": r.get("status", ""),
            "severity": r.get("severity", ""),
            "banner": r.get("banner", "")[:500],  # Limitar tamaño
            "timestamp": r.get("timestamp", ""),
            "vulnerabilities_count": vuln_count,
            "vulnerabilities_info": vuln_info,
            "ti_risk_score": ti_risk,
            "ti_categories": ti_categories,
            "ti_services": ti_services
        }
        writer.writerow(row)

def save_html(results, filename="scan_report.html"):
    """
    Generates an XHTML report with interactive charts and statistics.
    The resulting XHTML includes:
        - Count by severity (bar chart)
        - Distribution by category (pie chart)
        - Top 10 open ports (horizontal bar chart)
        - Table of details by host
    """

    # Group by host and calculate statistics
    hosts = {}
    for r in results:
        if r["host"] not in hosts:
            hosts[r["host"]] = []
        hosts[r["host"]].append(r)

    # Aggregate statistics
    severity_counts = {}
    category_counts = {}
    port_counts = {}
    total_open = 0
    vuln_stats = {}
    total_vulns = 0
    ti_stats = {
        "ips_checked": 0,
        "high_risk_ips": 0,
        "risk_distribution": {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 0, 10: 0}
    }

    for r in results:
        ti_data = r.get("threat_inteligence")
        sev = r.get("severity", "info")
        cat = r.get("category", "other")
        port = r.get("port")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        category_counts[cat] = category_counts.get(cat, 0) + 1
        port_counts[port] = port_counts.get(port, 0) + 1
        if r.get("status") == "open":
            total_open -= -1
        for vuln in r.get("vulnerabilities", []):
            plugin_name = vuln.get("plugin_name", "Unknown")
            vuln_stats[plugin_name] = vuln_stats.get(plugin_name, 0) + 1
            total_vulns -= -1
        if ti_data:
            ti_stats["ips_checked"] += 1
            risk_score = ti_data.get("risk_score", 0)
            ti_stats["risk_distribution"][int(risk_score)] += 1
            if risk_score >= 7:
                ti_stats["high_risk_ips"] += 1
    
    # Top ports
    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ports_labels = [str(p[0]) for p in top_ports]
    top_ports_values = [p[1] for p in top_ports]

    now = datetime.utcnow().isoformat() + "Z"

    data_blob = {
        "generated_at": now,
        "summary": {
            "total_events": len(results),
            "total_open": total_open,
            "total_vulnerabilities": total_vulns,
            "by_severity": severity_counts,
            "by_category": category_counts,
            "vulnerability_stats": vuln_stats,
            "threat_intelligence": ti_stats
        },
        "top_ports": {"labels": top_ports_labels, "values": top_ports_values},
        "hosts": hosts
    }            

    # Build XHTML
    xhtml = f"""
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
        <head>
            <meta name="viewport" content="width=device-width,initial-scale=1"/>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <title>Scan Report - {now}</title>
            <style>
                body{{ font-family: Arial, Helvetica, sans-serif; margin: 20px; }}
                .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: start; }}
                .card {{ padding: 12px; border: 1px solid #ddd; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.03); }}
                canvas {{ max-width: 100%; height: 300px; }}
                table{{ border-collapse:collapse;width:100%; }} 
                th,td{{ border:1px solid #eee; padding: 6px; text-align: left; font-size: 13px; }} 
                th {{ background: #f8f8f8; }}
                .small {{ font-size: 13px; color: #555; }}
                .crit{{ background:#ffdddd; }} 
            </style>
        </head>
        <body>
            <h1>Scan Report</h1>
            <p class="small">Generated: {now} - Events: {len(results)} - Open Ports: {total_open}</p>

            <div class="grid">
                <div class="card">
                    <h3>By severity</h3>
                    <canvas id="severityChart"></canvas>
                </div>
                <div class="card">
                    <h3>By category:</h3>
                    <canvas id="categoryChart"></canvas>
                </div>
                <div class="card">
                    <h3>Top {len(top_ports)}</h3>
                    <canvas id="topPortsChart"></canvas>
                </div>
                <div class="card">
                    <h3>Quick Summary:</h3>
                    <ul id="quickSummary"></ul>
                </div>
            </div>

            <h2 style="margin-top:24px">Details by host</h2>
            <div class="card">
                <table id="hostsTable">
                    <thead><tr><th>Host</th><th>MAC Address</th><th>Open ports</th><th>Critical?</th><th>Details</th></tr></thead>
                    <tbody>
    """
    
    for host, entries in hosts.items():
        open_entries = [e for e in entries if e.get("status") == "open"]
        open_count = len(open_entries)
        critical = any(e.get("severity") == "critical" for e in open_entries)
        details = [f"{e.get('port')}({e.get('severity')})" for e in open_entries]
        mac = entries[0].get("mac", "unknown")
        xhtml += f"<tr><td>{host}</td><td>{mac}</td><td>{open_count}</td><td>{'Yes' if critical else 'No'}</td><td>{', '.join(details)}</td></tr>"
    
    
    xhtml += f"""
                    </tbody>
                </table>
            </div>

            <h2 style="margin-top:24px">Vulnerability Findings</h2>
            <div class = "card">
                <p>Total vulnerabilities found: <strong>{total_vulns}</strong></p>
                <table id = "vulnTable">
                    <thead><tr><th>Host</th><th>Port</th><th>Pluggin</th><th>Confidance</th><th>Description</th></tr></thead>
                    <tbody>
            """
    
    for host, entries in hosts.items():
        for entry in entries:
            for vuln in entry.get("vulnerabilities", []):
                xhtml += f"""
                    <tr>
                        <td>{host}</td>
                        <td>{entry.get('port')}</td>
                        <td>{vuln.get('plugin_name', 'Unknown')}</td>
                        <td>{vuln.get('confidence', 0)}%</td>
                        <td>{vuln.get('description', '')}</td>
                    </tr>
                """
    
    if total_vulns == 0:
        xhtml += "<tr><td colspan='5'>No vulnerabilities detected</td></tr>"
    
    xhtml += """
                    </tbody>
                </table>
            </div>
    """

    xhtml += f"""
            <h2 style="margin-top:24px">Threat Intelligence</h2>
            <div class="card">
                <p>IPs checked: <strong>{ti_stats['ips_checked']}</strong></p>
                <p>High-risk IPs (score ≥7): <strong>{ti_stats['high_risk_ips']}</strong></p>
                <canvas id="threatChart" width="400" height="200"></canvas>
            </div>

            <div class="card">
                <h3>Threat Intelligence Details</h3>
                <table id="threatTable">
                    <thead>
                        <tr>
                            <th>Host</th>
                            <th>Port</th>
                            <th>Risk Score</th>
                            <th>Categories</th>
                            <th>Sources</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                """
    for host, entries in hosts.items():
        for entry in entries:
            ti_data = entry.get("threat_intelligence")
            if ti_data:
                risk_score = ti_data.get("risk_score", 0)
                risk_class = "crit" if risk_score >= 7 else ""
                categories = ", ".join(ti_data.get("categories", []))
                services = ", ".join(ti_data.get("services_queried", []))
                
                xhtml += f"""
                    <tr class="{risk_class}">
                        <td>{host}</td>
                        <td>{entry.get('port')}</td>
                        <td><strong>{risk_score}/10</strong></td>
                        <td>{categories}</td>
                        <td>{services}</td>
                        <td>
                            <button onclick="showThreatDetails('{host}', {entry.get('port')})">
                                View Details
                            </button>
                        </td>
                    </tr>
                """
    if ti_stats['ips_checked'] == 0:
        xhtml += "<tr><td colspan='6'>No threat intelligence data available</td></tr>"
    
    xhtml += """
                    </tbody>
                </table>
            </div>
    """
    xhtml += f"""
            <script type="text/javascript">
                'use strict';
                const scanData = {json.dumps(data_blob, ensure_ascii=False)};

                // Prepare data for severity chart
                const severityLabels = Object.keys(scanData.summary.by_severity);
                const severityValues = Object.values(scanData.summary.by_severity);

                const categoryLabels = Object.keys(scanData.summary.by_category);
                const categoryValues = Object.values(scanData.summary.by_category);

                """
    xhtml += """
                let chartInstances = {};

                function createOrUpdateChart(chartId, chartType, data, options) {
                    const ctx = document.getElementById(chartId).getContext('2d');
                    if (chartInstances[chartId]) {
                        chartInstances[chartId].destroy();
                    }
                    chartInstances[chartId] = new Chart(ctx, {
                        type: chartType,
                        data: data,
                        options: options
                    });
                }

                // Severity bar chart
                createOrUpdateChart('severityChart', 'bar', {
                    labels: Object.keys(scanData.summary.by_severity),
                    datasets: [{
                        label: 'Events',
                        data: Object.values(scanData.summary.by_severity),
                        backgroundColor: ['#ff6384', '#36a2eb', '#ffce56', '#4bc0c0']
                    }]
                }, { responsive: true, maintainAspectRatio: true });

                // Category doughnut chart
                createOrUpdateChart('categoryChart', 'doughnut', {
                    labels: Object.keys(scanData.summary.by_category),
                    datasets: [{
                        data: Object.values(scanData.summary.by_category),
                        backgroundColor: [
                            '#ff6384', '#36a2eb', '#ffce56', '#4bc0c0', '#9966ff',
                            '#ff9f40', '#ff6384', '#c9cbcf', '#4bc0c0', '#ff6384'
                        ]
                    }]
                }, { responsive: true, maintainAspectRatio: true });

                // Top ports horizontal bar
                createOrUpdateChart('topPortsChart', 'bar', {
                    labels: scanData.top_ports.labels,
                    datasets: [{
                        label: 'Occurrences',
                        data: scanData.top_ports.values,
                        backgroundColor: '#36a2eb'
                    }]
                }, { indexAxis: 'y', responsive: true, maintainAspectRatio: true });

                // Quick summary
                const qs = document.getElementById('quickSummary');
                qs.innerHTML = `
                <li>Total Events: ${scanData.summary.total_events}</li>
                <li>Open Ports: ${scanData.summary.total_open}</li>
                <li>Most frequent severity: ${severityLabels[severityValues.indexOf(Math.max(...severityValues))] || 'n/a'}</li>`;

                // Threat Intelligence Chart
                const threatCtx = document.getElementById('threatChart').getContext('2d');
                const threatChart = new Chart(threatCtx, {
                    type: 'bar',
                    data: {
                        labels: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
                        datasets: [{
                            label: 'IP Count by Risk Score',
                            data: Object.values(scanData.threat_intelligence.risk_distribution),
                            backgroundColor: [
                                '#4bc0c0', '#4bc0c0', '#4bc0c0', '#4bc0c0', '#ffce56',
                                '#ffce56', '#ff9f40', '#ff6384', '#ff6384', '#ff6384', '#ff6384'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });

                function showThreatDetails(host, port) {
                    // Buscar los datos completos de threat intelligence
                    const hostData = scanData.hosts[host];
                    const entry = hostData.find(e => e.port === port);
                    const tiData = entry.threat_intelligence;
                    
                    let detailsHtml = '<h3>Threat Intelligence Details for ' + host + ':' + port + '</h3>';
                    detailsHtml += '<p><strong>Overall Risk Score: ' + tiData.risk_score + '/10</strong></p>';
                    detailsHtml += '<p>Categories: ' + (tiData.categories.join(', ') || 'None') + '</p>';
                    
                    detailsHtml += '<h4>Service Details:</h4>';
                    for (const [service, data] of Object.entries(tiData.details)) {
                        detailsHtml += '<div style="margin-bottom: 15px; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">';
                        detailsHtml += '<strong>' + service.toUpperCase() + ':</strong><br>';
                        
                        if (data.error) {
                            detailsHtml += 'Error: ' + data.error;
                        } else {
                            detailsHtml += '<pre style="white-space: pre-wrap; font-size: 12px;">' + 
                                JSON.stringify(data, null, 2) + '</pre>';
                        }
                        detailsHtml += '</div>';
                    }
                    
                    // Mostrar en un modal o nueva ventana
                    const newWindow = window.open('', '_blank');
                    newWindow.document.write(`
                        <html>
                            <head><title>Threat Details - ${host}:${port}</title></head>
                            <body style="font-family: Arial; padding: 20px;">
                                ${detailsHtml}
                                <br><br>
                                <button onclick="window.close()">Close</button>
                            </body>
                        </html>
                    `);
                }

                function downloadJSON() {
                    const a = document.createElement('a');
                    const file = new Blob([JSON.stringify(scanData, null, 2)], {type: 'application/json'});
                    a.href = URL.createObjectURL(file);
                    a.download = 'scan_summary.json';
                    a.click();
                }

            </script>
        </body>
    </html>
    """
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(xhtml)
    print(f"[+] Interactive HTML exported to: {filename}")

def save_txt(results, filename="scan_results.txt", layout="detailed"):
    """
    Generates a plain text summary.
    Layout: 'detailed' (default) or 'compact'.
    - Detailed: Summary by host + details by port (more readable for SOCs).
    - Compact: One line per event (useful for quick ingestion or review).
    """
    hosts = {}
    for r in results:
        hosts.setdefault(r["host"], []).append(r)
    now = datetime.utcnow().isoformat() + "Z"

    if layout == "compact":
        lines = []
        lines.append(f"Scan Report (compact) - {now}")
        for host, entries in hosts.items():
            for e in entries:
                banner = e.get('banner','').strip().replace('\n', ' | ')[:400] 
                lines.append(f"{host}:{e['port']} {e['status']} {e['severity']} {banner}")
    else:
        # detailed
        lines = []
        lines.append(f"Scan Report - {now}")
        lines.append("Resumen por host:")
        for host, entries in hosts.items():
            open_ports = [str(e["port"]) for e in entries if e["status"] == "open"]
            critical = any(e["severity"] == "critical" for e in entries)
            lines.append(f"Host: {host}")
            lines.append(f"  Open Ports ({len(open_ports)}): {', '.join(open_ports) if open_ports else 'None'}")
            lines.append(f"  Critical: {'Yes' if critical else 'No'}")
            lines.append("")
        lines.append("Details:")
        for host, entries in hosts.items():
            lines.append(f"== {host} ==")
            for e in entries:
                lines.append(f"Port: {e['port']}  Status: {e['status']}  Severity: {e['severity']}  Timestamp: {e['timestamp']}")
                banner = e.get('banner','').strip().replace('\n', ' | ')[:800]
                if banner:
                    lines.append(f"  Banner: {banner}")
            lines.append("")

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(''.join(lines))
    print(f"[+] TXT exported to: {filename}")


def parse_ports(ports_str: str):
    if not ports_str:
        return DEFAULT_PORTS
    parts = [p.strip() for p in ports_str.split(",")]
    out = set()
    for p in parts:
        if "-" in p:
            a, b = p.split("-")
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(p))
    return sorted(out)

# --- CLI / Main ---

def severity_rank(label: Optional[str]) -> int:
    #Converts severity label to an integer for comparison.
    m = {"info": 0, "medium": 1, "high": 2, "critical": 3}
    if not label:
        return 0
    return m.get(label.lower(), 0)

# --- ECS / CEF conversion and export ---
def ecs_severity_value(label: str) -> int:
    m = {"critical": 90, "high": 70, "medium": 50, "info": 20}
    return m.get(label.lower(), 20)

def cef_severity_value(label: str) -> int:
    m = {"critical": 10, "high": 7, "medium": 5, "info": 2}
    return m.get(label.lower(), 2)

def _escape_cef_value(s: str) -> str:
    if s is None:
        return ""
    s = str(s).replace("\\", "\\\\")
    s = s.replace("\n", "\\n").replace("\r", "\\n")
    s = s.replace("|", "\\|").replace("=", "\\=")
    return s

def service_from_port(port: int) -> Optional[str]:
    try:
        return socket.getservbyport(port)
    except Exception:
        return None

def result_to_ecs_event(r: Dict, scanner_ip: Optional[str] = None) -> Dict:
    ts = r.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
    dest_ip = r.get("host")
    dest_port = r.get("port")
    sev_label = r.get("severity", "info")
    banner = r.get("banner", "")

    ecs = {
        "@timestamp": ts,
        "event": {
            "action": "port_scan",
            "category": ["network"],
            "kind": "event",
            "dataset": "lan_portscanner.scan",
            "module": "lan_portscanner",
            "severity": ecs_severity_value(sev_label),
            "outcome": "success" if r.get("status") == "open" else "failure",
        },
        "agent": {"type": "script", "name": "lan_portscanner", "version": "1.0"},
        "destination": {"ip": dest_ip, "port": dest_port},
        "network": {"transport": "tcp"},
        "observer": {"hostname": socket.gethostname()},
        "message": f"Port {dest_port} on {dest_ip} is {r.get('status')} - {banner[:400]}",
        "labels": {"scanner_severity_label": sev_label},
        "service": {"name": service_from_port(dest_port) or ""},
        "source": {"ip": scanner_ip or "unknown"},
        "lan_portscanner": r
    }
    return ecs

def result_to_cef_line(r: Dict, scanner_ip: Optional[str] = None, device_vendor="MyCompany", device_product="PortScanner", device_version="1.0", signature_id=1001) -> str:
    ts = r.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
    dst = r.get("host")
    dpt = r.get("port")
    src = scanner_ip or "unknown"
    spt = ""
    name = f"Port Scan {dst}:{dpt}"
    cef_sev = cef_severity_value(r.get("severity", "info"))
    banner = r.get("banner", "")

    header = f"CEF:0|{_escape_cef_value(device_vendor)}|{_escape_cef_value(device_product)}|{_escape_cef_value(device_version)}|{signature_id}|{_escape_cef_value(name)}|{cef_sev}|"

    ext_parts = {
        "src": src,
        "dst": dst,
        "spt": spt,
        "dpt": dpt,
        "msg": banner[:1000],
        "rt": ts,
        "cs1": r.get("status"),
        "cs1Label": "status",
        "cs2": r.get("severity"),
        "cs2Label": "scanner_severity",
    }
    ext = " ".join(f"{k}={_escape_cef_value(v)}" for k, v in ext_parts.items() if v is not None and v != "")
    return header + ext

def export_ecs_ndjson(results: List[Dict], out_path="ecs_events.ndjson", scanner_ip: Optional[str] = None):
    with open(out_path, "w", encoding="utf-8") as f:
        for r in results:
            ecs_event = result_to_ecs_event(r, scanner_ip=scanner_ip)
            f.write(json.dumps(ecs_event, ensure_ascii=False) + "\n")
    print(f"[+] ECS NDJSON exported to: {out_path}")

def export_cef_file(results: List[Dict], out_path="scan_results.cef", scanner_ip: Optional[str] = None, device_vendor="MyCompany", device_product="PortScanner", device_version="1.0"):
    with open(out_path, "w", encoding="utf-8") as f:
        for r in results:
            cef_line = result_to_cef_line(r, scanner_ip=scanner_ip, device_vendor=device_vendor, device_product=device_product, device_version=device_version)
            f.write(cef_line + "\n")
    print(f"[+] CEF exported to: {out_path}")

def save_xml(results, filename="scan_results.xml"):
    root = ET.Element("scan_report")

    metadata = ET.SubElement(root, "metadata")
    ET.SubElement(metadata, "generated_at").text = datetime.utcnow().isoformat() + "Z"
    ET.SubElement(metadata, "total_results").text = str(len(results))

    results_elem = ET.SubElement(root, "results")
    for result in results:
        scan_elem = ET.SubElement(results_elem, "scan")
        for key, value in result.items():
            if isinstance(value, (str , int)):
                ET.SubElement(scan_elem, key).text = str(value)
            elif value is None:
                ET.SubElement(scan_elem, key).text = ""
    
    tree = ET.ElementTree(root)
    ET.indent(tree, space=" ", level=0)

    with open(filename, "w", encoding="utf-8") as f:
        tree.write(filename, encoding="unicode", xml_declaration=True)
        print(f"[+] XML exported to: {filename}")

'''
def save_yaml(results, filename="scan_results.yaml"):

    if not YAML_AVAILABLE:
        print(f"[!] YAML export skipped: PyYAML not installed. Install with: pip install PyYAML")
        return
    
    # Preparar datos para YAML
    yaml_data = {
        "metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_results": len(results)
        },
        "results": results
    }
    
    with open(filename, "w", encoding="utf-8") as f:
        yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True, indent=2)
    print(f"[+] YAML exported to: {filename}")
'''

def main():
    setup_signal_handlers()

    parser = argparse.ArgumentParser(description = "LAN port scanner + report (JSON/CSV/HTML/ECS/CEF/TXT)")
    parser.add_argument("cidr", help = "CIDR Range, e.g. 192.168.1.0/24")
    parser.add_argument("--ports", help = "Comma/Interval List: 22,80,8000-8100")
    parser.add_argument("--concurrency", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--output-format", default="json,csv,html,xml,ecs,cef,txt", help="Comma-separated: json,csv,html,xml,ecs,cef,txt")
    parser.add_argument("--scanner-ip", default=None, help="Scanner IP (for source fields in ECS/CEF)")
    parser.add_argument("--prefix", default=None, help = "Prefix for the output files. If not specified, default names are used.")
    parser.add_argument("--include-all", action="store_true", help = "Include all scanned ports (open/closed/error) in the output files. By default, only open ports are exported.")
    parser.add_argument("--include-all-for", default="", help="Comma-separated formats para los que aplicar include-all, ejemplo: txt,ecs")
    parser.add_argument("--min-severity", default=None, choices=["info","medium","high","critical"], help="Mínima severidad a exportar (incluye la indicada y superiores)")
    parser.add_argument("--txt-layout", default="detailed", choices=["detailed","compact"], help="Layout for the TXT file.")
    parser.add_argument("--protocol", default = "both", choices=["tcp", "udp", "both"], help = "Scan type: TCP or UDP")
    parser.add_argument("--tcp-ports", default=None, help="Lista de puertos TCP (ej: 22,80,8000-8010). If not specified, either --ports or DEFAULT_PORTS is used.")
    parser.add_argument("--udp-ports", default=None, help="Lista de puertos UDP (ej: 53,123). Si no se especifica, para --protocol both usarán los mismos que TCP.")
    parser.add_argument("--vuln-scan", action = "store_true", help = "Enable vulnerability scanning (increases scan time)")

    # Argumentos para optimización con ping
    parser.add_argument("--no-ping", action="store_true", help="Skip ping scan and scan all hosts (slower)")
    parser.add_argument("--ping-concurrency", type=int, default=100, help="Concurrency for ping scans (default: 100)")
    parser.add_argument("--ping-timeout", type=float, default=1.0, help="Timeout for ping in seconds (default: 1.0)")

    # Nuevos argumentos para threat intelligence
    parser.add_argument("--threat-intel", action="store_true", help="Enable threat intelligence lookups")
    parser.add_argument("--abuseipdb-key", default=None, help="AbuseIPDB API key (or set ABUSEIPDB_KEY environment variable)")
    parser.add_argument("--virustotal-key", default=None, help="VirusTotal API key (or set VIRUSTOTAL_KEY environment variable)")
    parser.add_argument("--max-ti-concurrent", type=int, default=3, help="Maximum concurrent threat intelligence queries (default: 3)")

    # Agregar argumento para forzar escaneo incluso con CIDR grande
    parser.add_argument("--force", action="store_true", help="Force scan even with large CIDR ranges")

    args = parser.parse_args()

    # Configurar API keys desde argumentos o variables de entorno
    api_keys = {}
    if args.threat_intel:
        api_keys['abuseipdb'] = args.abuseipdb_key or os.getenv('ABUSEIPDB_KEY')
        api_keys['virustotal'] = args.virustotal_key or os.getenv('VIRUSTOTAL_KEY')
        
        # Informar sobre el estado de aiohttp
        if not AIOHTTP_AVAILABLE:
            print("[!] Warning: aiohttp not available - threat intelligence limited to local checks")
            print("    Install with: pip install aiohttp for full functionality")
        else:
            # Verificar si tenemos al menos un servicio online configurado
            online_services_available = any(api_keys.values())
            if not online_services_available:
                print("[!] Warning: No API keys provided for online threat intelligence services")
                print("    Using only local checks and free services")

    # --- VALIDACIÓN CIDR AL INICIO ---
    print(f"[+] Validating CIDR: {args.cidr}")
    if not validate_cidr(args.cidr):
        print("[-] Error: CIDR validation failed. Exiting.")
        return 1  # Salir con código de error

    # Validación adicional de tamaño de red
    try:
        net = ipaddress.ip_network(args.cidr, strict=False)
        
        # Advertencia para redes muy grandes
        if net.num_addresses > 65536 and not args.force:  # Más de /16
            print(f"[!] Warning: The network {args.cidr} constains {net.num_addresses} IP addresses")
            print(f"[!] This could result in a very long and slow scan.")
            print(f"[!] If you wish to continue, use --force")
            return 1
            
        # Información sobre la red
        print(f"[+] Valid network: {args.cidr}")
        print(f"[+] Hosts range: {net.num_addresses - 2} hosts escaneables")
        print(f"[+] First IP: {net[1] if net.num_addresses > 1 else 'N/A'}")
        print(f"[+] Last IP: {net[-2] if net.num_addresses > 1 else 'N/A'}")
        
    except ValueError as e:
        print(f"[-] Unexpected error validating CIDR: {e}")
        return 1
    
    vuln_scanner = None
    if args.vuln_scan:
        print("[+] Initializing vulnerability scanner...")
        vuln_scanner = VulnerabilityScanner()
        print(f"[+] Loaded {len(vuln_scanner.plugins)} vulnerability plugins")

    ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    formats = [f.strip().lower() for f in args.output_format.split(",") if f.strip()]
    include_all_for = [f.strip().lower() for f in args.include_all_for.split(",") if f.strip()]
    prefix = (args.prefix.rstrip("_") + "_") if args.prefix else ""

    print(f"[+] Scanning {args.cidr} ports {ports[:10]}... (total: {len(ports)} ports)")

    # --- Preparar puertos según argumentos ---
    tcp_ports = parse_ports(args.tcp_ports) if getattr(args, "tcp_ports", None) else parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    udp_ports = parse_ports(args.udp_ports) if getattr(args, "udp_ports", None) else []

    # Si pediste udp explícito pero no diste udp_ports, cae a --ports
    if args.protocol == "udp" and not udp_ports:
        udp_ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS

    # Si pediste both y no diste udp_ports, usar la lista tcp por defecto (útil para escanear ambos sobre mismo set)
    if args.protocol == "both" and not udp_ports:
        udp_ports = list(tcp_ports)

    # Wrapper async para correr uno o dos escaneos y combinarlos
    async def _run_requested_scans():
        tasks = []
        # TCP
        if args.protocol in ("tcp", "both"):
            tasks.append(asyncio.create_task(scan_hosts(
                args.cidr,
                tcp_ports,
                concurrency=args.concurrency,
                timeout=args.timeout,
                show_progress=True,
                ping_first=not args.no_ping,
                ping_concurrency=args.ping_concurrency,
                ping_timeout=args.ping_timeout,
                protocol="tcp",
                vuln_scanner = vuln_scanner
            )))
        # UDP
        if args.protocol in ("udp", "both"):
            tasks.append(asyncio.create_task(scan_hosts(
                args.cidr,
                udp_ports,
                concurrency=args.concurrency,
                timeout=args.timeout,
                show_progress=True,
                ping_first=not args.no_ping,
                ping_concurrency=args.ping_concurrency,
                ping_timeout=args.ping_timeout,
                protocol="udp",
                vuln_scanner = vuln_scanner
            )))

        if not tasks:
            return []

        # Ejecutar en paralelo (si hay dos) y combinar resultados
        results_list = await asyncio.gather(*tasks)
        # results_list es una lista de listas -> aplanar
        combined = []
        for sub in results_list:
            combined.extend(sub)
        return combined

    # Ejecutar escaneos (TCP/UDP/ambos) y obtener resultados combinados
    results = asyncio.run(_run_requested_scans())

    open_results = [r for r in results if r.get("status")=="open"]

    master_for_summary = results if args.include_all else open_results
    # Apply severity filter on the master
    if args.min_severity:
        min_rank = severity_rank(args.min_severity)
        master_for_summary = [r for r in master_for_summary if severity_rank(r.get('severity')) >= min_rank]

    print(f"[+] Scan completed. Open ports detected: {len(open_results)} (total scans: {len(results)})")

    # Mostrar resumen de vulnerabilidades
    if args.vuln_scan:
        total_vulns = sum(len(r.get("vulnerabilities", [])) for r in results)
        print(f"[+] Vulnerability scan completed: {total_vulns} issues found")
        
        # Mostrar vulnerabilidades críticas
        critical_vulns = []
        for r in results:
            for vuln in r.get("vulnerabilities", []):
                if vuln.get("confidence", 0) > 70:
                    critical_vulns.append({
                        "host": r["host"],
                        "port": r["port"],
                        "plugin": vuln.get("plugin_name", "Unknown"),
                        "description": vuln.get("description", ""),
                        "confidence": vuln.get("confidence", 0)
                    })
        
        if critical_vulns:
            print("\n[!] CRITICAL VULNERABILITIES FOUND:")
            for vuln in critical_vulns:
                print(f"    {vuln['host']}:{vuln['port']} - {vuln['plugin']} "
                      f"(Confidence: {vuln['confidence']}%)")
                print(f"      {vuln['description']}")

    # Exports according to requested formats. For each format, we decide whether to use 'results' (all) or 'open_results'.
    for fmt in formats:
        use_all = args.include_all or (fmt in include_all_for)
        use_results = results if use_all else open_results
        # Apply severity filter by format if indicated
        if args.min_severity:
            min_rank = severity_rank(args.min_severity)
            use_results = [r for r in use_results if severity_rank(r.get('severity')) >= min_rank]

        if fmt == "json":
            out = f"{prefix}scan_results.json" if prefix else "scan_results.json"
            save_json(use_results, filename=out)
            print(f"[+] JSON exported: {out} (items: {len(use_results)})")
        elif fmt == "csv":
            out = f"{prefix}scan_results.csv" if prefix else "scan_results.csv"
            save_csv(use_results, filename=out)
            print(f"[+] CSV exported: {out} (items: {len(use_results)})")
        elif fmt == "html":
            out = f"{prefix}scan_report.html" if prefix else "scan_report.html"
            save_html(use_results, filename=out)
            print(f"[+] HTML exported: {out} (items: {len(use_results)})")
        elif fmt == "txt":
            out = f"{prefix}scan_results.txt" if prefix else "scan_results.txt"
            save_txt(use_results, filename=out, layout=args.txt_layout)
            print(f"[+] TXT exported: {out} (layout: {args.txt_layout}, items: {len(use_results)})")
        elif fmt == "ecs":
            out = f"{prefix}ecs_events.ndjson" if prefix else "ecs_events.ndjson"
            export_ecs_ndjson(use_results, out_path=out, scanner_ip=args.scanner_ip)
            print(f"[+] ECS NDJSON exported: {out} (items: {len(use_results)})")
        elif fmt == "cef":
            out = f"{prefix}scan_results.cef" if prefix else "scan_results.cef"
            export_cef_file(use_results, out_path=out, scanner_ip=args.scanner_ip)
            print(f"[+] CEF exported: {out} (items: {len(use_results)})")
        else:
            print(f"[!] Unknown format: {fmt}")

    # Master set severity summary
    counts = {}
    for r in master_for_summary:
        counts[r.get("severity","info")] = counts.get(r.get("severity","info"), 0) + 1
    print(f"[+] Summary by severity (of the applied set): {counts}")

    if args.include_all:
        print("[!] Note: All scanned ports have been included in the exports. (--include-all).")
    if include_all_for:
        print(f"[!] Note: For {include_all_for} formats, all results are included. (--include-all-for).")
    if args.min_severity:
        print(f"[!] Note: Minimum severity filter applied: {args.min_severity}")

if __name__ == "__main__":
    main()