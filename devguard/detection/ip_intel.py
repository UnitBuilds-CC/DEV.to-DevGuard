import socket
import logging
from typing import List, Dict, Any, Optional
import httpx
from devguard.detection.scoring import DetectionFlag

logger = logging.getLogger("devguard.detection.ip_intel")

DATACENTER_KEYWORDS = [
    "aws", "amazon", "google", "gcp", "azure", "microsoft", "hosting", "server",
    "vps", "cloud", "datacenter", "ovh", "hetzner", "digitalocean", "linode",
    "scaleway", "leaseweb", "contabo", "vultr", "m247", "host", "dedicated"
]

class IPIntelDetector:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.provider = self.config.get("provider", "ip-api")
        self.api_key = self.config.get("api_key", "")

    async def detect(self, ip_address: str) -> List[DetectionFlag]:
        """Analyzes an IP address using reverse DNS and a public IP intelligence API."""
        flags = []
        if not ip_address or ip_address in ("127.0.0.1", "localhost", "::1"):
            return flags

        # 1. Reverse DNS (PTR) analysis
        ptr_record = ""
        try:
            # Run in executor or wrap in try/except to prevent blocking
            ptr_record, _, _ = socket.gethostbyaddr(ip_address)
            ptr_record = ptr_record.lower()
        except Exception:
            pass

        if ptr_record:
            matched_keywords = [kw for kw in DATACENTER_KEYWORDS if kw in ptr_record]
            if matched_keywords:
                flags.append(DetectionFlag(
                    detector="ip_intel",
                    rule_name="datacenter_ptr",
                    severity=0.7,
                    description=f"Reverse DNS record '{ptr_record}' contains hosting keywords: {', '.join(matched_keywords)}",
                    evidence={"ptr": ptr_record, "matched_keywords": matched_keywords}
                ))

        # 2. IP Intelligence API lookup (ip-api.com free tier)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,as,hosting,proxy"
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        is_hosting = data.get("hosting", False)
                        is_proxy = data.get("proxy", False)
                        asn_info = data.get("as", "")
                        
                        if is_hosting:
                            flags.append(DetectionFlag(
                                detector="ip_intel",
                                rule_name="datacenter_ip",
                                severity=0.85,
                                description=f"IP belongs to a hosting provider or datacenter ({asn_info})",
                                evidence={"asn": asn_info, "hosting": True}
                            ))
                            
                        if is_proxy:
                            flags.append(DetectionFlag(
                                detector="ip_intel",
                                rule_name="proxy_vpn_ip",
                                severity=0.75,
                                description="IP is identified as a VPN, proxy, or Tor exit node",
                                evidence={"proxy": True}
                            ))
                            
                        # If not flagged as hosting, check ASN text as fallback
                        if not is_hosting and asn_info:
                            asn_lower = asn_info.lower()
                            matched_asn_kws = [kw for kw in DATACENTER_KEYWORDS if kw in asn_lower]
                            if matched_asn_kws:
                                flags.append(DetectionFlag(
                                    detector="ip_intel",
                                    rule_name="datacenter_asn",
                                    severity=0.65,
                                    description=f"IP ASN details ({asn_info}) match cloud/hosting keywords",
                                    evidence={"asn": asn_info}
                                ))
        except Exception as e:
            logger.error(f"Failed to query IP intelligence API for {ip_address}: {e}")

        return flags
