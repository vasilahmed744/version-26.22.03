from __future__ import annotations

import ipaddress


def is_private_ip(ip_address: str) -> bool:
    try:
        return ipaddress.ip_address(ip_address).is_private
    except ValueError:
        return False


def is_public_ip(ip_address: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        )
    except ValueError:
        return False
