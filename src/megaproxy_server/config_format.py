"""Portable configuration structure shared by exports and the standalone API."""
from __future__ import annotations

import uuid
import re
from copy import deepcopy
from typing import Any


def profile(name: str, proxy: dict[str, Any], color: int, country_code: str = "", *, identity: str | None = None) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"dev.megaproxy.server/{identity if identity is not None else name}")),
        "name": name, "color": color, "countryCode": country_code, "proxy": proxy,
        "tls": {"fingerprint": "DEFAULT", "customJa3": ""},
        "dns": {"provider": "CLOUDFLARE", "customDohUrl": ""},
        "routing": {"routeAllApps": True, "selectedPackages": [], "allowIpv6": False, "bypassLocalNetworks": True},
    }


def configuration(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "net.megaproxy487.config", "version": 7,
        "passwordsIncluded": True, "privateKeysIncluded": True, "diagnosticLogLimitMb": 3,
        "tls": {"fingerprint": "DEFAULT", "customJa3": ""},
        "ssh": {"fingerprint": "DEFAULT", "authMode": "AUTO", "keepaliveSeconds": 30,
                "maxChannels": 32, "rotationMinutes": 0, "rotationMb": 0},
        "failover": {"mode": "DISABLED", "profileIds": []},
        "routing": {"routeAllApps": True, "selectedPackages": [], "bypassLocalNetworks": True},
        "profiles": profiles,
    }


def https_jump_profile(entry: dict[str, Any], exit_profile: dict[str, Any], name: str,
                       country_code: str, color: int, *, identity: str) -> dict[str, Any]:
    item = deepcopy(exit_profile)
    proxy = item["proxy"]
    proxy["type"] = "HTTPS_JUMP"
    proxy["jump"] = {k: v for k, v in entry["proxy"].items()
                     if k in {"host", "port", "allowInvalidProxyCertificate"}}
    proxy["jump"]["sameAuthentication"] = True
    proxy["preferHttp3"] = bool(proxy.get("preferHttp3") and entry["proxy"].get("preferHttp3"))
    generated = profile(name, proxy, color,
                        country_code if re.fullmatch(r"[A-Z]{2}", country_code) else "", identity=identity)
    item.update({k: generated[k] for k in ("id", "name", "color", "countryCode")})
    return item
