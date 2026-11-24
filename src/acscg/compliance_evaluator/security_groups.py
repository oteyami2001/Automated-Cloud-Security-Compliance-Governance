"""SEC-005 / SEC-006: ingress open to the internet on administrative ports.

Accepts the three shapes the platform sees:
* EC2 ``DescribeSecurityGroupRules`` rules (``CidrIpv4``/``CidrIpv6``, ``IsEgress``) - live checks;
* EC2 ``IpPermissions`` (``IpRanges``/``Ipv6Ranges``) - API responses;
* AWS Config configuration items (``ipPermissions`` with ``ipv4Ranges``/``ipv6Ranges``/``ipRanges``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = {"SEC-005": 22, "SEC-006": 3389}


@dataclass(frozen=True)
class OpenRule:
    protocol: str
    from_port: int | None
    to_port: int | None
    cidr: str
    rule_id: str | None = None


def _get(data: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in data:
            return data[name]
    return None


def covers_port(protocol: str, from_port: int | None, to_port: int | None, port: int) -> bool:
    """True if a rule with this protocol and range admits TCP traffic to ``port``."""
    proto = str(protocol).lower()
    if proto in {"-1", "all"}:
        return True
    if proto not in {"tcp", "6"}:
        return False
    if from_port is None or to_port is None:
        return True  # tcp without a range means all ports
    if int(from_port) == -1 and int(to_port) == -1:
        return True
    return int(from_port) <= port <= int(to_port)


def _cidrs(permission: dict[str, Any]) -> list[str]:
    cidrs: list[str] = []
    for item in _get(permission, "IpRanges", "ipv4Ranges") or []:
        cidrs.append(item.get("CidrIp") or item.get("cidrIp") if isinstance(item, dict) else item)
    for item in _get(permission, "Ipv6Ranges", "ipv6Ranges") or []:
        cidrs.append(item.get("CidrIpv6") or item.get("cidrIpv6") if isinstance(item, dict) else item)
    # Config also lists IPv4 CIDRs as plain strings under "ipRanges".
    for item in permission.get("ipRanges", []) or []:
        if isinstance(item, str):
            cidrs.append(item)
    return [c for c in cidrs if c]


def open_permissions(permissions: list[dict[str, Any]], port: int) -> list[OpenRule]:
    """Offending entries in IpPermissions / Config ipPermissions form."""
    found: dict[tuple[str, int | None, int | None, str], OpenRule] = {}
    for permission in permissions or []:
        protocol = str(_get(permission, "IpProtocol", "ipProtocol"))
        from_port = _get(permission, "FromPort", "fromPort")
        to_port = _get(permission, "ToPort", "toPort")
        if not covers_port(protocol, from_port, to_port, port):
            continue
        for cidr in _cidrs(permission):
            if cidr in OPEN_CIDRS:
                found[(protocol, from_port, to_port, cidr)] = OpenRule(protocol, from_port, to_port, cidr)
    return list(found.values())


def open_rules(rules: list[dict[str, Any]], port: int) -> list[OpenRule]:
    """Offending ingress rules in DescribeSecurityGroupRules form (each has a rule ID)."""
    offending = []
    for rule in rules or []:
        if rule.get("IsEgress"):
            continue
        cidr = rule.get("CidrIpv4") or rule.get("CidrIpv6")
        if cidr not in OPEN_CIDRS:
            continue
        if covers_port(str(rule.get("IpProtocol")), rule.get("FromPort"), rule.get("ToPort"), port):
            offending.append(
                OpenRule(
                    str(rule.get("IpProtocol")),
                    rule.get("FromPort"),
                    rule.get("ToPort"),
                    cidr,
                    rule.get("SecurityGroupRuleId"),
                )
            )
    return offending
