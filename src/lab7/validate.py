"""Reject translated policies that must not reach the switch."""

from __future__ import annotations

import ipaddress

import requests

from lab7.schema import check_schema
from lab7.topology import CONTROLLER_REST, DPID, HOSTS

_BY_MAC = {host["mac"]: name for name, host in HOSTS.items()}
_BY_IP = {host["ip"]: name for name, host in HOSTS.items()}
_IP_PROTO = {1: "icmp", 6: "tcp", 17: "udp"}
_L4 = {"icmp", "tcp", "udp"}


def validate_policy(policy_dict: dict) -> str | None:
    """Return a human-readable rejection, or None if the policy may be installed.

    The caller prints the message and skips apply_policy. This function does
    not raise for an invalid policy.
    """

    try:
        check_schema(policy_dict)
    except ValueError as exc:
        return f"Rejected: the policy is missing required fields or is otherwise invalid. {exc}"

    for index, rule in enumerate(policy_dict["rules"], start=1):
        for endpoint in (rule["source"], rule["destination"]):
            message = _unknown_endpoint(endpoint, index)
            if message:
                return message

        if rule["action"] not in ("block", "allow"):
            return (
                f"Rejected: rules[{index}] uses action {rule['action']!r}, "
                "which this controller cannot enforce. It installs block and "
                "allow rules only, so a prioritize or rate-limit translation "
                "would not change forwarding."
            )

    clauses = _clauses(policy_dict["rules"], "this policy")
    for left, right in _pairs(clauses):
        message = _contradiction(left, right, installed=False)
        if message:
            return message

    try:
        installed = _installed_clauses()
    except requests.exceptions.RequestException as exc:
        return (
            "Rejected: the controller flow table could not be read, so the "
            f"policy was not applied. {exc}"
        )

    for new_rule in clauses:
        for existing in installed:
            message = _contradiction(new_rule, existing, installed=True)
            if message:
                return message

    return None


def _unknown_endpoint(endpoint: str, index: int) -> str | None:
    if endpoint == "any" or endpoint in HOSTS or endpoint in _BY_IP:
        return None

    known = ", ".join(
        f"{name} ({host['ip']})" for name, host in HOSTS.items()
    )
    where = f"rules[{index}]"

    if endpoint.startswith("h") and endpoint[1:].isdigit():
        return (
            f"Rejected: {where} references {endpoint}, which is not in this "
            f"topology. Hosts are {known}."
        )

    try:
        address = ipaddress.ip_address(endpoint)
    except ValueError:
        address = None

    if address is not None:
        return (
            f"Rejected: {where} references {endpoint}, which is not an address "
            f"of a host in this topology. Hosts are {known}."
        )

    try:
        network = ipaddress.ip_network(endpoint, strict=False)
    except ValueError:
        return (
            f"Rejected: {where} references {endpoint}, which is not a host "
            f"in this topology. Hosts are {known}."
        )

    if any(ipaddress.ip_address(host["ip"]) in network for host in HOSTS.values()):
        return None

    return (
        f"Rejected: {where} references subnet {endpoint}, which contains none "
        f"of the hosts in this topology. Hosts are {known}."
    )


def _clauses(rules: list[dict], origin: str) -> list[dict]:
    clauses = []
    for rule in rules:
        directions = [(rule["source"], rule["destination"])]
        if rule["direction"] == "bidirectional" and rule["source"] != rule["destination"]:
            directions.append((rule["destination"], rule["source"]))
        for source, destination in directions:
            clauses.append(_clause(rule, source, destination, origin))
    return clauses


def _clause(rule: dict, source: str, destination: str, origin: str) -> dict:
    return {
        "action": rule["action"],
        "priority": rule["parameters"]["priority"],
        "source": _canonical(source),
        "destination": _canonical(destination),
        "protocol": rule["protocol"],
        "port": rule["port"],
        "port_field": rule["port_field"],
        "origin": origin,
    }


def _canonical(endpoint: str) -> str:
    return _BY_IP.get(endpoint, endpoint)


def _installed_clauses() -> list[dict]:
    response = requests.get(f"{CONTROLLER_REST}/stats/flow/{DPID}", timeout=10)
    response.raise_for_status()
    clauses = []
    for flow in response.json().get(str(DPID), []):
        # Priority 0 is table-miss. Priority 1 is the learning switch.
        # Neither is an operator policy.
        if flow.get("priority", 0) < 100:
            continue
        clause = _clause_from_flow(flow)
        if clause is not None:
            clauses.append(clause)
    return clauses


def _clause_from_flow(flow: dict) -> dict | None:
    match = flow.get("match", {})
    source = _BY_MAC.get(match.get("dl_src"), match.get("nw_src", "any"))
    destination = _BY_MAC.get(match.get("dl_dst"), match.get("nw_dst", "any"))
    protocol = _IP_PROTO.get(match.get("nw_proto"), "any")

    if "tp_dst" in match:
        port, port_field = match["tp_dst"], "destination"
    elif "tp_src" in match:
        port, port_field = match["tp_src"], "source"
    else:
        port, port_field = None, None

    actions = flow.get("actions", [])
    if actions == []:
        action = "block"
    elif any(str(item).startswith("OUTPUT:") for item in actions):
        action = "allow"
    else:
        return None

    return {
        "action": action,
        "priority": flow.get("priority", 0),
        "source": _canonical(str(source)),
        "destination": _canonical(str(destination)),
        "protocol": protocol,
        "port": port,
        "port_field": port_field,
        "origin": "s1",
    }


def _pairs(clauses: list[dict]) -> list[tuple[dict, dict]]:
    return [
        (clauses[left], clauses[right])
        for left in range(len(clauses))
        for right in range(left + 1, len(clauses))
    ]


def _contradiction(left: dict, right: dict, *, installed: bool) -> str | None:
    if left["action"] == right["action"] or not _overlaps(left, right):
        return None
    if _exception_ok(left, right) or _exception_ok(right, left):
        return None

    if installed:
        existing = right if right["origin"] == "s1" else left
        proposed = left if existing is right else right
        return (
            "Rejected: this policy conflicts with a rule already installed on s1. "
            f"The new rule {_describes(proposed)}, but s1 already "
            f"{_describes(existing)}."
        )

    return (
        "Rejected: this policy contradicts itself. "
        f"It {_describes(left)} and also {_describes(right)}."
    )


def _exception_ok(specific: dict, broad: dict) -> bool:
    """A narrower rule may override a broader one only at a higher priority."""

    return _more_specific(specific, broad) and specific["priority"] > broad["priority"]


def _overlaps(left: dict, right: dict) -> bool:
    return (
        _endpoints_overlap(left["source"], right["source"])
        and _endpoints_overlap(left["destination"], right["destination"])
        and _protocols_overlap(left["protocol"], right["protocol"])
        and _ports_overlap(left, right)
    )


def _endpoints_overlap(left: str, right: str) -> bool:
    if left == "any" or right == "any" or left == right:
        return True
    return _in_network(left, right) or _in_network(right, left)


def _in_network(endpoint: str, network_text: str) -> bool:
    try:
        network = ipaddress.ip_network(network_text, strict=False)
        address = _address_of(endpoint)
    except ValueError:
        return False
    return address is not None and address in network


def _address_of(endpoint: str) -> ipaddress.IPv4Address | None:
    text = HOSTS[endpoint]["ip"] if endpoint in HOSTS else endpoint
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _protocols_overlap(left: str, right: str) -> bool:
    if left == right or left == "any" or right == "any":
        return True
    if left == "ip" and right in _L4:
        return True
    if right == "ip" and left in _L4:
        return True
    return False


def _ports_overlap(left: dict, right: dict) -> bool:
    if left["port"] is None or right["port"] is None:
        return True
    return left["port"] == right["port"] and left["port_field"] == right["port_field"]


def _more_specific(specific: dict, broad: dict) -> bool:
    covered = (
        _endpoint_covered(specific["source"], broad["source"])
        and _endpoint_covered(specific["destination"], broad["destination"])
        and _protocol_covered(specific["protocol"], broad["protocol"])
        and _port_covered(specific, broad)
    )
    if not covered:
        return False
    return any((
        specific["source"] != broad["source"],
        specific["destination"] != broad["destination"],
        specific["protocol"] != broad["protocol"],
        specific["port"] != broad["port"],
    ))


def _endpoint_covered(specific: str, broad: str) -> bool:
    if broad == "any" or specific == broad:
        return True
    return _in_network(specific, broad)


def _protocol_covered(specific: str, broad: str) -> bool:
    if broad == "any" or specific == broad:
        return True
    return broad == "ip" and specific in _L4


def _port_covered(specific: dict, broad: dict) -> bool:
    if broad["port"] is None:
        return True
    return (
        specific["port"] == broad["port"]
        and specific["port_field"] == broad["port_field"]
    )


def _describes(clause: dict) -> str:
    port = ""
    if clause["port"] is not None:
        port = f", {clause['port_field']} port {clause['port']}"
    return (
        f"{clause['action']}s traffic from {clause['source']} to "
        f"{clause['destination']} (protocol {clause['protocol']}{port}, "
        f"priority {clause['priority']})"
    )
