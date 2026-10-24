"""Install a translated block or allow policy on the lab switch."""

from __future__ import annotations

import json

import requests

from lab7.schema import check_schema
from lab7.topology import CONTROLLER_REST, DPID, HOSTS, SWITCH

ETH_TYPE_IP = 0x0800
ETH_TYPE_ARP = 0x0806
IP_PROTO = {"icmp": 1, "tcp": 6, "udp": 17}

_BY_IP = {host["ip"]: name for name, host in HOSTS.items()}


class PolicyApplyError(Exception):
    """The policy could not be installed on the switch."""


def apply_policy(policy_dict: dict) -> None:
    """Install each block or allow rule in ``policy_dict`` on s1.

    Rate-limit and prioritize rules are rejected. Objective 3 covers those.
    Prints the switch, match, and actions for every flow that is installed.
    """

    try:
        check_schema(policy_dict)
    except ValueError as exc:
        raise PolicyApplyError(str(exc)) from exc

    unsupported = sorted(
        {rule["action"] for rule in policy_dict["rules"]} - {"block", "allow"}
    )
    if unsupported:
        names = ", ".join(unsupported)
        raise PolicyApplyError(
            f"apply_policy cannot install {names} rules. "
            "This objective installs block and allow rules."
        )

    flows = [_flow_entry(rule, source, destination)
             for rule in policy_dict["rules"]
             for source, destination in _directions(rule)]

    for flow in flows:
        _install(flow)
        _print_installed(flow)
        _confirm_installed(flow)


def _directions(rule: dict) -> list[tuple[str, str]]:
    forward = (rule["source"], rule["destination"])
    if rule["direction"] == "unidirectional" or rule["source"] == rule["destination"]:
        return [forward]
    return [forward, (rule["destination"], rule["source"])]


def _flow_entry(rule: dict, source: str, destination: str) -> dict:
    match = {}
    match.update(_endpoint_match(source, "src", rule["protocol"]))
    match.update(_endpoint_match(destination, "dst", rule["protocol"]))
    match.update(_protocol_match(rule))

    if rule["action"] == "block":
        actions = []
    else:
        actions = [{"type": "OUTPUT", "port": _output_port(destination)}]

    return {
        "dpid": DPID,
        "priority": rule["parameters"]["priority"],
        "match": match,
        "actions": actions,
        "table_id": 0,
    }


def _endpoint_match(endpoint: str, role: str, protocol: str) -> dict:
    if endpoint == "any":
        return {}

    host_name = endpoint if endpoint in HOSTS else _BY_IP.get(endpoint)
    if host_name is not None:
        host = HOSTS[host_name]
        if role == "src":
            fields = {"in_port": host["port"], "dl_src": host["mac"]}
        else:
            fields = {"dl_dst": host["mac"]}
        if protocol not in ("any", "arp"):
            ip_field = "nw_src" if role == "src" else "nw_dst"
            fields[ip_field] = host["ip"]
        return fields

    ip_field = "nw_src" if role == "src" else "nw_dst"
    return {ip_field: endpoint}


def _protocol_match(rule: dict) -> dict:
    protocol = rule["protocol"]
    fields = {}

    if protocol == "arp":
        fields["dl_type"] = ETH_TYPE_ARP
    else:
        # "any" is installed as all IPv4. ARP stays with the learning
        # switch so hosts can still resolve each other. An allow-only
        # ICMP rule would never see ICMP if the broader block ate ARP.
        fields["dl_type"] = ETH_TYPE_IP

    if protocol in IP_PROTO:
        fields["nw_proto"] = IP_PROTO[protocol]

    if rule["port"] is not None:
        port_key = "tp_dst" if rule["port_field"] == "destination" else "tp_src"
        fields[port_key] = rule["port"]

    return fields


def _output_port(destination: str) -> int:
    host_name = destination if destination in HOSTS else _BY_IP.get(destination)
    if host_name is None:
        raise PolicyApplyError(
            f"Cannot forward to {destination!r}. An allow rule needs a "
            "destination host so the flow has an output port."
        )
    return HOSTS[host_name]["port"]


def _install(flow: dict) -> None:
    try:
        response = requests.post(
            f"{CONTROLLER_REST}/stats/flowentry/add",
            json=flow,
            timeout=10,
        )
    except requests.exceptions.RequestException as exc:
        raise PolicyApplyError(f"Failed to reach the Ryu controller: {exc}") from exc

    if not response.ok:
        raise PolicyApplyError(
            f"Ryu rejected the flow with status {response.status_code}: "
            f"{response.text.strip()}"
        )


def _print_installed(flow: dict) -> None:
    action = "block" if flow["actions"] == [] else "allow"
    print(f"Installed {action} rule on {SWITCH} (dpid {DPID}):")
    print(f"  priority: {flow['priority']}")
    print(f"  match: {json.dumps(flow['match'], sort_keys=True)}")
    print(f"  actions: {json.dumps(flow['actions'])}")


def _confirm_installed(flow: dict) -> None:
    try:
        response = requests.get(
            f"{CONTROLLER_REST}/stats/flow/{DPID}",
            timeout=10,
        )
        response.raise_for_status()
        installed = response.json().get(str(DPID), [])
    except requests.exceptions.RequestException as exc:
        raise PolicyApplyError(f"Could not read the flow table on {SWITCH}: {exc}") from exc

    if not any(_same_flow(flow, entry) for entry in installed):
        raise PolicyApplyError(
            f"The flow was sent to Ryu but is not in the {SWITCH} flow table: "
            f"priority {flow['priority']} match {flow['match']}"
        )


def _same_flow(flow: dict, entry: dict) -> bool:
    if entry.get("priority") != flow["priority"]:
        return False
    if entry.get("table_id", 0) != flow["table_id"]:
        return False

    actual = {_normalize_key(key): _normalize_value(value)
              for key, value in entry.get("match", {}).items()}
    expected = {_normalize_key(key): _normalize_value(value)
                for key, value in flow["match"].items()}
    if any(actual.get(key) != value for key, value in expected.items()):
        return False

    if flow["actions"] == []:
        return entry.get("actions", []) == []

    port = flow["actions"][0]["port"]
    return f"OUTPUT:{port}" in entry.get("actions", [])


def _normalize_key(key: str) -> str:
    aliases = {
        "eth_src": "dl_src",
        "eth_dst": "dl_dst",
        "eth_type": "dl_type",
        "ipv4_src": "nw_src",
        "ipv4_dst": "nw_dst",
        "ip_proto": "nw_proto",
        "tcp_src": "tp_src",
        "tcp_dst": "tp_dst",
        "udp_src": "tp_src",
        "udp_dst": "tp_dst",
    }
    return aliases.get(key, key)


def _normalize_value(value: object) -> str:
    text = str(value).lower()
    if text.endswith("/32"):
        return text[:-3]
    return text
