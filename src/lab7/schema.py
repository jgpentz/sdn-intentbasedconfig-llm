"""JSON contract for a translated network intent.

``translate_intent`` asks the model for one object of this shape.
``check_schema`` rejects anything the applier cannot trust.

A policy is a list of rules, most specific first. One sentence usually
becomes one rule. "Allow only X" becomes two: a higher-priority allow
for X, then a lower-priority block for everything else between the same
endpoints.

Field reference
---------------
summary
    One sentence restating the intent in operational language.

rules
    One to eight rule objects. Order is most specific to least specific.

action
    What the switch should do with matching traffic.
    ``block`` drops it.
    ``allow`` forwards it.
    ``rate_limit`` forwards it, capped at ``parameters.rate_kbps``.
    ``prioritize`` forwards it ahead of best-effort traffic. Set a
    priority above 100, and set ``dscp`` or ``queue_id`` when the
    intent names a mark or a queue.

direction
    ``unidirectional`` for "from A to B".
    ``bidirectional`` for "between A and B".

source, destination
    ``h1``–style host name, an IPv4 address, an IPv4 CIDR, or ``any``.
    Use a host name when the operator names a host. Host existence is
    not checked here; that belongs in the later topology validator.

protocol
    ``any``, ``ip``, ``icmp``, ``tcp``, ``udp``, or ``arp``.
    A port is allowed only on ``tcp`` or ``udp``.

port
    Transport port 0–65535, or JSON null when the rule matches every port.

port_field
    ``destination`` or ``source`` when ``port`` is set, otherwise null.
    "Traffic on port 80" means the destination port.

parameters
    Action-specific settings. ``priority`` is required on every rule
    (1–65535). Ordinary rules use 100. A more specific allow that must
    beat a broader block uses 200. Prioritized traffic uses 300 unless
    the operator names a value.
    ``rate_kbps`` is required for ``rate_limit`` and is forbidden otherwise.
    ``burst_kb`` is optional and only valid on ``rate_limit``.
    ``dscp`` (0–63) and ``queue_id`` (0 or greater) are optional and
    only valid on ``prioritize``.
"""

from __future__ import annotations

import re

ACTIONS = ("block", "allow", "rate_limit", "prioritize")
DIRECTIONS = ("unidirectional", "bidirectional")
PROTOCOLS = ("any", "ip", "icmp", "tcp", "udp", "arp")
PORT_FIELDS = ("source", "destination")

TOP_LEVEL_FIELDS = ("summary", "rules")
RULE_FIELDS = (
    "action",
    "direction",
    "source",
    "destination",
    "protocol",
    "port",
    "port_field",
    "parameters",
)

_HOST = re.compile(r"^h[1-9][0-9]*$")
_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_CIDR = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$")


def check_schema(policy: dict) -> None:
    """Raise ValueError when ``policy`` does not match the intent schema."""

    if not isinstance(policy, dict):
        raise ValueError("Policy must be a JSON object.")

    unexpected = sorted(set(policy) - set(TOP_LEVEL_FIELDS))
    if unexpected:
        raise ValueError(f"Unexpected policy field(s): {', '.join(unexpected)}.")

    missing = [field for field in TOP_LEVEL_FIELDS if field not in policy]
    if missing:
        raise ValueError(f"Policy is missing field(s): {', '.join(missing)}.")

    summary = policy["summary"]
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("summary must be a non-empty string.")
    if len(summary) > 400:
        raise ValueError("summary must be 400 characters or fewer.")

    rules = policy["rules"]
    if not isinstance(rules, list) or not rules:
        raise ValueError("rules must be a non-empty list.")
    if len(rules) > 8:
        raise ValueError("rules cannot contain more than 8 entries.")

    for index, rule in enumerate(rules, start=1):
        _check_rule(rule, index)


def _check_rule(rule: object, index: int) -> None:
    where = f"rules[{index}]"

    if not isinstance(rule, dict):
        raise ValueError(f"{where} must be an object.")

    unexpected = sorted(set(rule) - set(RULE_FIELDS))
    if unexpected:
        raise ValueError(
            f"{where} has unexpected field(s): {', '.join(unexpected)}."
        )

    missing = [field for field in RULE_FIELDS if field not in rule]
    if missing:
        raise ValueError(f"{where} is missing field(s): {', '.join(missing)}.")

    action = rule["action"]
    if action not in ACTIONS:
        raise ValueError(
            f"{where}.action must be one of: {', '.join(ACTIONS)}."
        )

    if rule["direction"] not in DIRECTIONS:
        raise ValueError(
            f"{where}.direction must be one of: {', '.join(DIRECTIONS)}."
        )

    for endpoint in ("source", "destination"):
        _check_endpoint(rule[endpoint], f"{where}.{endpoint}")

    protocol = rule["protocol"]
    if protocol not in PROTOCOLS:
        raise ValueError(
            f"{where}.protocol must be one of: {', '.join(PROTOCOLS)}."
        )

    _check_port(rule, where, protocol)
    _check_parameters(rule["parameters"], where, action)


def _check_endpoint(value: object, where: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{where} must be a string.")

    if value == "any" or _HOST.match(value):
        return

    if _valid_ipv4(value) or _valid_cidr(value):
        return

    raise ValueError(
        f"{where} must be a host name such as h1, an IPv4 address, "
        f"an IPv4 CIDR, or 'any'. Got {value!r}."
    )


def _check_port(rule: dict, where: str, protocol: str) -> None:
    port = rule["port"]
    port_field = rule["port_field"]

    if port is None:
        if port_field is not None:
            raise ValueError(
                f"{where}.port_field must be null when port is null."
            )
        return

    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError(f"{where}.port must be an integer from 0 to 65535, or null.")

    if protocol not in ("tcp", "udp"):
        raise ValueError(
            f"{where}.port is only valid when protocol is tcp or udp."
        )

    if port_field not in PORT_FIELDS:
        raise ValueError(
            f"{where}.port_field must be 'source' or 'destination' when port is set."
        )


def _check_parameters(parameters: object, where: str, action: str) -> None:
    label = f"{where}.parameters"
    if not isinstance(parameters, dict):
        raise ValueError(f"{label} must be an object.")

    allowed = {"priority"}
    if action == "rate_limit":
        allowed |= {"rate_kbps", "burst_kb"}
    elif action == "prioritize":
        allowed |= {"dscp", "queue_id"}

    unexpected = sorted(set(parameters) - allowed)
    if unexpected:
        raise ValueError(
            f"{label} has unexpected field(s) for action {action}: "
            f"{', '.join(unexpected)}."
        )

    if "priority" not in parameters:
        raise ValueError(f"{label}.priority is required.")
    _check_int(parameters["priority"], f"{label}.priority", minimum=1, maximum=65535)

    if action == "rate_limit":
        if "rate_kbps" not in parameters:
            raise ValueError(f"{label}.rate_kbps is required for rate_limit.")
        _check_int(
            parameters["rate_kbps"],
            f"{label}.rate_kbps",
            minimum=1,
            maximum=10_000_000,
        )
        if "burst_kb" in parameters:
            _check_int(
                parameters["burst_kb"],
                f"{label}.burst_kb",
                minimum=1,
                maximum=10_000_000,
            )

    if "dscp" in parameters:
        _check_int(parameters["dscp"], f"{label}.dscp", minimum=0, maximum=63)
    if "queue_id" in parameters:
        _check_int(
            parameters["queue_id"],
            f"{label}.queue_id",
            minimum=0,
            maximum=7,
        )


def _check_int(value: object, where: str, *, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{where} must be an integer.")
    if not minimum <= value <= maximum:
        raise ValueError(f"{where} must be from {minimum} to {maximum}.")


def _valid_ipv4(value: str) -> bool:
    match = _IPV4.match(value)
    if not match:
        return False
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def _valid_cidr(value: str) -> bool:
    match = _CIDR.match(value)
    if not match:
        return False
    octets = match.groups()[:4]
    prefix = int(match.group(5))
    return all(0 <= int(octet) <= 255 for octet in octets) and 0 <= prefix <= 32
