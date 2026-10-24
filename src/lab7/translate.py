"""Translate a natural-language network intent into the lab policy schema."""

from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path

import requests

from lab7.schema import check_schema


MODEL = "gemini-3.5-flash-lite"
API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    f"{MODEL}:generateContent"
)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = PROJECT_ROOT / ".env"

SYSTEM_INSTRUCTION = textwrap.dedent(
    """
    You are a network policy translator for a small OpenFlow 1.3 network.
    The live topology is one switch, s1, and four hosts on 10.0.0.0/24:

    - h1, 10.0.0.1, MAC 00:00:00:00:00:01
    - h2, 10.0.0.2, MAC 00:00:00:00:00:02
    - h3, 10.0.0.3, MAC 00:00:00:00:00:03
    - h4, 10.0.0.4, MAC 00:00:00:00:00:04

    Convert the operator's intent into one JSON object and nothing else.
    No preamble, no explanation, and no markdown fences.

    The object has two fields:
    - summary: one sentence restating the intent
    - rules: a non-empty list of rule objects, most specific first

    Each rule has exactly these fields:
    - action: "block", "allow", "rate_limit", or "prioritize"
    - direction: "unidirectional" for "from A to B", "bidirectional" for "between A and B"
    - source: a host name (h1), an IPv4 address, an IPv4 CIDR, or "any"
    - destination: same forms as source
    - protocol: "any", "ip", "icmp", "tcp", "udp", or "arp"
    - port: an integer from 0 to 65535, or null
    - port_field: "destination" or "source" when port is set, otherwise null
    - parameters: an object that always includes "priority" (integer 1-65535)

    Action rules:
    - block drops matching traffic. parameters contains only priority. Use 100.
    - allow forwards matching traffic. parameters contains only priority. Use 100.
    - rate_limit forwards matching traffic up to a cap. parameters must include
      rate_kbps (kilobits per second) and priority. burst_kb is optional.
    - prioritize forwards matching traffic ahead of best-effort. Use priority 300
      unless the operator names one. Include dscp (0-63) or queue_id (0-7) only
      when the operator asks for a mark or a queue.

    Translation rules:
    - Use the host name when the operator names h1, h2, h3, or h4.
    - Use "any" for "any host", "all hosts", or an omitted endpoint.
    - Use a CIDR only when the operator names a subnet.
    - "All traffic" with no protocol and no port is protocol "any" and port null.
    - A named port with no protocol is tcp. "Port 80" means destination port 80.
    - ICMP and ARP never have a port.
    - "Allow only X between A and B" is two bidirectional rules with the same
      endpoints: an allow for X at priority 200, then a block of protocol "any"
      at priority 100.
    - Do not invent hosts, protocols, or rates the operator did not state.
    - If several rules are required, keep them in one object under rules.

    Example. Intent: "Block all traffic from h1 to h3"
    {"summary":"Drop every packet from h1 to h3.","rules":[{"action":"block","direction":"unidirectional","source":"h1","destination":"h3","protocol":"any","port":null,"port_field":null,"parameters":{"priority":100}}]}

    Example. Intent: "Allow only ICMP traffic between h2 and h4"
    {"summary":"Allow ICMP between h2 and h4 and drop every other packet between them.","rules":[{"action":"allow","direction":"bidirectional","source":"h2","destination":"h4","protocol":"icmp","port":null,"port_field":null,"parameters":{"priority":200}},{"action":"block","direction":"bidirectional","source":"h2","destination":"h4","protocol":"any","port":null,"port_field":null,"parameters":{"priority":100}}]}
    """
).strip()


class IntentTranslationError(Exception):
    """The model response was not valid JSON matching the policy schema."""


def load_api_key() -> str:
    """Read GEMINI_API_KEY from the environment, then from the project .env file."""

    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if key:
        return key

    if ENV_PATH.is_file():
        for line in ENV_PATH.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name.strip() != "GEMINI_API_KEY":
                continue
            value = value.strip().strip('"').strip("'")
            if value:
                return value

    raise IntentTranslationError(
        "GEMINI_API_KEY is not set. Add it to .env in the project root "
        "or export it in the shell."
    )


def translate_intent(intent_string: str) -> dict:
    """Translate a natural-language policy into a schema-valid dictionary.

    Raises IntentTranslationError when the model response is not valid JSON
    matching the policy schema, or when the API cannot be reached.
    """

    intent = intent_string.strip()
    if not intent:
        raise IntentTranslationError("Intent string is empty.")

    api_key = load_api_key()
    policy, raw, error = _request_policy(intent, api_key, correction=None)
    if policy is not None:
        return policy

    policy, raw, error = _request_policy(intent, api_key, correction=error)
    if policy is not None:
        return policy

    preview = raw.strip()
    if len(preview) > 800:
        preview = preview[:800] + "..."
    raise IntentTranslationError(
        f"{error} Raw model response: {preview or '<empty>'}"
    )


def _request_policy(
    intent: str,
    api_key: str,
    *,
    correction: str | None,
) -> tuple[dict | None, str, str]:
    """Return (policy, raw text, error). Policy is None when parsing fails."""

    user_text = f"Translate this network intent:\n{intent}"
    if correction:
        user_text += (
            "\n\nThe previous response was rejected:\n"
            f"{correction}\n"
            "Return only one corrected JSON object matching the schema."
        )

    try:
        response = requests.post(
            API_URL,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            },
            json={
                "systemInstruction": {
                    "parts": [{"text": SYSTEM_INSTRUCTION}],
                },
                "contents": [
                    {
                        "role": "user",
                        "parts": [{"text": user_text}],
                    }
                ],
                "generationConfig": {
                    "temperature": 0,
                    "maxOutputTokens": 2048,
                    "responseMimeType": "application/json",
                },
            },
            timeout=60,
        )
    except requests.exceptions.RequestException as exc:
        raise IntentTranslationError(f"Failed to reach the Gemini API: {exc}") from exc

    if not response.ok:
        raise IntentTranslationError(
            f"Gemini API request failed with status {response.status_code}: "
            f"{response.text.strip()}"
        )

    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        return None, response.text, f"Gemini response was not JSON: {exc}"

    raw = _extract_text(payload)
    if not raw:
        return None, json.dumps(payload), "Gemini returned no text."

    try:
        policy = _parse_policy(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        return None, raw, str(exc)

    return policy, raw, ""


def _extract_text(payload: dict) -> str:
    """Return the model's text, omitting internal thought parts."""

    candidates = payload.get("candidates") or []
    if not candidates:
        return ""

    parts = candidates[0].get("content", {}).get("parts") or []
    texts = []
    for part in parts:
        if part.get("thought"):
            continue
        text = part.get("text")
        if text:
            texts.append(text)
    return "\n".join(texts).strip()


def _parse_policy(text: str) -> dict:
    """Parse model text and require the policy schema."""

    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    try:
        policy = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise json.JSONDecodeError(
            f"Response is not valid JSON: {exc.msg}",
            exc.doc,
            exc.pos,
        ) from exc

    try:
        check_schema(policy)
    except ValueError as exc:
        raise ValueError(f"Response JSON does not match the policy schema: {exc}") from exc

    return policy
