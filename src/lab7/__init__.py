import json
import sys

from lab7.translate import IntentTranslationError, translate_intent


def main() -> None:
    """Translate one intent from the command line and print the JSON."""

    if len(sys.argv) < 2:
        print('Usage: lab7 "<natural language policy>"')
        raise SystemExit(2)

    intent = " ".join(sys.argv[1:])
    try:
        policy = translate_intent(intent)
    except IntentTranslationError as exc:
        print(f"Translation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(json.dumps(policy, indent=2))
