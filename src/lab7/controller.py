"""Ask for an intent, show the translation, and install it after confirmation."""

from __future__ import annotations

import json
import sys

from lab7.apply import PolicyApplyError, apply_policy
from lab7.translate import IntentTranslationError, translate_intent
from lab7.validate import validate_policy


def run_intent_controller() -> None:
    """Translate one typed intent and install it only after a yes answer."""

    intent = input("Intent: ").strip()
    if not intent:
        print("No intent entered.")
        return
    review_and_apply(intent)


def run_voice_intent_controller(duration: float = 5.0) -> None:
    """Transcribe a spoken intent, validate it, and install it after a yes."""

    from lab7.voice import capture_voice_intent

    intent = capture_voice_intent(duration)
    print(f"Transcription: {intent}")
    if not intent:
        print("No speech was transcribed.")
        return
    review_and_apply(intent)


def review_and_apply(intent: str) -> None:
    """Translate, validate, confirm, and maybe install one intent string."""

    policy = translate_intent(intent)
    print(json.dumps(policy, indent=2))

    rejection = validate_policy(policy)
    if rejection:
        print(rejection)
        return

    answer = input("Apply this policy? (yes/no) ").strip().lower()
    if answer != "yes":
        print("Policy not applied.")
        return

    apply_policy(policy)
    print("The rule is active.")


def main() -> None:
    try:
        run_intent_controller()
    except (IntentTranslationError, PolicyApplyError) as exc:
        print(f"Controller error: {exc}")
        raise SystemExit(1) from exc


def voice_main() -> None:
    duration = 5.0
    if len(sys.argv) > 1:
        duration = float(sys.argv[1])
    try:
        run_voice_intent_controller(duration)
    except (IntentTranslationError, PolicyApplyError, ValueError) as exc:
        print(f"Controller error: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
