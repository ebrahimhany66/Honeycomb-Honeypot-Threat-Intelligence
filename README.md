# Honeycomb

A honeypot that turns real attacks into evidence-based block decisions, approved by a human analyst.

## Quick start

    python -m venv .venv
    source .venv/Scripts/activate      # macOS/Linux: source .venv/bin/activate
    pip install -r requirements.txt pytest
    cp .env.example .env               # put your API keys in .env only
    python -m pytest

## Team rules
- Every change goes through a branch, a Pull Request, and a review by another member. No direct pushes to main.
- Never commit: API keys, real logs, PCAPs, databases, or malware.
- Changes to the event contract (contracts/event.md) must be approved by Member 2 and announced to the team.
- Changes to scoring or the whitelist go in a separate PR.
- Daily 10-minute standup in the team chat: what I did, what I will do, what I am blocked on.
