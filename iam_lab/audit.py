
import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    def __init__(self):
        self.events = []

        # Project root ke andar logs folder ka path.
        project_root = Path(__file__).resolve().parent.parent
        self.log_dir = project_root / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.log_file = self.log_dir / "iam_audit.log"

    def log_event(
        self,
        action: str,
        username: str,
        outcome: str,
        details: str = "",
    ) -> dict:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "username": username,
            "outcome": outcome,
            "details": details,
        }

        # Current program ke liye event memory mein rakho.
        self.events.append(event)

        # Har event ko file mein separate JSON line par save karo.
        with self.log_file.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")

        return event

    def get_events(self) -> list[dict]:
        return self.events.copy()


