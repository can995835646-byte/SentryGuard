from dataclasses import dataclass, field
from typing import List


@dataclass
class ThreatResult:
    event_id: str
    timestamp: str
    title: str
    threat_level: str  # "high" | "medium" | "low" | "clean"
    detected_patterns: List[str] = field(default_factory=list)
    payload_preview: str = ""

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "title": self.title,
            "threat_level": self.threat_level,
            "detected_patterns": self.detected_patterns,
            "payload_preview": self.payload_preview,
        }
