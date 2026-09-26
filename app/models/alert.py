from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Alert:
    id: str
    type: str
    severity: str
    status: str
    timestamp: datetime
    description: str
    user: Optional[str] = None
    source_ip: Optional[str] = None
    evidence: list[str] = field(default_factory=list)