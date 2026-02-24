from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable


@dataclass
class ConnectorTarget:
    company_name: str
    domain: str
    sector: str
    regions: str
    demo_mode: bool = False
    assessment_id: int | None = None
    examination_logger: Callable[..., None] | None = None

    def log_examination(
        self,
        *,
        url: str,
        source_type: str,
        status: str,
        discovered_from: str = "",
        http_status: int | None = None,
        content_hash: str = "",
        bytes_size: int | None = None,
        parse_summary: str = "",
        error_message: str = "",
        fetched_at: datetime | None = None,
    ) -> None:
        if not self.examination_logger:
            return
        self.examination_logger(
            url=url,
            source_type=source_type,
            status=status,
            discovered_from=discovered_from,
            http_status=http_status,
            content_hash=content_hash,
            bytes_size=bytes_size,
            parse_summary=parse_summary,
            error_message=error_message,
            fetched_at=fetched_at,
        )


@dataclass
class EvidencePayload:
    connector: str
    category: str
    title: str
    snippet: str
    source_url: str = ""
    confidence: int = 60
    observed_at: datetime = field(default_factory=datetime.utcnow)
    raw: dict[str, Any] = field(default_factory=dict)


class ConnectorBase:
    name: str = "base"
    requires_api_key: bool = False
    description: str = ""

    def ping(self, api_key: str | None = None) -> tuple[bool, str]:
        return True, "Connector ready"

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        raise NotImplementedError
