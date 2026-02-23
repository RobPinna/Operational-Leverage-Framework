from datetime import datetime

from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload


MOCK_POSTS = [
    {
        "title": "Community thread questions invoice portal legitimacy",
        "tone": "concerned",
        "theme": "billing impersonation",
        "community": "regional business forum",
    },
    {
        "title": "Volunteer group discusses fake donation messages",
        "tone": "alarmed",
        "theme": "charity spoofing",
        "community": "ngo supporters",
    },
    {
        "title": "Customer post cites delayed support responses",
        "tone": "frustrated",
        "theme": "support trust",
        "community": "social feed",
    },
    {
        "title": "Industry chatter links brand with partner onboarding scams",
        "tone": "neutral",
        "theme": "partner pivot",
        "community": "supply chain group",
    },
]


class SocialMockConnector(ConnectorBase):
    name = "social_mock"
    description = "Generates realistic social mention signals without API keys"

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        evidences: list[EvidencePayload] = []
        for idx, post in enumerate(MOCK_POSTS, start=1):
            source_url = f"mock://social/mention/{idx}"
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="mention",
                    title=f"{target.company_name}: {post['title']}",
                    snippet=(
                        f"Theme={post['theme']}; Tone={post['tone']}; Community={post['community']}"
                    ),
                    source_url=source_url,
                    confidence=58 if target.demo_mode else 45,
                    raw={"target": target.company_name, **post},
                )
            )
            target.log_examination(
                url=source_url,
                source_type="manual",
                status="parsed",
                discovered_from="social mock dataset",
                parse_summary=post["title"][:200],
                fetched_at=datetime.utcnow(),
            )

        return evidences
