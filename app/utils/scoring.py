from collections import Counter

from app.models import Evidence


def confidence_from_evidence(evidence: Evidence) -> int:
    category_bonus = {
        "exposure": 10,
        "touchpoint": 5,
        "mention": 0,
        "pivot": 7,
    }
    base = evidence.confidence
    return max(1, min(100, base + category_bonus.get(evidence.category, 0)))


def finding_severity(
    finding_type: str,
    evidence_count: int,
    has_critical_touchpoint: bool,
    downstream_relevance: bool,
) -> int:
    score = 1
    score += 1 if evidence_count >= 2 else 0
    score += 1 if evidence_count >= 5 else 0
    score += 1 if has_critical_touchpoint else 0
    score += 1 if downstream_relevance else 0

    if finding_type == "pivot":
        score = min(5, score + 1)

    return max(1, min(5, score))


def build_assumptions(evidences: list[Evidence]) -> list[str]:
    categories = Counter(e.category for e in evidences)
    assumptions = [
        "Inferences are probabilistic and based on publicly observable signals.",
        "No intrusive testing or unauthorized access was performed.",
    ]
    if categories.get("mention", 0) > categories.get("exposure", 0):
        assumptions.append("Narrative signal density is higher than technical exposure evidence.")
    if categories.get("touchpoint", 0) == 0:
        assumptions.append("Touchpoint visibility is limited; unseen channels may exist.")
    return assumptions
