from collections import defaultdict

from app.models import Assessment, Edge, Evidence, Finding, Node
from app.utils.jsonx import from_json, to_json


def rebuild_graph(assessment: Assessment, evidences: list[Evidence]) -> tuple[list[Node], list[Edge]]:
    nodes: list[Node] = []
    edges: list[Edge] = []

    center = Node(
        assessment_id=assessment.id,
        label=assessment.company_name,
        type="company",
        confidence=95,
        meta_json=to_json({"domain": assessment.domain}),
    )
    nodes.append(center)

    buckets = defaultdict(list)
    for ev in evidences:
        buckets[ev.category].append(ev)

    for category, items in buckets.items():
        label = {
            "exposure": "Public Information Exposure",
            "mention": "Mentions & Narrative",
            "touchpoint": "External Contact Channels",
            "pivot": "Risk to Clients via Impersonation",
        }.get(category, category.title())
        conf = int(sum(i.confidence for i in items) / max(1, len(items)))
        node = Node(
            assessment_id=assessment.id,
            label=label,
            type=category,
            confidence=conf,
            meta_json=to_json({"count": len(items)}),
        )
        nodes.append(node)

    # Leaf nodes for key evidences (top 12 by confidence)
    top_evidences = sorted(evidences, key=lambda x: x.confidence, reverse=True)[:12]
    for ev in top_evidences:
        leaf = Node(
            assessment_id=assessment.id,
            label=ev.title[:70],
            type="signal",
            confidence=ev.confidence,
            meta_json=to_json({"evidence_id": ev.id, "category": ev.category}),
        )
        nodes.append(leaf)

    # Edges are built later after nodes persist and IDs are available.
    return nodes, edges


def build_edges_for_persisted_nodes(assessment_id: int, nodes: list[Node]) -> list[Edge]:
    by_type = defaultdict(list)
    for n in nodes:
        by_type[n.type].append(n)

    center = by_type.get("company", [None])[0]
    if not center:
        return []

    edges: list[Edge] = []
    for category in ["exposure", "mention", "touchpoint", "pivot"]:
        for node in by_type.get(category, []):
            edges.append(
                Edge(
                    assessment_id=assessment_id,
                    from_node_id=center.id,
                    to_node_id=node.id,
                    relation_type=f"has_{category}",
                    weight=1.2,
                    meta_json=to_json({"derived": True}),
                )
            )

    # Link signal nodes to best parent based on category in meta
    category_parents = {}
    for category in ["exposure", "mention", "touchpoint", "pivot"]:
        if by_type.get(category):
            category_parents[category] = by_type[category][0]

    for signal in by_type.get("signal", []):
        meta = from_json(signal.meta_json, {})
        category = meta.get("category", "exposure")
        parent = category_parents.get(category, center)
        edges.append(
            Edge(
                assessment_id=assessment_id,
                from_node_id=parent.id,
                to_node_id=signal.id,
                relation_type="supported_by",
                weight=0.8,
                meta_json=to_json({"category": category}),
            )
        )

    return edges


def findings_by_type(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped = {"exposure": [], "mention": [], "touchpoint": [], "pivot": []}
    for finding in findings:
        grouped.setdefault(finding.type, []).append(finding)
    return grouped
