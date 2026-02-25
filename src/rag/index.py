from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
import json
import logging
from math import log
from pathlib import Path
import re

from sqlalchemy import select

from app.config import get_settings
from app.db import SessionLocal
from app.models import Document

logger = logging.getLogger(__name__)


QUERY_PLAN: list[dict[str, str]] = [
    {
        "id": "Q1",
        "query": "External Contact Channels support billing onboarding account management",
    },
    {
        "id": "Q2",
        "query": "Terze parti fornitori vendor provider partner integrazioni dichiarati impliciti",
    },
    {
        "id": "Q3",
        "query": "Dettagli operativi esposti ruoli tool processi escalation runbook",
    },
    {
        "id": "Q4",
        "query": "Asset identita canali ufficiali email telefoni portali domini social brand kit",
    },
    {
        "id": "Q5",
        "query": "Risk to Clients via Impersonation customers partners beneficiaries service delivery",
    },
    {
        "id": "Q6",
        "query": "Policy compliance privacy security acceptable use terms data protection",
    },
]

TOKEN_RE = re.compile(r"[a-z0-9@._+-]{2,}", re.IGNORECASE)
SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
DEFAULT_TOP_K = 4
BM25_K1 = 1.5
BM25_B = 0.75


@dataclass(slots=True)
class _Passage:
    id: int
    doc_id: int
    url: str
    title: str
    snippet: str
    token_count: int


def _index_dir() -> Path:
    target = get_settings().runtime_dir / "exports" / "rag_indexes"
    target.mkdir(parents=True, exist_ok=True)
    return target


def _index_path(assessment_id: int) -> Path:
    return _index_dir() / f"assessment_{assessment_id}.json"


def _tokenize(text: str) -> list[str]:
    return [tok.lower() for tok in TOKEN_RE.findall(text or "")]


def _chunk_text(text: str, chunk_words: int = 140, overlap: int = 35) -> list[str]:
    words = (text or "").split()
    if not words:
        return []
    if len(words) <= chunk_words:
        return [" ".join(words)]

    chunks: list[str] = []
    step = max(1, chunk_words - overlap)
    for start in range(0, len(words), step):
        end = min(len(words), start + chunk_words)
        part = " ".join(words[start:end]).strip()
        if part:
            chunks.append(part)
        if end >= len(words):
            break
    return chunks


def _compact_snippet(value: str, max_chars: int = 480) -> str:
    raw = re.sub(r"\s+", " ", (value or "").strip())
    return raw[:max_chars]


def _build_passages(rows: list[Document]) -> tuple[list[_Passage], dict[str, list[list[int]]], dict[str, int], float]:
    passages: list[_Passage] = []
    inverted: dict[str, list[list[int]]] = {}
    doc_freq: dict[str, int] = {}

    next_id = 0
    total_len = 0
    for row in rows:
        for chunk in _chunk_text(row.extracted_text):
            tokens = _tokenize(chunk)
            if not tokens:
                continue
            tf = Counter(tokens)
            passage = _Passage(
                id=next_id,
                doc_id=row.id,
                url=row.url,
                title=row.title,
                snippet=_compact_snippet(chunk),
                token_count=len(tokens),
            )
            passages.append(passage)
            total_len += len(tokens)
            next_id += 1

            for term, freq in tf.items():
                postings = inverted.setdefault(term, [])
                postings.append([passage.id, int(freq)])
            for term in tf.keys():
                doc_freq[term] = doc_freq.get(term, 0) + 1

    avgdl = (total_len / len(passages)) if passages else 0.0
    return passages, inverted, doc_freq, avgdl


def build_index(assessment_id: int) -> dict:
    """Build and persist a local BM25 index for one assessment."""
    with SessionLocal() as db:
        rows = (
            db.execute(
                select(Document).where(
                    Document.assessment_id == assessment_id,
                    Document.extracted_text != "",
                ).order_by(Document.id.asc())
            )
            .scalars()
            .all()
        )

    passages, inverted, doc_freq, avgdl = _build_passages(rows)
    payload = {
        "assessment_id": assessment_id,
        "built_at": datetime.utcnow().isoformat() + "Z",
        "num_documents": len(rows),
        "num_passages": len(passages),
        "avgdl": avgdl,
        "passages": [
            {
                "id": p.id,
                "doc_id": p.doc_id,
                "url": p.url,
                "title": p.title,
                "snippet": p.snippet,
                "token_count": p.token_count,
            }
            for p in passages
        ],
        "inverted_index": inverted,
        "doc_freq": doc_freq,
    }

    _index_path(assessment_id).write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")
    return {
        "assessment_id": assessment_id,
        "num_documents": len(rows),
        "num_passages": len(passages),
        "index_path": str(_index_path(assessment_id)),
    }


def _load_or_build(assessment_id: int) -> dict:
    path = _index_path(assessment_id)
    if not path.exists():
        build_index(assessment_id)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.exception("Failed to load rag index for assessment %s", assessment_id)
        return {}


def search(assessment_id: int, query: str, top_k: int = DEFAULT_TOP_K) -> list[dict]:
    """Search top passages for an assessment query."""
    index = _load_or_build(assessment_id)
    if not index:
        return []

    passages = index.get("passages", [])
    inverted = index.get("inverted_index", {})
    doc_freq = index.get("doc_freq", {})
    n = int(index.get("num_passages", 0))
    avgdl = float(index.get("avgdl", 0.0) or 0.0)
    if not passages or not n or avgdl <= 0:
        return []

    p_by_id = {int(p["id"]): p for p in passages}
    q_terms = _tokenize(query)
    if not q_terms:
        return []

    unique_terms = list(dict.fromkeys(q_terms))
    scores: dict[int, float] = {}
    for term in unique_terms:
        postings = inverted.get(term, [])
        if not postings:
            continue
        df = int(doc_freq.get(term, 0))
        if df <= 0:
            continue
        idf = log(1 + ((n - df + 0.5) / (df + 0.5)))
        for pid, tf in postings:
            passage = p_by_id.get(int(pid))
            if not passage:
                continue
            dl = max(1, int(passage.get("token_count", 1)))
            tf_value = float(tf)
            score = idf * ((tf_value * (BM25_K1 + 1)) / (tf_value + BM25_K1 * (1 - BM25_B + BM25_B * dl / avgdl)))
            scores[int(pid)] = scores.get(int(pid), 0.0) + score

    ranked = []
    for pid, value in scores.items():
        item = p_by_id.get(pid)
        if not item:
            continue
        snippet = str(item.get("snippet", ""))
        lower_snippet = snippet.lower()
        coverage = 0.0
        if unique_terms:
            coverage = sum(1 for term in unique_terms if term in lower_snippet) / len(unique_terms)
        rerank_score = value + (0.2 * coverage)
        ranked.append(
            {
                "passage_id": pid,
                "doc_id": item.get("doc_id"),
                "url": item.get("url", ""),
                "title": item.get("title", ""),
                "snippet": snippet,
                "score": round(rerank_score, 4),
            }
        )

    ranked.sort(
        key=lambda row: (
            -float(row.get("score", 0.0) or 0.0),
            str(row.get("url", "")),
            str(row.get("title", "")),
            str(row.get("snippet", "")),
            int(row.get("passage_id", 0) or 0),
        )
    )
    return ranked[: max(1, int(top_k))]


def _claim_from_snippet(snippet: str) -> str:
    text = (snippet or "").strip()
    if not text:
        return "No reliable statement extracted from retrieved passage."
    sentences = [s.strip() for s in SENTENCE_SPLIT_RE.split(text) if s.strip()]
    if not sentences:
        return text[:220]
    return sentences[0][:220]


def _build_gaps(query_id: str, results: list[dict]) -> list[str]:
    if not results:
        return [f"{query_id}: no relevant passages retrieved from indexed documents."]
    return [f"{query_id}: insufficient supporting passages, manual review required."]


def run_query_plan(assessment_id: int, top_k: int = DEFAULT_TOP_K, min_ratio: float = 0.70) -> dict:
    """Run fixed query plan and return claim candidates with citations or information gaps."""
    sections: list[dict] = []

    for item in QUERY_PLAN:
        query_id = item["id"]
        query_text = item["query"]
        # Pull a larger candidate set, then apply a relative threshold:
        # keep passages scoring at least `min_ratio * top1_score`.
        candidates = search(assessment_id, query_text, top_k=max(20, int(top_k) * 6))
        if not candidates:
            sections.append(
                {
                    "query_id": query_id,
                    "query": query_text,
                    "findings_candidates": [],
                    "information_gaps": _build_gaps(query_id, []),
                }
            )
            continue

        top1 = float(candidates[0].get("score", 0.0) or 0.0)
        threshold = top1 * float(min_ratio or 0.70)
        strong = [r for r in candidates if float(r.get("score", 0.0) or 0.0) >= threshold]
        strong.sort(
            key=lambda row: (
                -float(row.get("score", 0.0) or 0.0),
                str(row.get("url", "")),
                str(row.get("title", "")),
                str(row.get("snippet", "")),
                int(row.get("passage_id", 0) or 0),
            )
        )
        strong = strong[: max(1, int(top_k))]

        if len(strong) < 1:
            sections.append(
                {
                    "query_id": query_id,
                    "query": query_text,
                    "findings_candidates": [],
                    "information_gaps": _build_gaps(query_id, candidates),
                }
            )
            continue

        findings_candidates = []
        for row in strong[:4]:
            findings_candidates.append(
                {
                    "claim": _claim_from_snippet(row.get("snippet", "")),
                    "citations": [
                        {
                            "doc_id": row.get("doc_id"),
                            "url": row.get("url", ""),
                            "title": row.get("title", ""),
                            "snippet": row.get("snippet", ""),
                            "score": row.get("score", 0.0),
                        }
                    ],
                }
            )

        sections.append(
            {
                "query_id": query_id,
                "query": query_text,
                "top1_score": round(top1, 4),
                "threshold_score": round(threshold, 4),
                "min_ratio": float(min_ratio or 0.70),
                "findings_candidates": findings_candidates,
                "information_gaps": [],
            }
        )

    return {
        "assessment_id": assessment_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "sections": sections,
    }


def debug_query_plan(assessment_id: int, top_k: int = 5) -> dict:
    """Return retrieval debug for each fixed query-plan item."""
    index = _load_or_build(assessment_id)
    num_documents = int(index.get("num_documents", 0) or 0) if index else 0
    num_passages = int(index.get("num_passages", 0) or 0) if index else 0

    sections: list[dict] = []
    for item in QUERY_PLAN:
        query_id = item["id"]
        query_text = item["query"]
        results = search(assessment_id, query_text, top_k=max(1, int(top_k)))
        sections.append(
            {
                "query_id": query_id,
                "query": query_text,
                "top_passages": results[: max(1, int(top_k))],
                "has_results": bool(results),
                "hint": "" if results else "index empty / collector failed",
            }
        )

    return {
        "assessment_id": assessment_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "num_documents": num_documents,
        "num_passages": num_passages,
        "sections": sections,
        "global_hint": "" if num_passages > 0 else "index empty / collector failed",
    }
