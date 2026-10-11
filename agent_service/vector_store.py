"""Layer 4: the vector store (Weaviate) and the document loader.

Two jobs live here:

1. Loading (the "ingest" job, run once before the agents start):
   read the approved documents, split them into passages, hold back any
   paragraph that contains hidden instructions, turn each passage into an
   embedding and store it in Weaviate together with where it came from
   (file, section, classification, file fingerprint and load time).
   Recording where each passage came from is called data lineage.
   When the stored passages already match the documents' fingerprints the
   load is skipped, so restarting the platform never empties the store
   while the agents are answering.

2. Searching (used by the Executor agent, the only tool it may call):
   hybrid search, which combines meaning-based search over the embeddings
   with keyword search (BM25), filtered to the document classifications
   the caller's role may read. Results are scanned again for hidden
   instructions before they are used (defence in depth).

An embedding is a list of numbers that represents the meaning of a piece
of text, so that texts with similar meanings have similar numbers. The
small all-MiniLM-L6-v2 model (the same one used in the monitored
retrieval service) is built into the container image, so no internet
access is needed at run time.

Run the loader with:  python -m agent_service.vector_store ingest
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("vector_store")

KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"

# Which roles may read each document. Anything not listed is treated as
# internal, so a new file is never exposed to viewers by accident.
DOCUMENT_CLASSIFICATION = {
    "acceptable_use_policy.pdf": "public",
    "security_incident_management_policy.pdf": "internal",
    "soc_first_response_runbook.md": "internal",
}
DEFAULT_CLASSIFICATION = "internal"
MAX_PASSAGE_CHARS = 800

# Identical to INJECTION_PATTERNS in gateway/guardrails.py. A unit test
# fails if the two copies differ, so they cannot drift apart unnoticed.
INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+"
     r"(instructions?|prompts?|rules?|directions?|messages?)", "tries to override earlier instructions"),
    (r"disregard\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|your)\s+"
     r"(instructions?|prompts?|rules?|guidelines?)", "tries to override earlier instructions"),
    (r"forget\s+(everything|all\s+previous|your\s+(instructions?|rules?|training))",
     "tries to erase earlier instructions"),
    (r"(reveal|show|print|repeat|display|output|leak)\s+(me\s+)?(your\s+|the\s+)?"
     r"(system\s+prompt|hidden\s+prompt|initial\s+instructions?|secret)", "tries to expose the hidden system prompt"),
    (r"you\s+are\s+now\s+(a\s+|an\s+|in\s+|free|unrestricted|unfiltered|jailbroken)",
     "tries to give the model a new identity"),
    (r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(an?\s+)?(unrestricted|unfiltered|jailbroken|different)\s*(ai|assistant|model)?",
     "tries to switch the model into an unrestricted role"),
    (r"developer\s+mode", "references the well-known developer mode jailbreak"),
    (r"\bdo\s+anything\s+now\b|\bdan\s+mode\b", "references the DAN jailbreak"),
    (r"\bjailbreak(ed|ing)?\b", "openly references jailbreaking"),
    (r"override\s+(the\s+)?(safety|security|system|guard|filter)", "tries to switch off safety controls"),
    (r"new\s+(system\s+)?instructions?\s*:", "tries to inject replacement instructions"),
    (r"^\s*system\s*:", "pretends to be a system message"),
    (r"pretend\s+(that\s+)?you\s+(have\s+no|are\s+not\s+bound\s+by)\s+(rules?|restrictions?|guidelines?|limits?)",
     "tries to talk the model out of its rules"),
]
_INJECTION = [(re.compile(p, re.IGNORECASE), reason) for p, reason in INJECTION_PATTERNS]
_INVISIBLE = dict.fromkeys([0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF, 0x00AD, 0x2060])


def injection_reasons(text: str) -> list[str]:
    """Returns why a piece of text looks like hidden instructions (empty if clean)."""
    cleaned = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text).translate(_INVISIBLE).lower()).strip()
    return [reason for pattern, reason in _INJECTION if pattern.search(cleaned)]


# ---------------------------------------------------------------------------
# Reading and splitting documents.
# ---------------------------------------------------------------------------
@dataclass
class Passage:
    """One searchable piece of a document, with where it came from."""

    text: str
    source: str
    title: str
    section: str
    classification: str
    chunk_index: int = 0
    sha256: str = ""
    score: float = 0.0


@dataclass
class IngestReport:
    documents: int = 0
    passages: int = 0
    quarantined: list[dict] = field(default_factory=list)
    by_classification: dict[str, int] = field(default_factory=dict)
    up_to_date: bool = False


def read_text(path: Path) -> str:
    """Extracts plain text from a Markdown or PDF file."""
    if path.suffix.lower() == ".pdf":
        from pypdf import PdfReader  # imported here so unit tests do not need it

        return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
    return path.read_text(encoding="utf-8")


def _looks_like_heading(line: str) -> bool:
    """Short, no closing punctuation and every longer word capitalised, like "Core Requirements"."""
    words = line.replace(",", " ").split()
    return (0 < len(words) <= 7 and len(line) <= 60 and not line.endswith((".", ":", ";", "?", "!"))
            and not line[0].isdigit() and all(w[0].isupper() for w in words if len(w) > 3))


def split_into_units(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Rebuilds paragraphs and section headings from extracted text.

    Returns the document title and a list of (section, paragraph) pairs.
    PDF text arrives as wrapped lines without blank lines, so a paragraph
    ends at a line that finishes a sentence and a short line without a
    full stop is treated as a section heading.
    """
    lines = [line.strip() for line in text.splitlines()]
    title, section, units, buffer = "", "", [], []

    def flush() -> None:
        if buffer:
            units.append((section, " ".join(buffer)))
            buffer.clear()

    for line in lines:
        if not line:
            flush()
            continue
        if not title:
            title = line.lstrip("#").strip()
            continue
        if line.startswith("#"):
            flush()
            section = line.lstrip("#").strip()
            continue
        if not buffer and _looks_like_heading(line):
            section = line
            continue
        buffer.append(line)
        if line.endswith((".", "?", "!")):
            flush()
    flush()
    return title, units


def build_passages(path: Path, report: IngestReport) -> list[Passage]:
    """Turns one document into passages, holding back unsafe paragraphs."""
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    classification = DOCUMENT_CLASSIFICATION.get(path.name, DEFAULT_CLASSIFICATION)
    title, units = split_into_units(read_text(path))

    passages: list[Passage] = []
    current_section, current = None, []

    def close() -> None:
        if current:
            passages.append(Passage(text=" ".join(current), source=path.name, title=title,
                                    section=current_section or "", classification=classification,
                                    chunk_index=len(passages), sha256=sha))
            current.clear()

    for section, unit in units:
        reasons = injection_reasons(unit)
        if reasons:
            # Kept out of the store entirely and recorded for review.
            report.quarantined.append({"source": path.name, "section": section, "reasons": reasons,
                                       "preview": unit[:80]})
            continue
        if section != current_section or sum(len(u) for u in current) + len(unit) > MAX_PASSAGE_CHARS:
            close()
            current_section = section
        current.append(unit)
    close()
    report.documents += 1
    report.passages += len(passages)
    report.by_classification[classification] = report.by_classification.get(classification, 0) + len(passages)
    return passages


# ---------------------------------------------------------------------------
# Embeddings.
# ---------------------------------------------------------------------------
class Embedder:
    """Turns text into embeddings with the all-MiniLM-L6-v2 model (384 numbers each)."""

    def __init__(self, model_name: str, cache_dir: str | None = None):
        from fastembed import TextEmbedding  # imported here so unit tests do not need it

        self._model = TextEmbedding(model_name=model_name, cache_dir=cache_dir)

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [vector.tolist() for vector in self._model.embed(texts)]


# ---------------------------------------------------------------------------
# The Weaviate store.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class StoreSettings:
    host: str = "weaviate"
    http_port: int = 8080
    grpc_port: int = 50051
    collection: str = "SecOpsKnowledge"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    model_cache_dir: str | None = None
    top_k: int = 4
    hybrid_alpha: float = 0.5

    @classmethod
    def from_env(cls) -> "StoreSettings":
        return cls(
            host=os.getenv("WEAVIATE_HOST", cls.host),
            http_port=int(os.getenv("WEAVIATE_HTTP_PORT", str(cls.http_port))),
            grpc_port=int(os.getenv("WEAVIATE_GRPC_PORT", str(cls.grpc_port))),
            collection=os.getenv("COLLECTION_NAME", cls.collection),
            embedding_model=os.getenv("EMBEDDING_MODEL", cls.embedding_model),
            model_cache_dir=os.getenv("MODEL_CACHE_DIR") or None,
            top_k=int(os.getenv("TOP_K", str(cls.top_k))),
            hybrid_alpha=float(os.getenv("HYBRID_ALPHA", str(cls.hybrid_alpha))),
        )


class KnowledgeStore:
    """Connects to Weaviate and runs the loading and the hybrid search."""

    def __init__(self, settings: StoreSettings, embedder: Embedder | None = None):
        self.settings = settings
        self._embedder = embedder
        self._client = None

    # ----------------------------------------------------------- plumbing
    @property
    def embedder(self) -> Embedder:
        if self._embedder is None:
            self._embedder = Embedder(self.settings.embedding_model, self.settings.model_cache_dir)
        return self._embedder

    def connect(self, wait_seconds: int = 120):
        """Connects to Weaviate, waiting for it to be ready if it is still starting."""
        import weaviate
        from weaviate.config import AdditionalConfig, Timeout

        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                client = weaviate.connect_to_custom(
                    http_host=self.settings.host, http_port=self.settings.http_port, http_secure=False,
                    grpc_host=self.settings.host, grpc_port=self.settings.grpc_port, grpc_secure=False,
                    additional_config=AdditionalConfig(timeout=Timeout(init=10, query=30, insert=120)),
                    # Skips the client's own start-up checks, one of which looks up the
                    # latest client version on the internet. The data network has no
                    # internet access, so readiness is checked directly below instead.
                    skip_init_checks=True,
                )
                if client.is_ready():
                    self._client = client
                    return client
                client.close()
            except Exception as error:  # Weaviate still starting
                if time.monotonic() > deadline:
                    raise RuntimeError(f"Weaviate was not ready after {wait_seconds} seconds: {error}") from error
            if time.monotonic() > deadline:
                raise RuntimeError(f"Weaviate was not ready after {wait_seconds} seconds")
            time.sleep(3)

    @property
    def client(self):
        if self._client is None:
            self.connect()
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # ------------------------------------------------------------ loading
    def recreate_collection(self):
        """Drops and recreates the collection, so every load starts clean."""
        from weaviate.classes.config import Configure, DataType, Property, Tokenization

        name = self.settings.collection
        if self.client.collections.exists(name):
            self.client.collections.delete(name)
        return self.client.collections.create(
            name=name,
            # We supply our own embeddings (computed in this container).
            vector_config=Configure.Vectors.self_provided(),
            properties=[
                Property(name="text", data_type=DataType.TEXT),
                Property(name="title", data_type=DataType.TEXT),
                Property(name="section", data_type=DataType.TEXT),
                # Labels, not prose: kept out of keyword scoring, matched exactly.
                Property(name="source", data_type=DataType.TEXT, index_searchable=False,
                         tokenization=Tokenization.FIELD),
                Property(name="classification", data_type=DataType.TEXT, index_searchable=False,
                         tokenization=Tokenization.FIELD),
                Property(name="sha256", data_type=DataType.TEXT, index_searchable=False,
                         tokenization=Tokenization.FIELD),
                Property(name="chunk_index", data_type=DataType.INT),
                Property(name="ingested_at", data_type=DataType.DATE),
            ],
        )

    def loaded_fingerprints(self) -> tuple[set[tuple[str, str]], int]:
        """What the store holds now: (file, fingerprint) pairs and the passage count."""
        name = self.settings.collection
        if not self.client.collections.exists(name):
            return set(), 0
        collection = self.client.collections.get(name)
        count = collection.aggregate.over_all(total_count=True).total_count or 0
        objects = collection.query.fetch_objects(limit=10000, return_properties=["source", "sha256"]).objects
        return {(o.properties.get("source", ""), o.properties.get("sha256", "")) for o in objects}, count

    def ingest(self, folder: Path = KNOWLEDGE_DIR, force: bool = False) -> IngestReport:
        """Loads every approved document in the folder into a fresh collection.

        Skips the load when the store already holds exactly these documents
        (same fingerprints, same number of passages), unless force is set.
        """
        from weaviate.util import generate_uuid5

        report = IngestReport()
        passages: list[Passage] = []
        for path in sorted(folder.iterdir()):
            if path.suffix.lower() in {".md", ".pdf"}:
                passages.extend(build_passages(path, report))

        if not force:
            loaded, count = self.loaded_fingerprints()
            if count == len(passages) and loaded == {(p.source, p.sha256) for p in passages}:
                report.up_to_date = True
                return report

        collection = self.recreate_collection()
        vectors = self.embedder.embed([f"{p.title}. {p.section}. {p.text}" for p in passages])
        loaded_at = datetime.now(timezone.utc)
        with collection.batch.fixed_size(batch_size=64) as batch:
            for passage, vector in zip(passages, vectors):
                batch.add_object(
                    properties={"text": passage.text, "title": passage.title, "section": passage.section,
                                "source": passage.source, "classification": passage.classification,
                                "sha256": passage.sha256, "chunk_index": passage.chunk_index,
                                "ingested_at": loaded_at},
                    vector=vector,
                    uuid=generate_uuid5(f"{passage.source}:{passage.chunk_index}:{passage.sha256}"),
                )
        failed = collection.batch.failed_objects
        if failed:
            raise RuntimeError(f"{len(failed)} passages failed to load: {failed[0].message}")
        return report

    # ---------------------------------------------------------- searching
    def stats(self) -> dict:
        """Counts what is loaded, for the health check and the console."""
        name = self.settings.collection
        if not self.client.collections.exists(name):
            return {"ready": False, "passages": 0, "documents": 0}
        collection = self.client.collections.get(name)
        passages = collection.aggregate.over_all(total_count=True).total_count or 0
        sources = {o.properties["source"] for o in collection.query.fetch_objects(
            limit=1000, return_properties=["source"]).objects}
        return {"ready": passages > 0, "passages": passages, "documents": len(sources)}

    def search(self, query: str, clearance: list[str]) -> tuple[list[Passage], int]:
        """Hybrid search limited to the caller's clearance.

        Returns the passages and how many were dropped by the safety scan.
        """
        from weaviate.classes.query import Filter, MetadataQuery

        collection = self.client.collections.get(self.settings.collection)
        response = collection.query.hybrid(
            query=query,                                  # keyword (BM25) half
            vector=self.embedder.embed([query])[0],       # meaning (vector) half
            alpha=self.settings.hybrid_alpha,             # 0.5 = equal weight
            limit=self.settings.top_k,
            filters=Filter.by_property("classification").contains_any(clearance),
            return_metadata=MetadataQuery(score=True),
        )
        passages, dropped = [], 0
        for obj in response.objects:
            props = obj.properties
            if injection_reasons(props.get("text", "")):
                dropped += 1
                continue
            passages.append(Passage(text=props.get("text", ""), source=props.get("source", ""),
                                    title=props.get("title", ""), section=props.get("section", ""),
                                    classification=props.get("classification", ""),
                                    chunk_index=int(props.get("chunk_index") or 0),
                                    sha256=props.get("sha256", ""),
                                    score=round(float(obj.metadata.score or 0.0), 4)))
        return passages, dropped


def main(argv: list[str] | None = None) -> int:
    """Command line entry point for the one-off ingest job."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description="Load the approved documents into Weaviate.")
    parser.add_argument("command", choices=["ingest", "stats"])
    parser.add_argument("--folder", default=str(KNOWLEDGE_DIR))
    parser.add_argument("--force", action="store_true", help="reload even when the documents are unchanged")
    args = parser.parse_args(argv)

    store = KnowledgeStore(StoreSettings.from_env())
    try:
        store.connect()
        if args.command == "ingest":
            report = store.ingest(Path(args.folder), force=args.force)
            print(json.dumps({"event": "ingest_completed", **report.__dict__}, indent=2))
        else:
            print(json.dumps(store.stats(), indent=2))
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
