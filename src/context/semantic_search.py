import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import config

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    score: float
    content: str
    metadata: Dict[str, Any]


class SemanticSearch:
    def __init__(self, backend_preference: Optional[str] = None, persist_dir: Optional[Path] = None):
        self.documents: List[str] = []
        self.metadatas: List[Dict[str, Any]] = []
        self.mode = "keyword"
        self.model = None
        self.vectorizer = None
        self.embeddings = None
        self.persist_dir = Path(persist_dir or config.SEMANTIC_CACHE_DIR)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.backend_preference = (backend_preference or config.SEMANTIC_BACKEND or "keyword").lower()
        self.faiss_index = None
        self.faiss = None
        self.faiss_index_path = self.persist_dir / "semantic.index"
        self.faiss_meta_path = self.persist_dir / "semantic_meta.json"
        self.chroma_client = None
        self.chroma_collection = None
        self._init_backend()

    def _init_backend(self) -> None:
        preferred = self.backend_preference
        if preferred == "auto":
            order = ["faiss", "chroma", "neural", "tfidf", "keyword"]
        else:
            order = [preferred, "keyword"] if preferred != "keyword" else ["keyword"]

        for backend in order:
            if backend == "faiss" and self._init_faiss():
                return
            if backend == "chroma" and self._init_chroma():
                return
            if backend == "neural" and self._init_neural():
                return
            if backend == "tfidf" and self._init_tfidf():
                return
            if backend == "keyword":
                self._init_keyword()
                return

        # Always have a fallback
        self._init_keyword()

    def _init_faiss(self) -> bool:
        try:
            import faiss  # type: ignore
            import numpy as np
            from sentence_transformers import SentenceTransformer

            self.faiss = faiss
            if self.model is None:
                self.model = SentenceTransformer("all-MiniLM-L6-v2")
            if self.faiss_index_path.exists() and self.faiss_meta_path.exists():
                try:
                    self.faiss_index = faiss.read_index(str(self.faiss_index_path))
                    with open(self.faiss_meta_path, "r", encoding="utf-8") as fh:
                        persisted = json.load(fh)
                    self.documents = persisted.get("documents", [])
                    self.metadatas = persisted.get("metadatas", [])
                except (IOError, OSError, json.JSONDecodeError) as exc:
                    # Index file doesn't exist or is corrupted - will be created on first add()
                    logger.debug(f"[SemanticSearch] FAISS index not found or corrupted, will create new: {exc}")
                    self.faiss_index = None
                except Exception as exc:
                    logger.warning(f"[SemanticSearch] Unexpected error loading FAISS index: {exc}", exc_info=True)
                    self.faiss_index = None
            self.mode = "faiss"
            print("[SemanticSearch] Loaded FAISS-backed semantic index")
            return True
        except ImportError:
            return False
        except Exception as exc:
            print(f"[SemanticSearch] Failed to init FAISS backend: {exc}")
            return False

    def _init_chroma(self) -> bool:
        try:
            import chromadb  # type: ignore
            from sentence_transformers import SentenceTransformer

            if self.model is None:
                self.model = SentenceTransformer("all-MiniLM-L6-v2")
            self.chroma_client = chromadb.PersistentClient(path=str(self.persist_dir))
            self.chroma_collection = self.chroma_client.get_or_create_collection("mortar_semantic")
            try:
                snapshot = self.chroma_collection.get(
                    limit=10000, include=["documents", "metadatas", "ids"]
                )
                self.documents = snapshot.get("documents", []) or []
                self.metadatas = snapshot.get("metadatas", []) or []
            except Exception as exc:
                logger.debug(f"[SemanticSearch] Could not load existing Chroma documents: {exc}")
            self.mode = "chroma"
            print("[SemanticSearch] Loaded Chroma-backed semantic index")
            return True
        except ImportError:
            return False
        except Exception as exc:
            print(f"[SemanticSearch] Failed to init Chroma backend: {exc}")
            return False

    def _init_neural(self) -> bool:
        try:
            from sentence_transformers import SentenceTransformer

            self.model = SentenceTransformer("all-MiniLM-L6-v2")
            self.mode = "neural"
            print("[SemanticSearch] Loaded Neural Engine (all-MiniLM-L6-v2)")
            return True
        except ImportError:
            return False

    def _init_tfidf(self) -> bool:
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer

            self.vectorizer = TfidfVectorizer(stop_words="english")
            self.mode = "tfidf"
            print("[SemanticSearch] Loaded Statistical Engine (TF-IDF)")
            return True
        except ImportError:
            return False

    def _init_keyword(self) -> None:
        self.mode = "keyword"
        print("[SemanticSearch] Loaded Basic Engine (Keyword Matching)")

    def add_documents(self, documents: List[str], metadatas: List[Dict[str, Any]]):
        start_idx = len(self.documents)
        self.documents.extend(documents)
        self.metadatas.extend(metadatas)

        if self.mode == "faiss":
            embeddings = self._encode_documents(documents)
            if embeddings is None:
                return
            self._ensure_faiss_index(embeddings.shape[1])
            if self.faiss_index is None:
                return
            import numpy as np

            ids = np.arange(start_idx, len(self.documents))
            self.faiss_index.add_with_ids(embeddings.astype("float32"), ids)
            self._persist_faiss()

        elif self.mode == "chroma" and self.chroma_collection:
            embeddings = self._encode_documents(documents)
            ids = [f"doc-{i}" for i in range(start_idx, len(self.documents))]
            self.chroma_collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids,
                embeddings=embeddings.tolist() if embeddings is not None else None,
            )

        elif self.mode == "neural":
            self.embeddings = self._encode_documents(self.documents)

        elif self.mode == "tfidf":
            self.embeddings = self.vectorizer.fit_transform(self.documents)

    def search(self, query: str, top_k: int = 5) -> List[SearchResult]:
        if self.mode == "faiss":
            return self._search_faiss(query, top_k)
        if self.mode == "chroma":
            return self._search_chroma(query, top_k)

        if not self.documents:
            return []

        if self.mode == "neural":
            return self._search_neural(query, top_k)
        elif self.mode == "tfidf":
            return self._search_tfidf(query, top_k)
        else:
            return self._search_keyword(query, top_k)

    def _search_faiss(self, query: str, top_k: int) -> List[SearchResult]:
        if self.faiss_index is None or not self.documents:
            return self._search_keyword(query, top_k)
        import numpy as np

        query_vec = self._encode_documents([query])
        if query_vec is None:
            return self._search_keyword(query, top_k)
        scores, indices = self.faiss_index.search(query_vec.astype("float32"), top_k)
        results: List[SearchResult] = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self.documents):
                continue
            results.append(
                SearchResult(
                    score=float(score),
                    content=self.documents[idx],
                    metadata=self.metadatas[idx],
                )
            )
        return results

    def _search_chroma(self, query: str, top_k: int) -> List[SearchResult]:
        if self.chroma_collection is None:
            return self._search_keyword(query, top_k)
        embeddings = self._encode_documents([query])
        query_embeddings = embeddings.tolist() if embeddings is not None else None
        result = self.chroma_collection.query(
            query_embeddings=query_embeddings,
            n_results=top_k,
            include=["documents", "metadatas", "distances"],
        )
        docs = result.get("documents", [[]])[0]
        metas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]
        cleaned: List[SearchResult] = []
        for doc, meta, dist in zip(docs, metas, distances):
            if doc is None:
                continue
            score = 1 - float(dist) if dist is not None else 0.0
            cleaned.append(SearchResult(score=score, content=doc, metadata=meta or {}))
        return cleaned

    def _search_neural(self, query: str, top_k: int) -> List[SearchResult]:
        import numpy as np
        from sklearn.metrics.pairwise import cosine_similarity

        query_vec = self._encode_documents([query])
        if query_vec is None or self.embeddings is None:
            return []
        scores = cosine_similarity(query_vec, self.embeddings)[0]
        top_indices = np.argsort(scores)[::-1][:top_k]

        results = []
        for idx in top_indices:
            results.append(
                SearchResult(
                    score=float(scores[idx]),
                    content=self.documents[idx],
                    metadata=self.metadatas[idx],
                )
            )
        return results

    def _search_tfidf(self, query: str, top_k: int) -> List[SearchResult]:
        import numpy as np
        from sklearn.metrics.pairwise import cosine_similarity

        query_vec = self.vectorizer.transform([query])
        scores = cosine_similarity(query_vec, self.embeddings)[0]
        top_indices = np.argsort(scores)[::-1][:top_k]

        results = []
        for idx in top_indices:
            if scores[idx] > 0:
                results.append(
                    SearchResult(
                        score=float(scores[idx]),
                        content=self.documents[idx],
                        metadata=self.metadatas[idx],
                    )
                )
        return results

    def _search_keyword(self, query: str, top_k: int) -> List[SearchResult]:
        query_terms = set(re.findall(r"\w+", query.lower()))
        scores = []

        for i, doc in enumerate(self.documents):
            doc_terms = set(re.findall(r"\w+", doc.lower()))
            if not doc_terms:
                score = 0.0
            else:
                overlap = len(query_terms.intersection(doc_terms))
                score = overlap / len(query_terms) if query_terms else 0.0

            scores.append((score, i))

        scores.sort(key=lambda x: x[0], reverse=True)

        results = []
        for score, idx in scores[:top_k]:
            if score > 0:
                results.append(
                    SearchResult(
                        score=score,
                        content=self.documents[idx],
                        metadata=self.metadatas[idx],
                    )
                )
        return results

    def _encode_documents(self, docs: List[str]):
        if self.model is None:
            return None
        import numpy as np

        embeddings = self.model.encode(docs)
        if embeddings is None:
            return None
        embeddings = np.array(embeddings, dtype="float32")
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms[norms == 0] = 1
        return embeddings / norms

    def _ensure_faiss_index(self, dim: int) -> None:
        if self.faiss_index is None and self.faiss is not None:
            self.faiss_index = self.faiss.IndexIDMap(self.faiss.IndexFlatIP(dim))
        elif self.faiss_index is not None:
            if getattr(self.faiss_index, "d", dim) != dim:
                self.faiss_index = self.faiss.IndexIDMap(self.faiss.IndexFlatIP(dim))

    def _persist_faiss(self) -> None:
        if not self.faiss_index:
            return
        try:
            self.faiss.write_index(self.faiss_index, str(self.faiss_index_path))
            payload = {"documents": self.documents, "metadatas": self.metadatas}
            with open(self.faiss_meta_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
        except Exception as exc:
            print(f"[SemanticSearch] Failed to persist FAISS index: {exc}")
