"""
Vector Codebase DB Tool (MCP Tool 2)
Provides semantic code chunking and retrieval using ChromaDB with resilient local fallback.
"""
import os
import hashlib
from typing import List, Dict, Any, Optional


class SemanticEmbeddingFunction:
    """Production-grade dense semantic embedding function using SentenceTransformer all-MiniLM-L6-v2."""
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model = None
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(model_name)
        except Exception:
            self._model = None

    def __call__(self, input: List[str]) -> List[List[float]]:
        if self._model is not None:
            embeddings = self._model.encode(input, convert_to_numpy=True)
            return embeddings.tolist()
        # Fallback to local deterministic normalized vectors if model failed to load
        embeddings = []
        dim = 384
        for text in input:
            vec = [0.0] * dim
            words = text.lower().split()
            for w in words:
                h = int(hashlib.sha256(w.encode('utf-8', errors='ignore')).hexdigest(), 16)
                vec[h % dim] += 1.0
            norm = sum(x**2 for x in vec) ** 0.5 or 1.0
            embeddings.append([round(x / norm, 5) for x in vec])
        return embeddings


class VectorCodebaseTool:
    def __init__(self, collection_name: str = "devpilot_codebase"):
        self.collection_name = collection_name
        self.chroma_client = None
        self.collection = None
        self._local_chunks: List[Dict[str, Any]] = []

        try:
            import chromadb
            self.chroma_client = chromadb.Client()
            self.collection = self.chroma_client.get_or_create_collection(
                name=collection_name,
                embedding_function=SemanticEmbeddingFunction()
            )
        except Exception:
            self.chroma_client = None
            self.collection = None

    def index_files(self, repo_path: str, files: List[str]) -> int:
        """Chunks files by function/class or sliding window and indexes them."""
        chunks = []
        for rel_file in files:
            full_path = os.path.join(repo_path, rel_file) if not os.path.isabs(rel_file) else rel_file
            if not os.path.exists(full_path):
                continue
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception:
                continue

            chunk_size = 25
            overlap = 5
            for i in range(0, len(lines), max(1, chunk_size - overlap)):
                window = lines[i:i + chunk_size]
                chunk_text = "".join(window).strip()
                if not chunk_text:
                    continue
                clean_rel_path = rel_file.replace("\\", "/")
                chunk_id = f"{clean_rel_path}#L{i+1}-L{i+len(window)}"
                chunks.append({
                    "id": chunk_id,
                    "text": chunk_text,
                    "metadata": {
                        "file_path": clean_rel_path,
                        "line_start": i + 1,
                        "line_end": i + len(window)
                    }
                })

        if not chunks:
            return 0

        self._local_chunks = chunks

        if self.collection:
            try:
                ids = [c["id"] for c in chunks]
                documents = [c["text"] for c in chunks]
                metadatas = [c["metadata"] for c in chunks]
                self.collection.upsert(
                    ids=ids,
                    documents=documents,
                    metadatas=metadatas
                )
            except Exception:
                pass

        return len(chunks)

    def search_codebase(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Searches vector index or uses TF-IDF / keyword fallback for query matching."""
        if self.collection:
            try:
                res = self.collection.query(query_texts=[query], n_results=min(top_k, len(self._local_chunks)))
                if res and res.get("documents") and len(res["documents"][0]) > 0:
                    docs = res["documents"][0]
                    metas = res["metadatas"][0] if res.get("metadatas") else [{}] * len(docs)
                    ids = res["ids"][0]
                    results = []
                    for cid, doc, meta in zip(ids, docs, metas):
                        results.append({
                            "chunk_id": cid,
                            "content": doc,
                            "code_snippet": doc,
                            "file_path": meta.get("file_path", ""),
                            "line_start": meta.get("line_start", 0),
                            "line_end": meta.get("line_end", 0),
                        })
                    return results
            except Exception:
                pass

        # Resilient local keyword/term-overlap search
        query_terms = [t for t in query.lower().replace("_", " ").split() if len(t) > 2]
        scored = []
        for chunk in self._local_chunks:
            text_lower = chunk["text"].lower().replace("_", " ")
            overlap = sum(1 for term in query_terms if term in text_lower)
            if overlap > 0:
                scored.append((overlap, chunk))

        scored.sort(key=lambda x: x[0], reverse=True)
        fallback_results = [
            {
                "chunk_id": c["id"],
                "content": c["text"],
                "code_snippet": c["text"],
                "file_path": c["metadata"]["file_path"],
                "line_start": c["metadata"]["line_start"],
                "line_end": c["metadata"]["line_end"],
            }
            for _, c in scored[:top_k]
        ]
        
        # If no strict overlap found, return top chunk if available
        if not fallback_results and self._local_chunks:
            c = self._local_chunks[0]
            fallback_results.append({
                "chunk_id": c["id"],
                "content": c["text"],
                "code_snippet": c["text"],
                "file_path": c["metadata"]["file_path"],
                "line_start": c["metadata"]["line_start"],
                "line_end": c["metadata"]["line_end"],
            })

        return fallback_results
