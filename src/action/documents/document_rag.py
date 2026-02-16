"""
Document RAG (Retrieval-Augmented Generation) system.

Integrates document processing with vector database for intelligent Q&A.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json

from .document_processor import DocumentProcessor, Document, DocumentChunk


@dataclass
class RAGResult:
    """Result from RAG query."""
    answer: str
    relevant_chunks: List[DocumentChunk]
    confidence: float
    sources: List[str]
    reasoning: str


class DocumentRAG:
    """
    RAG system for document question-answering.
    
    Combines document retrieval with LLM generation for accurate answers.
    """
    
    def __init__(self, llm_provider=None, vector_store=None):
        """
        Initialize Document RAG.
        
        Args:
            llm_provider: Language model for answer generation
            vector_store: Vector database for semantic search
        """
        self.llm_provider = llm_provider
        self.vector_store = vector_store
        self.processor = DocumentProcessor()
        self.documents: Dict[str, Document] = {}
        
    def ingest_document(self, filepath: str, collection_name: str = "documents") -> Document:
        """
        Ingest document into RAG system.
        
        Args:
            filepath: Path to document
            collection_name: Vector store collection name
            
        Returns:
            Processed Document
        """
        document = self.processor.process_file(filepath)
        
        self.documents[document.doc_id] = document
        
        if self.vector_store:
            self._index_document_chunks(document, collection_name)
        
        return document
    
    def _index_document_chunks(self, document: Document, collection_name: str):
        """Index document chunks in vector database."""
        if not self.vector_store:
            return
        
        texts = []
        metadatas = []
        ids = []
        
        for chunk in document.chunks:
            texts.append(chunk.content)
            
            metadata = {
                'doc_id': document.doc_id,
                'filename': document.filename,
                'chunk_id': chunk.chunk_id,
                'chunk_index': chunk.chunk_index,
                'file_type': document.file_type
            }
            
            if chunk.page_number:
                metadata['page_number'] = chunk.page_number
            
            metadatas.append(metadata)
            ids.append(f"{document.doc_id}_{chunk.chunk_id}")
        
        self.vector_store.add_memories(
            collection_name=collection_name,
            texts=texts,
            metadatas=metadatas,
            ids=ids
        )
    
    def query(self, question: str, top_k: int = 5, 
             collection_name: str = "documents") -> RAGResult:
        """
        Query documents with RAG.
        
        Args:
            question: User question
            top_k: Number of relevant chunks to retrieve
            collection_name: Collection to search
            
        Returns:
            RAGResult with answer and sources
        """
        relevant_chunks = self._retrieve_relevant_chunks(question, top_k, collection_name)
        
        if not relevant_chunks:
            return RAGResult(
                answer="No relevant information found in the documents.",
                relevant_chunks=[],
                confidence=0.0,
                sources=[],
                reasoning="No chunks retrieved from vector search."
            )
        
        answer = self._generate_answer(question, relevant_chunks)
        
        sources = list(set([
            chunk.metadata.get('filename', 'Unknown') 
            for chunk in relevant_chunks
        ]))
        
        confidence = self._assess_confidence(question, relevant_chunks, answer)
        
        reasoning = self._generate_reasoning(question, relevant_chunks, answer)
        
        return RAGResult(
            answer=answer,
            relevant_chunks=relevant_chunks,
            confidence=confidence,
            sources=sources,
            reasoning=reasoning
        )
    
    def _retrieve_relevant_chunks(self, question: str, top_k: int, 
                                  collection_name: str) -> List[DocumentChunk]:
        """Retrieve relevant chunks using vector search."""
        if not self.vector_store:
            return self._fallback_keyword_search(question, top_k)
        
        try:
            results = self.vector_store.search_memories(
                collection_name=collection_name,
                query_text=question,
                n_results=top_k
            )
            
            chunks = []
            
            if results and 'documents' in results:
                for i, doc_text in enumerate(results['documents']):
                    metadata = results['metadatas'][i] if i < len(results['metadatas']) else {}
                    
                    chunk = DocumentChunk(
                        chunk_id=metadata.get('chunk_id', f'chunk_{i}'),
                        content=doc_text,
                        chunk_index=metadata.get('chunk_index', i),
                        metadata=metadata
                    )
                    chunks.append(chunk)
            
            return chunks
            
        except Exception as e:
            print(f"Vector search error: {e}")
            return self._fallback_keyword_search(question, top_k)
    
    def _fallback_keyword_search(self, question: str, top_k: int) -> List[DocumentChunk]:
        """Fallback keyword-based search."""
        all_chunks = []
        
        for doc in self.documents.values():
            matching = self.processor.search_chunks(doc, question)
            for chunk in matching:
                chunk.metadata = chunk.metadata or {}
                chunk.metadata['filename'] = doc.filename
                chunk.metadata['doc_id'] = doc.doc_id
            all_chunks.extend(matching)
        
        return all_chunks[:top_k]
    
    def _generate_answer(self, question: str, chunks: List[DocumentChunk]) -> str:
        """Generate answer using LLM and retrieved context."""
        context = "\n\n---\n\n".join([
            f"[Source: {chunk.metadata.get('filename', 'Unknown')}]\n{chunk.content}"
            for chunk in chunks
        ])
        
        if not self.llm_provider:
            return self._generate_answer_heuristic(question, chunks)
        
        prompt = f"""Based on the following document excerpts, answer the question accurately and concisely.

Question: {question}

Document Context:
{context}

Instructions:
1. Answer based ONLY on the provided context
2. If the context doesn't contain enough information, say so
3. Cite sources when possible
4. Be precise and factual

Answer:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=500,
                temperature=0.3,
                task_type='analysis'
            )
            
            return response.get('content', '').strip()
            
        except Exception as e:
            print(f"LLM generation error: {e}")
            return self._generate_answer_heuristic(question, chunks)
    
    def _generate_answer_heuristic(self, question: str, chunks: List[DocumentChunk]) -> str:
        """Fallback heuristic answer generation."""
        if not chunks:
            return "No relevant information found."
        
        answer_parts = [
            "Based on the documents:",
            "",
            chunks[0].content[:500] + "..." if len(chunks[0].content) > 500 else chunks[0].content,
            "",
            f"(Found in {len(chunks)} relevant sections)"
        ]
        
        return '\n'.join(answer_parts)
    
    def _assess_confidence(self, question: str, chunks: List[DocumentChunk], 
                          answer: str) -> float:
        """Assess confidence in the answer."""
        if not chunks:
            return 0.0
        
        confidence = 0.5
        
        if len(chunks) >= 3:
            confidence += 0.2
        
        question_lower = question.lower()
        answer_lower = answer.lower()
        
        question_words = set(question_lower.split())
        answer_words = set(answer_lower.split())
        
        overlap = len(question_words & answer_words) / max(len(question_words), 1)
        confidence += overlap * 0.2
        
        if "based on" in answer_lower or "according to" in answer_lower:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _generate_reasoning(self, question: str, chunks: List[DocumentChunk], 
                           answer: str) -> str:
        """Generate reasoning explanation."""
        reasoning_parts = [
            f"Retrieved {len(chunks)} relevant document sections.",
            f"Sources: {', '.join(set([chunk.metadata.get('filename', 'Unknown') for chunk in chunks]))}",
            f"Answer confidence: {self._assess_confidence(question, chunks, answer):.2f}"
        ]
        
        return ' '.join(reasoning_parts)
    
    def summarize_document(self, doc_id: str, max_length: int = 500) -> str:
        """
        Generate document summary.
        
        Args:
            doc_id: Document ID
            max_length: Maximum summary length
            
        Returns:
            Document summary
        """
        if doc_id not in self.documents:
            raise ValueError(f"Document not found: {doc_id}")
        
        document = self.documents[doc_id]
        
        if not self.llm_provider:
            return self._summarize_heuristic(document, max_length)
        
        content_preview = document.content[:4000]
        
        prompt = f"""Summarize the following document concisely.

Document: {document.filename}
Type: {document.file_type}

Content:
{content_preview}

Generate a {max_length}-character summary highlighting:
1. Main topic/purpose
2. Key points
3. Important findings or conclusions

Summary:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=max_length // 2,
                temperature=0.5,
                task_type='analysis'
            )
            
            return response.get('content', '').strip()
            
        except Exception as e:
            print(f"LLM summarization error: {e}")
            return self._summarize_heuristic(document, max_length)
    
    def _summarize_heuristic(self, document: Document, max_length: int) -> str:
        """Fallback heuristic summarization."""
        lines = document.content.split('\n')
        non_empty_lines = [line.strip() for line in lines if line.strip()]
        
        summary_lines = non_empty_lines[:10]
        
        summary = ' '.join(summary_lines)
        
        if len(summary) > max_length:
            summary = summary[:max_length - 3] + "..."
        
        return summary
    
    def get_document_stats(self, doc_id: str) -> Dict[str, Any]:
        """Get statistics for a document."""
        if doc_id not in self.documents:
            raise ValueError(f"Document not found: {doc_id}")
        
        document = self.documents[doc_id]
        
        return {
            'filename': document.filename,
            'file_type': document.file_type,
            'total_length': len(document.content),
            'num_chunks': len(document.chunks),
            'metadata': document.metadata,
            'processed_at': document.processed_at
        }
    
    def list_documents(self) -> List[Dict[str, Any]]:
        """List all ingested documents."""
        return [
            {
                'doc_id': doc_id,
                'filename': doc.filename,
                'file_type': doc.file_type,
                'chunks': len(doc.chunks),
                'processed_at': doc.processed_at
            }
            for doc_id, doc in self.documents.items()
        ]
