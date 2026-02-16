"""
Advanced document analysis with entity extraction and classification.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import re
from collections import Counter

from .document_processor import Document, DocumentProcessor


@dataclass
class Entity:
    """Extracted entity from document."""
    text: str
    type: str
    confidence: float
    context: str


@dataclass
class DocumentInsights:
    """Analysis insights from document."""
    summary: str
    key_topics: List[str]
    entities: List[Entity]
    sentiment: str
    complexity_score: float
    readability_score: float
    key_statistics: Dict[str, Any]
    recommendations: List[str]


class DocumentAnalyzer:
    """
    Advanced document analysis with NLP capabilities.
    
    Provides entity extraction, topic modeling, sentiment analysis,
    and content classification.
    """
    
    def __init__(self, llm_provider=None):
        """
        Initialize document analyzer.
        
        Args:
            llm_provider: LLM for advanced analysis
        """
        self.llm_provider = llm_provider
        self.processor = DocumentProcessor()
        
    def analyze(self, document: Document) -> DocumentInsights:
        """
        Perform comprehensive document analysis.
        
        Args:
            document: Document to analyze
            
        Returns:
            DocumentInsights with complete analysis
        """
        summary = self._generate_summary(document)
        
        key_topics = self._extract_topics(document)
        
        entities = self._extract_entities(document)
        
        sentiment = self._analyze_sentiment(document)
        
        complexity = self._calculate_complexity(document)
        
        readability = self._calculate_readability(document)
        
        statistics = self._compute_statistics(document)
        
        recommendations = self._generate_recommendations(document, complexity, readability)
        
        return DocumentInsights(
            summary=summary,
            key_topics=key_topics,
            entities=entities,
            sentiment=sentiment,
            complexity_score=complexity,
            readability_score=readability,
            key_statistics=statistics,
            recommendations=recommendations
        )
    
    def _generate_summary(self, document: Document) -> str:
        """Generate document summary."""
        if self.llm_provider:
            return self._generate_summary_llm(document)
        else:
            return self._generate_summary_heuristic(document)
    
    def _generate_summary_llm(self, document: Document) -> str:
        """LLM-based summarization."""
        content_preview = document.content[:3000]
        
        prompt = f"""Summarize this document in 3-4 sentences:

Document: {document.filename}
Type: {document.file_type}

Content:
{content_preview}

Summary:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=200,
                temperature=0.5,
                task_type='analysis'
            )
            
            return response.get('content', '').strip()
            
        except Exception as e:
            print(f"LLM summary error: {e}")
            return self._generate_summary_heuristic(document)
    
    def _generate_summary_heuristic(self, document: Document) -> str:
        """Heuristic summarization."""
        sentences = re.split(r'[.!?]\s+', document.content)
        
        non_empty = [s.strip() for s in sentences if len(s.strip()) > 20]
        
        summary_sentences = non_empty[:3]
        
        return '. '.join(summary_sentences) + '.'
    
    def _extract_topics(self, document: Document) -> List[str]:
        """Extract key topics from document."""
        if self.llm_provider:
            return self._extract_topics_llm(document)
        else:
            return self._extract_topics_heuristic(document)
    
    def _extract_topics_llm(self, document: Document) -> List[str]:
        """LLM-based topic extraction."""
        content_preview = document.content[:2000]
        
        prompt = f"""Extract 5-7 key topics from this document. Return as comma-separated list.

Content:
{content_preview}

Key Topics:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=100,
                temperature=0.3,
                task_type='analysis'
            )
            
            topics_text = response.get('content', '').strip()
            topics = [t.strip() for t in topics_text.split(',')]
            
            return topics[:7]
            
        except Exception as e:
            print(f"LLM topic extraction error: {e}")
            return self._extract_topics_heuristic(document)
    
    def _extract_topics_heuristic(self, document: Document) -> List[str]:
        """Heuristic topic extraction using keyword frequency."""
        words = re.findall(r'\b[A-Z][a-z]{3,}\b', document.content)
        
        word_freq = Counter(words)
        
        top_words = [word for word, count in word_freq.most_common(10) if count >= 2]
        
        return top_words[:7]
    
    def _extract_entities(self, document: Document) -> List[Entity]:
        """Extract named entities (people, organizations, locations)."""
        entities = []
        
        person_pattern = r'\b([A-Z][a-z]+ [A-Z][a-z]+)\b'
        people = re.findall(person_pattern, document.content)
        for person in set(people[:10]):
            entities.append(Entity(
                text=person,
                type='PERSON',
                confidence=0.7,
                context=self._get_entity_context(document.content, person)
            ))
        
        org_patterns = [
            r'\b([A-Z][a-z]+ (?:Inc|Corp|LLC|Ltd|Company|Corporation))\b',
            r'\b([A-Z][A-Z]+)\b'
        ]
        
        orgs = []
        for pattern in org_patterns:
            orgs.extend(re.findall(pattern, document.content))
        
        for org in set(orgs[:10]):
            if len(org) > 2:
                entities.append(Entity(
                    text=org,
                    type='ORGANIZATION',
                    confidence=0.6,
                    context=self._get_entity_context(document.content, org)
                ))
        
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, document.content)
        for email in set(emails[:5]):
            entities.append(Entity(
                text=email,
                type='EMAIL',
                confidence=0.95,
                context=self._get_entity_context(document.content, email)
            ))
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, document.content)
        for url in set(urls[:5]):
            entities.append(Entity(
                text=url,
                type='URL',
                confidence=0.95,
                context=''
            ))
        
        date_pattern = r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{1,2},? \d{4}\b'
        dates = re.findall(date_pattern, document.content)
        for date in set(dates[:5]):
            entities.append(Entity(
                text=date,
                type='DATE',
                confidence=0.85,
                context=self._get_entity_context(document.content, date)
            ))
        
        return entities
    
    def _get_entity_context(self, content: str, entity: str) -> str:
        """Get context around entity mention."""
        try:
            idx = content.find(entity)
            if idx == -1:
                return ""
            
            start = max(0, idx - 50)
            end = min(len(content), idx + len(entity) + 50)
            
            context = content[start:end].strip()
            
            return f"...{context}..."
        except:
            return ""
    
    def _analyze_sentiment(self, document: Document) -> str:
        """Analyze document sentiment."""
        if self.llm_provider:
            return self._analyze_sentiment_llm(document)
        else:
            return self._analyze_sentiment_heuristic(document)
    
    def _analyze_sentiment_llm(self, document: Document) -> str:
        """LLM-based sentiment analysis."""
        content_preview = document.content[:1500]
        
        prompt = f"""Analyze the sentiment of this document. Choose ONE: Positive, Negative, Neutral, or Mixed.

Content:
{content_preview}

Sentiment (one word):"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=10,
                temperature=0.2,
                task_type='analysis'
            )
            
            sentiment = response.get('content', 'Neutral').strip()
            
            if sentiment.lower() in ['positive', 'negative', 'neutral', 'mixed']:
                return sentiment.capitalize()
            
            return 'Neutral'
            
        except Exception as e:
            print(f"LLM sentiment error: {e}")
            return self._analyze_sentiment_heuristic(document)
    
    def _analyze_sentiment_heuristic(self, document: Document) -> str:
        """Heuristic sentiment analysis."""
        positive_words = ['good', 'great', 'excellent', 'positive', 'success', 'improve', 
                         'benefit', 'advantage', 'opportunity', 'growth']
        negative_words = ['bad', 'poor', 'fail', 'problem', 'issue', 'risk', 'threat',
                         'challenge', 'decline', 'loss']
        
        content_lower = document.content.lower()
        
        positive_count = sum(content_lower.count(word) for word in positive_words)
        negative_count = sum(content_lower.count(word) for word in negative_words)
        
        if positive_count > negative_count * 1.5:
            return 'Positive'
        elif negative_count > positive_count * 1.5:
            return 'Negative'
        elif abs(positive_count - negative_count) <= 2:
            return 'Neutral'
        else:
            return 'Mixed'
    
    def _calculate_complexity(self, document: Document) -> float:
        """Calculate document complexity score (0-10)."""
        words = document.content.split()
        
        if not words:
            return 0.0
        
        avg_word_length = sum(len(word) for word in words) / len(words)
        
        sentences = re.split(r'[.!?]\s+', document.content)
        avg_sentence_length = len(words) / max(len(sentences), 1)
        
        long_words = sum(1 for word in words if len(word) > 6)
        long_word_ratio = long_words / len(words)
        
        complexity = (
            (avg_word_length / 10) * 3 +
            (avg_sentence_length / 30) * 4 +
            (long_word_ratio * 3)
        )
        
        return min(complexity, 10.0)
    
    def _calculate_readability(self, document: Document) -> float:
        """Calculate readability score (0-100, higher = more readable)."""
        words = document.content.split()
        
        if not words:
            return 0.0
        
        sentences = re.split(r'[.!?]\s+', document.content)
        num_sentences = max(len(sentences), 1)
        num_words = len(words)
        
        syllables = sum(self._count_syllables(word) for word in words)
        
        flesch_reading_ease = (
            206.835 - 
            1.015 * (num_words / num_sentences) - 
            84.6 * (syllables / num_words)
        )
        
        readability = max(0, min(100, flesch_reading_ease))
        
        return round(readability, 2)
    
    def _count_syllables(self, word: str) -> int:
        """Estimate syllable count for a word."""
        word = word.lower()
        vowels = 'aeiouy'
        syllable_count = 0
        previous_was_vowel = False
        
        for char in word:
            is_vowel = char in vowels
            if is_vowel and not previous_was_vowel:
                syllable_count += 1
            previous_was_vowel = is_vowel
        
        if word.endswith('e'):
            syllable_count -= 1
        
        if word.endswith('le') and len(word) > 2 and word[-3] not in vowels:
            syllable_count += 1
        
        if syllable_count == 0:
            syllable_count = 1
        
        return syllable_count
    
    def _compute_statistics(self, document: Document) -> Dict[str, Any]:
        """Compute document statistics."""
        words = document.content.split()
        sentences = re.split(r'[.!?]\s+', document.content)
        
        return {
            'total_words': len(words),
            'total_sentences': len(sentences),
            'total_characters': len(document.content),
            'avg_word_length': round(sum(len(w) for w in words) / max(len(words), 1), 2),
            'avg_sentence_length': round(len(words) / max(len(sentences), 1), 2),
            'unique_words': len(set(word.lower() for word in words)),
            'vocabulary_richness': round(len(set(word.lower() for word in words)) / max(len(words), 1), 3)
        }
    
    def _generate_recommendations(self, document: Document, 
                                 complexity: float, readability: float) -> List[str]:
        """Generate recommendations for document improvement."""
        recommendations = []
        
        if complexity > 7:
            recommendations.append("Consider simplifying language - document complexity is high")
        
        if readability < 50:
            recommendations.append("Improve readability - use shorter sentences and simpler words")
        
        if len(document.content.split()) < 100:
            recommendations.append("Document is short - consider adding more detail")
        
        if len(document.content.split()) > 5000:
            recommendations.append("Document is long - consider breaking into sections")
        
        sentences = re.split(r'[.!?]\s+', document.content)
        long_sentences = [s for s in sentences if len(s.split()) > 30]
        if len(long_sentences) > len(sentences) * 0.3:
            recommendations.append("Many long sentences detected - break them up for clarity")
        
        if not recommendations:
            recommendations.append("Document is well-structured and readable")
        
        return recommendations
    
    def compare_documents(self, doc1: Document, doc2: Document) -> Dict[str, Any]:
        """Compare two documents."""
        insights1 = self.analyze(doc1)
        insights2 = self.analyze(doc2)
        
        words1 = set(doc1.content.lower().split())
        words2 = set(doc2.content.lower().split())
        
        overlap = len(words1 & words2)
        similarity = overlap / max(len(words1), len(words2), 1)
        
        return {
            'doc1': doc1.filename,
            'doc2': doc2.filename,
            'similarity': round(similarity, 3),
            'complexity_diff': round(insights1.complexity_score - insights2.complexity_score, 2),
            'readability_diff': round(insights1.readability_score - insights2.readability_score, 2),
            'length_diff': len(doc1.content) - len(doc2.content),
            'common_topics': list(set(insights1.key_topics) & set(insights2.key_topics))
        }
