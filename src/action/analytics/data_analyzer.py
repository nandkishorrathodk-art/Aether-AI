"""Advanced data analytics engine for CSV/Excel analysis."""

from typing import Dict, List, Any, Optional, Union
import pandas as pd
import numpy as np
from dataclasses import dataclass
import json


@dataclass
class DataInsight:
    """A data insight discovered during analysis."""
    type: str
    title: str
    description: str
    importance: str
    confidence: float
    supporting_data: Dict[str, Any]


class DataAnalyzer:
    """
    Advanced data analytics engine with ML capabilities.
    
    Handles CSV/Excel files, performs statistical analysis, generates
    visualizations, and extracts actionable insights.
    """
    
    def __init__(self, llm_provider=None):
        """
        Initialize data analyzer.
        
        Args:
            llm_provider: Language model for intelligent analysis
        """
        self.llm_provider = llm_provider
        self.analysis_history: List[Dict[str, Any]] = []
        
    def analyze_file(self, filepath: str, analysis_type: str = 'comprehensive') -> Dict[str, Any]:
        """
        Analyze data file (CSV or Excel).
        
        Args:
            filepath: Path to data file
            analysis_type: Type of analysis ('comprehensive', 'statistical', 'ml', 'quick')
            
        Returns:
            Complete analysis results with insights
        """
        try:
            df = self._load_data(filepath)
        except Exception as e:
            return {'error': f"Failed to load data: {str(e)}"}
        
        basic_stats = self._compute_basic_statistics(df)
        
        insights = self._extract_insights(df, basic_stats)
        
        correlations = self._analyze_correlations(df)
        
        trends = self._detect_trends(df)
        
        anomalies = self._detect_anomalies(df)
        
        if analysis_type in ['comprehensive', 'ml']:
            ml_insights = self._perform_ml_analysis(df)
        else:
            ml_insights = {}
        
        recommendations = self._generate_recommendations(df, insights, trends)
        
        result = {
            'filepath': filepath,
            'rows': len(df),
            'columns': len(df.columns),
            'column_names': list(df.columns),
            'data_types': {col: str(dtype) for col, dtype in df.dtypes.items()},
            'basic_statistics': basic_stats,
            'insights': [self._insight_to_dict(i) for i in insights],
            'correlations': correlations,
            'trends': trends,
            'anomalies': anomalies,
            'ml_analysis': ml_insights,
            'recommendations': recommendations,
            'summary': self._generate_summary(df, insights, trends)
        }
        
        self.analysis_history.append(result)
        
        return result
    
    def _load_data(self, filepath: str) -> pd.DataFrame:
        """Load data from CSV or Excel file."""
        if filepath.endswith('.csv'):
            return pd.read_csv(filepath)
        elif filepath.endswith(('.xlsx', '.xls')):
            return pd.read_excel(filepath)
        else:
            raise ValueError(f"Unsupported file format: {filepath}")
    
    def _compute_basic_statistics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Compute basic statistical measures."""
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        stats = {}
        for col in numeric_cols:
            stats[col] = {
                'mean': float(df[col].mean()),
                'median': float(df[col].median()),
                'std': float(df[col].std()),
                'min': float(df[col].min()),
                'max': float(df[col].max()),
                'q1': float(df[col].quantile(0.25)),
                'q3': float(df[col].quantile(0.75)),
                'missing': int(df[col].isna().sum()),
                'missing_pct': float(df[col].isna().sum() / len(df) * 100)
            }
        
        categorical_cols = df.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            value_counts = df[col].value_counts()
            stats[col] = {
                'unique_values': int(df[col].nunique()),
                'most_common': str(value_counts.index[0]) if len(value_counts) > 0 else None,
                'most_common_count': int(value_counts.iloc[0]) if len(value_counts) > 0 else 0,
                'missing': int(df[col].isna().sum()),
                'missing_pct': float(df[col].isna().sum() / len(df) * 100)
            }
        
        return stats
    
    def _extract_insights(self, df: pd.DataFrame, stats: Dict[str, Any]) -> List[DataInsight]:
        """Extract actionable insights from data."""
        insights = []
        
        for col, col_stats in stats.items():
            if 'missing_pct' in col_stats and col_stats['missing_pct'] > 20:
                insights.append(DataInsight(
                    type='data_quality',
                    title=f'High missing data in {col}',
                    description=f'{col} has {col_stats["missing_pct"]:.1f}% missing values',
                    importance='High' if col_stats['missing_pct'] > 50 else 'Medium',
                    confidence=1.0,
                    supporting_data={'column': col, 'missing_pct': col_stats['missing_pct']}
                ))
            
            if 'std' in col_stats and col_stats['std'] > 0:
                cv = col_stats['std'] / abs(col_stats['mean']) if col_stats['mean'] != 0 else 0
                if cv > 1.0:
                    insights.append(DataInsight(
                        type='variability',
                        title=f'High variability in {col}',
                        description=f'{col} shows high coefficient of variation ({cv:.2f})',
                        importance='Medium',
                        confidence=0.9,
                        supporting_data={'column': col, 'cv': cv, 'std': col_stats['std']}
                    ))
        
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        if len(numeric_cols) >= 2:
            for i, col1 in enumerate(numeric_cols[:5]):
                for col2 in numeric_cols[i+1:6]:
                    corr = df[[col1, col2]].corr().iloc[0, 1]
                    if abs(corr) > 0.7:
                        insights.append(DataInsight(
                            type='correlation',
                            title=f'Strong correlation between {col1} and {col2}',
                            description=f'Correlation coefficient: {corr:.2f}',
                            importance='High' if abs(corr) > 0.85 else 'Medium',
                            confidence=0.85,
                            supporting_data={'col1': col1, 'col2': col2, 'correlation': corr}
                        ))
        
        return insights
    
    def _analyze_correlations(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze correlations between numerical columns."""
        numeric_df = df.select_dtypes(include=[np.number])
        
        if len(numeric_df.columns) < 2:
            return {'message': 'Insufficient numeric columns for correlation analysis'}
        
        corr_matrix = numeric_df.corr()
        
        strong_correlations = []
        for i in range(len(corr_matrix.columns)):
            for j in range(i+1, len(corr_matrix.columns)):
                corr_value = corr_matrix.iloc[i, j]
                if abs(corr_value) > 0.5:
                    strong_correlations.append({
                        'variable1': corr_matrix.columns[i],
                        'variable2': corr_matrix.columns[j],
                        'correlation': float(corr_value),
                        'strength': 'Strong' if abs(corr_value) > 0.7 else 'Moderate'
                    })
        
        return {
            'correlation_matrix': corr_matrix.to_dict(),
            'strong_correlations': sorted(strong_correlations, 
                                        key=lambda x: abs(x['correlation']), 
                                        reverse=True)[:10]
        }
    
    def _detect_trends(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect trends in time-series or sequential data."""
        trends = []
        
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numeric_cols[:5]:
            values = df[col].dropna()
            if len(values) < 3:
                continue
            
            x = np.arange(len(values))
            y = values.values
            
            try:
                slope, intercept = np.polyfit(x, y, 1)
                
                if abs(slope) > 0.01 * abs(np.mean(y)):
                    direction = 'increasing' if slope > 0 else 'decreasing'
                    strength = 'strong' if abs(slope) > 0.1 * abs(np.mean(y)) else 'moderate'
                    
                    trends.append({
                        'column': col,
                        'direction': direction,
                        'strength': strength,
                        'slope': float(slope),
                        'description': f'{col} is {strength}ly {direction}'
                    })
            except Exception:
                continue
        
        return trends
    
    def _detect_anomalies(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect anomalies using statistical methods."""
        anomalies = []
        
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numeric_cols[:5]:
            values = df[col].dropna()
            if len(values) < 10:
                continue
            
            q1 = values.quantile(0.25)
            q3 = values.quantile(0.75)
            iqr = q3 - q1
            
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            
            outliers = values[(values < lower_bound) | (values > upper_bound)]
            
            if len(outliers) > 0:
                anomalies.append({
                    'column': col,
                    'num_anomalies': len(outliers),
                    'percentage': float(len(outliers) / len(values) * 100),
                    'min_anomaly': float(outliers.min()),
                    'max_anomaly': float(outliers.max()),
                    'description': f'Found {len(outliers)} outliers in {col}'
                })
        
        return anomalies
    
    def _perform_ml_analysis(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Perform machine learning analysis."""
        try:
            from sklearn.decomposition import PCA
            from sklearn.cluster import KMeans
            
            numeric_df = df.select_dtypes(include=[np.number]).dropna()
            
            if len(numeric_df) < 10 or len(numeric_df.columns) < 2:
                return {'message': 'Insufficient data for ML analysis'}
            
            pca = PCA(n_components=min(2, len(numeric_df.columns)))
            principal_components = pca.fit_transform(numeric_df)
            
            optimal_k = min(3, len(numeric_df) // 3)
            if optimal_k >= 2:
                kmeans = KMeans(n_clusters=optimal_k, random_state=42, n_init=10)
                clusters = kmeans.fit_predict(numeric_df)
                
                cluster_analysis = {
                    'num_clusters': optimal_k,
                    'cluster_sizes': {int(i): int(np.sum(clusters == i)) for i in range(optimal_k)},
                    'inertia': float(kmeans.inertia_)
                }
            else:
                cluster_analysis = {'message': 'Insufficient data for clustering'}
            
            return {
                'pca': {
                    'explained_variance_ratio': [float(x) for x in pca.explained_variance_ratio_],
                    'cumulative_variance': float(np.sum(pca.explained_variance_ratio_))
                },
                'clustering': cluster_analysis
            }
        except ImportError:
            return {'message': 'scikit-learn not available for ML analysis'}
        except Exception as e:
            return {'error': f'ML analysis failed: {str(e)}'}
    
    def _generate_recommendations(self, df: pd.DataFrame, insights: List[DataInsight],
                                 trends: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        quality_issues = [i for i in insights if i.type == 'data_quality']
        if quality_issues:
            recommendations.append(
                f"Address {len(quality_issues)} data quality issues before proceeding with analysis"
            )
        
        increasing_trends = [t for t in trends if t['direction'] == 'increasing']
        if increasing_trends:
            recommendations.append(
                f"Monitor {len(increasing_trends)} increasing trend(s) for growth opportunities"
            )
        
        correlations = [i for i in insights if i.type == 'correlation']
        if correlations:
            recommendations.append(
                f"Investigate {len(correlations)} strong correlation(s) for potential causal relationships"
            )
        
        if not recommendations:
            recommendations.append("Data quality is good - proceed with advanced analysis")
        
        return recommendations
    
    def _generate_summary(self, df: pd.DataFrame, insights: List[DataInsight],
                         trends: List[Dict[str, Any]]) -> str:
        """Generate executive summary of analysis."""
        summary = f"""Data Analysis Summary

Dataset: {len(df)} rows, {len(df.columns)} columns

Key Findings:
- {len(insights)} insights discovered
- {len(trends)} trends identified
- {len([i for i in insights if i.importance == 'High'])} high-priority items

Top Insight: {insights[0].title if insights else 'No significant insights'}

Analysis Type: {"Time-series" if trends else "Cross-sectional"}
"""
        return summary
    
    def _insight_to_dict(self, insight: DataInsight) -> Dict[str, Any]:
        """Convert insight to dictionary."""
        return {
            'type': insight.type,
            'title': insight.title,
            'description': insight.description,
            'importance': insight.importance,
            'confidence': insight.confidence,
            'supporting_data': insight.supporting_data
        }
    
    def query_data(self, df_or_filepath: Union[pd.DataFrame, str], 
                  query: str) -> Dict[str, Any]:
        """
        Query data using natural language.
        
        Args:
            df_or_filepath: DataFrame or file path
            query: Natural language query
            
        Returns:
            Query results
        """
        if isinstance(df_or_filepath, str):
            df = self._load_data(df_or_filepath)
        else:
            df = df_or_filepath
        
        query_lower = query.lower()
        
        if 'average' in query_lower or 'mean' in query_lower:
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            return {
                'query': query,
                'result': {col: float(df[col].mean()) for col in numeric_cols},
                'type': 'aggregation'
            }
        elif 'count' in query_lower or 'how many' in query_lower:
            return {
                'query': query,
                'result': {'total_rows': len(df)},
                'type': 'count'
            }
        elif 'max' in query_lower or 'maximum' in query_lower or 'highest' in query_lower:
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            return {
                'query': query,
                'result': {col: float(df[col].max()) for col in numeric_cols},
                'type': 'max'
            }
        elif 'min' in query_lower or 'minimum' in query_lower or 'lowest' in query_lower:
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            return {
                'query': query,
                'result': {col: float(df[col].min()) for col in numeric_cols},
                'type': 'min'
            }
        else:
            return {
                'query': query,
                'result': 'Query not understood. Try asking for average, count, max, or min.',
                'type': 'unsupported'
            }
    
    def create_visualization_spec(self, df: pd.DataFrame, viz_type: str = 'auto') -> Dict[str, Any]:
        """
        Create visualization specification for frontend rendering.
        
        Args:
            df: DataFrame to visualize
            viz_type: Type of visualization ('auto', 'bar', 'line', 'scatter', 'pie')
            
        Returns:
            Visualization specification
        """
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        categorical_cols = df.select_dtypes(include=['object']).columns
        
        if viz_type == 'auto':
            if len(numeric_cols) >= 2:
                viz_type = 'scatter'
            elif len(categorical_cols) > 0 and len(numeric_cols) > 0:
                viz_type = 'bar'
            else:
                viz_type = 'line'
        
        if viz_type == 'bar' and len(categorical_cols) > 0 and len(numeric_cols) > 0:
            cat_col = categorical_cols[0]
            num_col = numeric_cols[0]
            data = df.groupby(cat_col)[num_col].mean().to_dict()
            
            return {
                'type': 'bar',
                'x': list(data.keys()),
                'y': list(data.values()),
                'title': f'{num_col} by {cat_col}',
                'xlabel': cat_col,
                'ylabel': num_col
            }
        elif viz_type == 'line' and len(numeric_cols) > 0:
            col = numeric_cols[0]
            return {
                'type': 'line',
                'x': list(range(len(df))),
                'y': df[col].tolist(),
                'title': f'{col} over time',
                'xlabel': 'Index',
                'ylabel': col
            }
        elif viz_type == 'scatter' and len(numeric_cols) >= 2:
            col1, col2 = numeric_cols[0], numeric_cols[1]
            return {
                'type': 'scatter',
                'x': df[col1].tolist(),
                'y': df[col2].tolist(),
                'title': f'{col2} vs {col1}',
                'xlabel': col1,
                'ylabel': col2
            }
        else:
            return {'error': 'Unable to create visualization specification'}
