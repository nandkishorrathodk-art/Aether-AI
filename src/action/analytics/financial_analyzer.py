"""Financial analysis and portfolio management."""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import json


@dataclass
class Stock:
    """Stock information."""
    symbol: str
    name: str
    price: float
    change: float
    change_percent: float
    volume: int
    market_cap: float


@dataclass
class PortfolioPosition:
    """Portfolio position."""
    symbol: str
    shares: float
    cost_basis: float
    current_price: float
    current_value: float
    gain_loss: float
    gain_loss_percent: float


class FinancialAnalyzer:
    """
    Financial analysis and portfolio management system.
    
    Tracks stocks, analyzes portfolios, predicts trends, and provides
    investment recommendations.
    """
    
    def __init__(self, llm_provider=None):
        """Initialize financial analyzer."""
        self.llm_provider = llm_provider
        self.portfolio: Dict[str, PortfolioPosition] = {}
        self.watchlist: List[str] = []
        self.analysis_history: List[Dict[str, Any]] = []
        
    def analyze_stock(self, symbol: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze a stock comprehensively.
        
        Args:
            symbol: Stock ticker symbol
            context: Market context and additional data
            
        Returns:
            Complete stock analysis
        """
        context = context or {}
        
        stock_data = self._fetch_stock_data(symbol)
        
        technical_analysis = self._perform_technical_analysis(stock_data)
        
        fundamental_analysis = self._perform_fundamental_analysis(symbol, context)
        
        sentiment_analysis = self._analyze_sentiment(symbol)
        
        recommendation = self._generate_recommendation(
            technical_analysis, fundamental_analysis, sentiment_analysis
        )
        
        result = {
            'symbol': symbol,
            'timestamp': datetime.now().isoformat(),
            'stock_data': stock_data,
            'technical_analysis': technical_analysis,
            'fundamental_analysis': fundamental_analysis,
            'sentiment': sentiment_analysis,
            'recommendation': recommendation,
            'risk_score': self._calculate_risk_score(technical_analysis, fundamental_analysis)
        }
        
        self.analysis_history.append(result)
        
        return result
    
    def analyze_portfolio(self, portfolio: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        """
        Analyze investment portfolio.
        
        Args:
            portfolio: Dict of {symbol: shares} or use internal portfolio
            
        Returns:
            Portfolio analysis with recommendations
        """
        if portfolio:
            self._update_portfolio(portfolio)
        
        if not self.portfolio:
            return {'error': 'No portfolio to analyze'}
        
        total_value = sum(pos.current_value for pos in self.portfolio.values())
        total_gain_loss = sum(pos.gain_loss for pos in self.portfolio.values())
        
        positions = [
            {
                'symbol': pos.symbol,
                'shares': pos.shares,
                'cost_basis': pos.cost_basis,
                'current_price': pos.current_price,
                'current_value': pos.current_value,
                'gain_loss': pos.gain_loss,
                'gain_loss_percent': pos.gain_loss_percent,
                'weight': (pos.current_value / total_value * 100) if total_value > 0 else 0
            }
            for pos in self.portfolio.values()
        ]
        
        diversification_score = self._calculate_diversification(positions)
        
        risk_analysis = self._analyze_portfolio_risk(positions)
        
        rebalancing = self._suggest_rebalancing(positions, diversification_score)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'total_value': total_value,
            'total_gain_loss': total_gain_loss,
            'total_return_percent': (total_gain_loss / (total_value - total_gain_loss) * 100) if total_value > total_gain_loss else 0,
            'num_positions': len(positions),
            'positions': sorted(positions, key=lambda x: x['current_value'], reverse=True),
            'diversification_score': diversification_score,
            'risk_analysis': risk_analysis,
            'rebalancing_suggestions': rebalancing,
            'performance_summary': self._generate_performance_summary(positions, total_gain_loss)
        }
    
    def predict_trend(self, symbol: str, days_ahead: int = 30) -> Dict[str, Any]:
        """
        Predict stock price trend.
        
        Args:
            symbol: Stock ticker symbol
            days_ahead: Number of days to predict
            
        Returns:
            Trend prediction with confidence
        """
        if self.llm_provider:
            prediction = self._predict_with_llm(symbol, days_ahead)
        else:
            prediction = self._predict_heuristic(symbol, days_ahead)
        
        return {
            'symbol': symbol,
            'prediction_date': datetime.now().isoformat(),
            'days_ahead': days_ahead,
            'predicted_trend': prediction['trend'],
            'confidence': prediction['confidence'],
            'price_target': prediction.get('price_target'),
            'reasoning': prediction.get('reasoning', 'Based on historical patterns and market conditions')
        }
    
    def _fetch_stock_data(self, symbol: str) -> Dict[str, Any]:
        """Fetch stock data (simulated for demo)."""
        import random
        base_price = random.uniform(50, 500)
        change = random.uniform(-5, 5)
        
        return {
            'symbol': symbol,
            'price': round(base_price, 2),
            'change': round(change, 2),
            'change_percent': round(change / base_price * 100, 2),
            'volume': random.randint(1000000, 50000000),
            'market_cap': round(base_price * random.uniform(1e9, 1e12), 2),
            'pe_ratio': round(random.uniform(10, 40), 2),
            'dividend_yield': round(random.uniform(0, 5), 2)
        }
    
    def _perform_technical_analysis(self, stock_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform technical analysis."""
        price = stock_data['price']
        change_pct = stock_data['change_percent']
        
        if change_pct > 2:
            momentum = 'Strong Bullish'
        elif change_pct > 0:
            momentum = 'Bullish'
        elif change_pct > -2:
            momentum = 'Bearish'
        else:
            momentum = 'Strong Bearish'
        
        rsi = 50 + (change_pct * 5)
        rsi = max(0, min(100, rsi))
        
        if rsi > 70:
            rsi_signal = 'Overbought'
        elif rsi < 30:
            rsi_signal = 'Oversold'
        else:
            rsi_signal = 'Neutral'
        
        return {
            'momentum': momentum,
            'rsi': round(rsi, 2),
            'rsi_signal': rsi_signal,
            'support_level': round(price * 0.95, 2),
            'resistance_level': round(price * 1.05, 2),
            'trend': 'Uptrend' if change_pct > 0 else 'Downtrend'
        }
    
    def _perform_fundamental_analysis(self, symbol: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform fundamental analysis."""
        stock_data = self._fetch_stock_data(symbol)
        
        pe_ratio = stock_data.get('pe_ratio', 20)
        
        if pe_ratio < 15:
            valuation = 'Undervalued'
        elif pe_ratio > 30:
            valuation = 'Overvalued'
        else:
            valuation = 'Fair Value'
        
        return {
            'valuation': valuation,
            'pe_ratio': pe_ratio,
            'market_cap': stock_data.get('market_cap', 0),
            'dividend_yield': stock_data.get('dividend_yield', 0),
            'financial_health': 'Strong' if pe_ratio < 25 else 'Moderate',
            'growth_potential': 'High' if pe_ratio > 20 else 'Moderate'
        }
    
    def _analyze_sentiment(self, symbol: str) -> Dict[str, Any]:
        """Analyze market sentiment."""
        import random
        sentiment_score = random.uniform(-1, 1)
        
        if sentiment_score > 0.3:
            sentiment = 'Positive'
        elif sentiment_score < -0.3:
            sentiment = 'Negative'
        else:
            sentiment = 'Neutral'
        
        return {
            'sentiment': sentiment,
            'sentiment_score': round(sentiment_score, 2),
            'confidence': round(abs(sentiment_score) * 100, 1)
        }
    
    def _generate_recommendation(self, technical: Dict[str, Any],
                                fundamental: Dict[str, Any],
                                sentiment: Dict[str, Any]) -> str:
        """Generate investment recommendation."""
        score = 0
        
        if technical['momentum'] in ['Bullish', 'Strong Bullish']:
            score += 1
        if technical['rsi_signal'] == 'Oversold':
            score += 1
        
        if fundamental['valuation'] == 'Undervalued':
            score += 2
        elif fundamental['valuation'] == 'Overvalued':
            score -= 2
        
        if sentiment['sentiment'] == 'Positive':
            score += 1
        elif sentiment['sentiment'] == 'Negative':
            score -= 1
        
        if score >= 3:
            return 'Strong Buy'
        elif score >= 1:
            return 'Buy'
        elif score >= -1:
            return 'Hold'
        elif score >= -3:
            return 'Sell'
        else:
            return 'Strong Sell'
    
    def _calculate_risk_score(self, technical: Dict[str, Any],
                             fundamental: Dict[str, Any]) -> float:
        """Calculate risk score (0-10)."""
        risk = 5.0
        
        if technical['rsi_signal'] == 'Overbought':
            risk += 1.5
        elif technical['rsi_signal'] == 'Oversold':
            risk -= 1.0
        
        if fundamental['valuation'] == 'Overvalued':
            risk += 2.0
        elif fundamental['valuation'] == 'Undervalued':
            risk -= 1.5
        
        return max(0, min(10, round(risk, 1)))
    
    def _update_portfolio(self, portfolio: Dict[str, float]):
        """Update portfolio positions."""
        self.portfolio.clear()
        
        for symbol, shares in portfolio.items():
            stock_data = self._fetch_stock_data(symbol)
            current_price = stock_data['price']
            cost_basis = current_price * 0.9
            
            current_value = shares * current_price
            total_cost = shares * cost_basis
            gain_loss = current_value - total_cost
            gain_loss_percent = (gain_loss / total_cost * 100) if total_cost > 0 else 0
            
            self.portfolio[symbol] = PortfolioPosition(
                symbol=symbol,
                shares=shares,
                cost_basis=cost_basis,
                current_price=current_price,
                current_value=current_value,
                gain_loss=gain_loss,
                gain_loss_percent=gain_loss_percent
            )
    
    def _calculate_diversification(self, positions: List[Dict[str, Any]]) -> float:
        """Calculate portfolio diversification score (0-100)."""
        if not positions:
            return 0
        
        num_positions = len(positions)
        
        weights = [pos['weight'] for pos in positions]
        concentration = max(weights) if weights else 100
        
        diversity_score = (num_positions * 10) - (concentration * 0.5)
        
        return max(0, min(100, round(diversity_score, 1)))
    
    def _analyze_portfolio_risk(self, positions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze portfolio risk."""
        if not positions:
            return {'risk_level': 'Unknown', 'volatility': 0}
        
        weights = [pos['weight'] for pos in positions]
        max_weight = max(weights)
        
        if max_weight > 50:
            risk_level = 'High'
        elif max_weight > 30:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        avg_gain_loss_pct = sum(pos['gain_loss_percent'] for pos in positions) / len(positions)
        volatility = abs(avg_gain_loss_pct) * 2
        
        return {
            'risk_level': risk_level,
            'concentration_risk': 'High' if max_weight > 40 else 'Moderate' if max_weight > 25 else 'Low',
            'volatility': round(volatility, 2),
            'max_position_weight': round(max_weight, 2)
        }
    
    def _suggest_rebalancing(self, positions: List[Dict[str, Any]],
                           diversification_score: float) -> List[str]:
        """Suggest portfolio rebalancing."""
        suggestions = []
        
        if diversification_score < 50:
            suggestions.append("Consider adding more positions to improve diversification")
        
        for pos in positions:
            if pos['weight'] > 30:
                suggestions.append(f"Reduce {pos['symbol']} position (currently {pos['weight']:.1f}% of portfolio)")
            
            if pos['gain_loss_percent'] < -20:
                suggestions.append(f"Review {pos['symbol']} - significant loss of {pos['gain_loss_percent']:.1f}%")
            elif pos['gain_loss_percent'] > 50:
                suggestions.append(f"Consider taking profits on {pos['symbol']} (+{pos['gain_loss_percent']:.1f}%)")
        
        if not suggestions:
            suggestions.append("Portfolio is well-balanced - no immediate rebalancing needed")
        
        return suggestions
    
    def _generate_performance_summary(self, positions: List[Dict[str, Any]],
                                     total_gain_loss: float) -> str:
        """Generate performance summary."""
        winners = [p for p in positions if p['gain_loss'] > 0]
        losers = [p for p in positions if p['gain_loss'] < 0]
        
        summary = f"""Portfolio Performance Summary

Total Positions: {len(positions)}
Winners: {len(winners)} | Losers: {len(losers)}
Overall P/L: ${total_gain_loss:,.2f}

Best Performer: {max(positions, key=lambda x: x['gain_loss_percent'])['symbol'] if positions else 'N/A'}
Worst Performer: {min(positions, key=lambda x: x['gain_loss_percent'])['symbol'] if positions else 'N/A'}
"""
        return summary
    
    def _predict_with_llm(self, symbol: str, days_ahead: int) -> Dict[str, Any]:
        """Predict using LLM."""
        prompt = f"""Analyze {symbol} stock and predict the price trend for the next {days_ahead} days.

Consider:
1. Historical performance
2. Market conditions
3. Industry trends
4. Economic factors

Provide:
- Trend: (Bullish/Bearish/Neutral)
- Confidence: (0-100%)
- Price Target: (estimated price)
- Reasoning: (brief explanation)

Prediction:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=300,
                temperature=0.7,
                task_type='analysis'
            )
            
            content = response.get('content', '')
            
            if 'bullish' in content.lower():
                trend = 'Bullish'
            elif 'bearish' in content.lower():
                trend = 'Bearish'
            else:
                trend = 'Neutral'
            
            return {
                'trend': trend,
                'confidence': 70,
                'reasoning': content
            }
        except Exception:
            return self._predict_heuristic(symbol, days_ahead)
    
    def _predict_heuristic(self, symbol: str, days_ahead: int) -> Dict[str, Any]:
        """Heuristic prediction."""
        stock_data = self._fetch_stock_data(symbol)
        change_pct = stock_data['change_percent']
        
        if change_pct > 1:
            trend = 'Bullish'
            confidence = 65
        elif change_pct < -1:
            trend = 'Bearish'
            confidence = 65
        else:
            trend = 'Neutral'
            confidence = 50
        
        price_target = stock_data['price'] * (1 + change_pct / 100 * days_ahead / 30)
        
        return {
            'trend': trend,
            'confidence': confidence,
            'price_target': round(price_target, 2),
            'reasoning': f'Based on current momentum ({change_pct}% change)'
        }
    
    def get_market_overview(self) -> Dict[str, Any]:
        """Get overall market overview."""
        indices = ['SPY', 'QQQ', 'DIA']
        
        market_data = {}
        for index in indices:
            data = self._fetch_stock_data(index)
            market_data[index] = {
                'price': data['price'],
                'change': data['change'],
                'change_percent': data['change_percent']
            }
        
        avg_change = sum(d['change_percent'] for d in market_data.values()) / len(market_data)
        
        if avg_change > 1:
            sentiment = 'Risk-On (Bullish)'
        elif avg_change < -1:
            sentiment = 'Risk-Off (Bearish)'
        else:
            sentiment = 'Neutral'
        
        return {
            'timestamp': datetime.now().isoformat(),
            'indices': market_data,
            'market_sentiment': sentiment,
            'avg_change_percent': round(avg_change, 2)
        }
