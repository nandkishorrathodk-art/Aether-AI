"""
Code Generation Assistant module.

Provides multi-language code generation, debugging, refactoring, and analysis.
"""

from .code_generator import (
    CodeGenerator,
    GeneratedCode,
    CodeAnalysis,
    ProgrammingLanguage
)

__all__ = [
    'CodeGenerator',
    'GeneratedCode',
    'CodeAnalysis',
    'ProgrammingLanguage'
]
