"""
backend/prompts/__init__.py

Public package exports for the backend prompt engineering module.
"""

from .system_prompt import DEFAULT_SYSTEM_PROMPT, GLOBAL_SYSTEM_PROMPT, get_system_prompt

__all__ = ["get_system_prompt", "DEFAULT_SYSTEM_PROMPT", "GLOBAL_SYSTEM_PROMPT"]