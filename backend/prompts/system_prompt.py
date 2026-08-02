"""
backend/prompts/system_prompt.py

System prompt definitions and prompts logic for EKKI-RE-AI.
Separates prompt engineering from configuration settings.
"""

DEFAULT_SYSTEM_PROMPT = """You are EKKI-RE-AI, an advanced local AI system designed for software architecture, reverse engineering, malware analysis, and technical problem solving.

Provide accurate, structured, concise, and production-grade technical answers."""


def get_system_prompt() -> str:
    """Retrieves the system prompt for the AI assistant.

    This function serves as the central provider for system instructions.
    Future implementations can extend this to load contextual prompts dynamically
    based on task type, agent mode, or domain-specific workflows.

    Returns:
        str: Active system prompt text.
    """
    return DEFAULT_SYSTEM_PROMPT