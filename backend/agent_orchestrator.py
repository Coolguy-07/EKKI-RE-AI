"""
backend/agent_orchestrator.py

Modular Multi-Agent Routing System for EKKI-RE-AI.
Routes reverse engineering and security tasks through specialized local Ollama models in sequence,
while preserving VRAM optimization (keep_alive: 0) for hardware constraints (6GB VRAM).
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional, Set

from ollama import Client, ResponseError

from .ai import extract_ollama_response_content
from .config import settings
from .memory import ChatMessage, session_memory_manager
from .prompts import GLOBAL_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

# Specialized agent task instructions
DECOMPILER_TASK_PROMPT = """
You are the Decompilation Specialist agent.
Your sole task is to analyze assembly (x86, x64, ARM), hex dumps, or binary code fragments provided by the user.
Translate raw assembly/hex instructions into clear, structured C pseudocode with accurate variable names, control flow comments, and function signature annotations.
"""

VULN_ANALYST_TASK_PROMPT = """
You are the Vulnerability Analyst agent.
Your task is to perform an in-depth security audit of code or pseudocode.
Identify memory corruption risks, buffer overflows, integer overflows, format string flaws, double-frees, logic vulnerabilities, or unvalidated inputs.
Explain the root cause of each identified vulnerability clearly.
"""

OBFUSCATION_TASK_PROMPT = """
You are the Obfuscation Specialist agent.
Your task is to analyze binary or code logic for anti-debugging tricks, anti-VM checks, packing mechanisms, string encryption routines, code virtualization, or control flow flattening.
Identify specific evasion mechanisms and recommend de-obfuscation techniques.
"""

SYNTHESIZER_TASK_PROMPT = """
You are the Lead Synthesizer agent and Master Reverse Engineering Architect.
Combine all specialist findings (decompilation, vulnerability analysis, obfuscation tricks) and generate a comprehensive, structured Reverse Engineering Report.
Structure your output into clear markdown sections:
1. Executive Summary
2. Architecture & Control Flow Analysis
3. Security & Vulnerability Assessment
4. Anti-Analysis & Obfuscation Measures
5. Recommendations & Remediation Plan
"""


def build_agent_system_prompt(task_prompt: str) -> str:
    """Combines the centralized GLOBAL_SYSTEM_PROMPT with specialist instructions."""
    return f"{GLOBAL_SYSTEM_PROMPT}\n\n{task_prompt.strip()}"


DECOMPILER_SYSTEM_PROMPT = build_agent_system_prompt(DECOMPILER_TASK_PROMPT)
VULN_ANALYST_SYSTEM_PROMPT = build_agent_system_prompt(VULN_ANALYST_TASK_PROMPT)
OBFUSCATION_SYSTEM_PROMPT = build_agent_system_prompt(OBFUSCATION_TASK_PROMPT)
SYNTHESIZER_SYSTEM_PROMPT = build_agent_system_prompt(SYNTHESIZER_TASK_PROMPT)



@dataclass
class AgentSpec:
    """Modular specification for a specialized pipeline agent."""

    id: str
    name: str
    model: str
    system_prompt: str
    description: str
    is_optional: bool = True
    priority: int = 10


class AgentRegistry:
    """Registry managing pluggable agent specifications."""

    def __init__(self) -> None:
        self._agents: Dict[str, AgentSpec] = {}
        self._register_defaults()

    def register(self, agent: AgentSpec) -> None:
        """Register a new specialist agent."""
        self._agents[agent.id] = agent
        logger.info("Registered agent '%s' (Model: %s)", agent.id, agent.model)

    def get(self, agent_id: str) -> Optional[AgentSpec]:
        """Retrieve an agent specification by ID."""
        return self._agents.get(agent_id)

    def list_agents(self) -> List[AgentSpec]:
        """List all registered agents sorted by priority."""
        return sorted(self._agents.values(), key=lambda a: a.priority)

    def _register_defaults(self) -> None:
        """Register default core specialist agents from configuration."""
        self.register(
            AgentSpec(
                id="decompilation",
                name="Decompilation Specialist",
                model=settings.DECOMPILER_MODEL,
                system_prompt=DECOMPILER_SYSTEM_PROMPT,
                description="Translates ASM/hex into C pseudocode and explains logic.",
                is_optional=True,
                priority=1,
            )
        )
        self.register(
            AgentSpec(
                id="vulnerability",
                name="Vulnerability Analyst",
                model=settings.VULN_ANALYST_MODEL,
                system_prompt=VULN_ANALYST_SYSTEM_PROMPT,
                description="Audits code for memory corruption, buffer overflows, or logic flaws.",
                is_optional=True,
                priority=2,
            )
        )
        self.register(
            AgentSpec(
                id="obfuscation",
                name="Obfuscation Specialist",
                model=settings.OBFUSCATION_MODEL,
                system_prompt=OBFUSCATION_SYSTEM_PROMPT,
                description="Analyzes anti-debugging, packing, or obfuscation tricks.",
                is_optional=True,
                priority=3,
            )
        )
        self.register(
            AgentSpec(
                id="synthesis",
                name="Lead Synthesizer",
                model=settings.SYNTHESIZER_MODEL,
                system_prompt=SYNTHESIZER_SYSTEM_PROMPT,
                description="Synthesizes all findings into a structured Reverse Engineering Report.",
                is_optional=False,
                priority=4,
            )
        )


class IntentRouter:
    """Classifies incoming user requests to determine execution path and required stages."""

    RE_PATTERNS = [
        r"\basm\b", r"\bassembly\b", r"\bdisassembl", r"\bdecompil", r"\bhex\b",
        r"\bopcodes?\b", r"\bmov\b", r"\bpush\b", r"\bpop\b", r"\bjmp\b", r"\bcall\b",
        r"\bregister[s]?\b", r"\beax\b", r"\brax\b", r"\brsp\b", r"\brbp\b",
        r"\bbuffer overflow\b", r"\bmemory corruption\b", r"\bexploit\b", r"\bpayload\b",
        r"\bshellcode\b", r"\bmalware\b", r"\bransomware\b", r"\bpefile\b", r"\belf\b",
        r"\bobfuscat", r"\bpack(ed|er)?\b", r"\banti-debug\b", r"\bptrace\b",
        r"\bida\b", r"\bghidra\b", r"\bradar2?\b", r"\bx64dbg\b", r"\bbinary analysis\b",
        r"\breverse engineer\b", r"\bre\b"
    ]

    def __init__(self, registry: AgentRegistry) -> None:
        self.registry = registry
        self._re_regex = re.compile("|".join(self.RE_PATTERNS), re.IGNORECASE)

    def route(self, prompt: str) -> Dict[str, Any]:
        """Classifies prompt intent and determines active specialist stages."""
        matches = self._re_regex.findall(prompt)
        is_re_task = len(matches) > 0 or len(prompt) > 300

        if not is_re_task:
            return {
                "route": "GENERAL_CHAT",
                "reason": "Standard programming or general inquiry detected.",
                "active_stage_ids": ["synthesis"],
            }

        sorted_stage_ids = [agent.id for agent in self.registry.list_agents()]

        return {
            "route": "REVERSE_ENGINEERING",
            "reason": f"Reverse Engineering task detected ({', '.join(set(matches[:5])) if matches else 'long prompt'}).",
            "active_stage_ids": sorted_stage_ids,
        }


class AgentOrchestrator:
    """Async Multi-Agent Orchestrator with strict VRAM cleanup (keep_alive: 0) and SSE streaming."""

    def __init__(self, host: Optional[str] = None) -> None:
        self.host = host or settings.OLLAMA_HOST
        self._client = Client(host=self.host)
        self.registry = AgentRegistry()
        self.router = IntentRouter(self.registry)

    def unload_model(self, model_name: str) -> bool:
        """Evicts a loaded model from GPU VRAM by issuing a keep_alive: 0 request."""
        try:
            logger.info("Unloading model '%s' from GPU VRAM (keep_alive=0)...", model_name)
            self._client.generate(model=model_name, prompt="", keep_alive=0)
            return True
        except Exception as err:
            logger.warning("VRAM unload request for '%s' returned: %s", model_name, err)
            return False

    def run_pipeline_stream(
        self, prompt: str, session_id: Optional[str] = None
    ) -> Generator[str, None, None]:
        """Executes the multi-agent pipeline sequentially and streams SSE events."""
        if not prompt or not prompt.strip():
            err_frame = json.dumps({"error": "Prompt cannot be empty."})
            yield f"data: {err_frame}\n\n"
            return

        # Fetch session conversation history if session_id is provided
        target_store = session_memory_manager.get_store(session_id) if session_id else None
        history: List[ChatMessage] = target_store.get_messages() if target_store else []

        route_info = self.router.route(prompt)
        route_name = route_info["route"]
        active_stage_ids: List[str] = route_info["active_stage_ids"]

        intent_event = json.dumps({
            "type": "intent",
            "route": route_name,
            "reason": route_info["reason"],
            "stages": [
                {"id": sid, "name": self.registry.get(sid).name, "model": self.registry.get(sid).model}
                for sid in active_stage_ids if self.registry.get(sid)
            ],
        })
        yield f"data: {intent_event}\n\n"

        accumulated_stage_outputs: Dict[str, str] = {}
        last_used_model: Optional[str] = None

        try:
            for stage_id in active_stage_ids:
                agent = self.registry.get(stage_id)
                if not agent:
                    continue

                if last_used_model and last_used_model != agent.model:
                    self.unload_model(last_used_model)
                    unload_event = json.dumps({
                        "type": "vram_unload",
                        "unloaded_model": last_used_model,
                        "next_model": agent.model,
                    })
                    yield f"data: {unload_event}\n\n"

                last_used_model = agent.model

                logger.info(
                    "Executing stage '%s' (%s) using model '%s' | System Prompt Prefix: %.60s...",
                    agent.id,
                    agent.name,
                    agent.model,
                    agent.system_prompt.replace("\n", " "),
                )

                stage_start_event = json.dumps({
                    "type": "stage_start",
                    "stage_id": agent.id,
                    "stage_name": agent.name,
                    "model": agent.model,
                })
                yield f"data: {stage_start_event}\n\n"


                messages_payload = [{"role": "system", "content": agent.system_prompt}]

                # Include prior session conversation history
                for msg in history:
                    messages_payload.append(msg.to_ollama_dict())

                if route_name == "REVERSE_ENGINEERING" and agent.id != "decompilation":
                    context_summary = []
                    for prev_id, prev_out in accumulated_stage_outputs.items():
                        prev_agent = self.registry.get(prev_id)
                        agent_title = prev_agent.name if prev_agent else prev_id
                        context_summary.append(f"### Findings from {agent_title}:\n{prev_out}")

                    if context_summary:
                        messages_payload.append({
                            "role": "user",
                            "content": f"Prior Specialist Analysis:\n" + "\n\n".join(context_summary)
                        })

                messages_payload.append({"role": "user", "content": prompt})

                accumulated_tokens: List[str] = []

                stream_response = self._client.chat(
                    model=agent.model,
                    messages=messages_payload,
                    stream=True,
                    options={"num_ctx": settings.OLLAMA_NUM_CTX},
                )

                for chunk in stream_response:
                    content = extract_ollama_response_content(chunk)
                    if content:
                        accumulated_tokens.append(content)
                        chunk_event = json.dumps({
                            "type": "stage_chunk",
                            "stage_id": agent.id,
                            "content": content,
                        })
                        yield f"data: {chunk_event}\n\n"

                stage_result = "".join(accumulated_tokens)
                accumulated_stage_outputs[agent.id] = stage_result

                stage_done_event = json.dumps({
                    "type": "stage_complete",
                    "stage_id": agent.id,
                })
                yield f"data: {stage_done_event}\n\n"

            if last_used_model:
                self.unload_model(last_used_model)
                unload_event = json.dumps({
                    "type": "vram_unload",
                    "unloaded_model": last_used_model,
                    "status": "VRAM cleared",
                })
                yield f"data: {unload_event}\n\n"

            final_output = accumulated_stage_outputs.get("synthesis", "")
            if session_id and final_output:
                store = session_memory_manager.get_store(session_id)
                store.add_message(ChatMessage(role="user", content=prompt))
                store.add_message(ChatMessage(role="assistant", content=final_output))

            done_event = json.dumps({"type": "done", "status": "completed", "done": True})
            yield f"data: {done_event}\n\n"

        except ResponseError as err:
            logger.error("Ollama ResponseError in stage: %s", err)
            err_event = json.dumps({"error": f"Ollama API Error (HTTP {err.status_code}): {err.error}"})
            yield f"data: {err_event}\n\n"
        except Exception as err:
            logger.exception("Unexpected error during multi-agent orchestration execution.")
            err_event = json.dumps({"error": f"Orchestrator error: {str(err)}"})
            yield f"data: {err_event}\n\n"


agent_orchestrator = AgentOrchestrator()
