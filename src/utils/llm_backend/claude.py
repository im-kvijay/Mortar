from typing import Dict, Any, Optional, List
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config import config
from utils.llm_backend.base import LLMBackend, LLMResponse


class ClaudeBackend(LLMBackend):

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None
    ):
        if model is None:
            model = config.DEFAULT_MODEL

        super().__init__(model)

        if api_key is None:
            api_key = config.ANTHROPIC_API_KEY
            if not api_key:
                raise ValueError(
                    "ANTHROPIC_API_KEY not set in environment. "
                    "Set it with: export ANTHROPIC_API_KEY='your-key-here'"
                )

        try:
            from anthropic import Anthropic
            import httpx

            timeout = httpx.Timeout(
                timeout=900.0,
                read=900.0,
                write=60.0,
                connect=10.0
            )

            self.client = Anthropic(api_key=api_key, timeout=timeout)
            self.available = True
        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")

    def __del__(self):
        try:
            if hasattr(self, 'client') and self.client:
                self.client.close()
        except Exception:
            pass

    def is_available(self) -> bool:
        return self.available

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        thinking_budget: Optional[int] = None,
        **kwargs
    ) -> LLMResponse:
        if max_tokens is None:
            max_tokens = config.MAX_OUTPUT_TOKENS
        if thinking_budget is None:
            thinking_budget = config.EXTENDED_THINKING_BUDGET

        if thinking_budget > 0:
            temperature = 1.0
            if max_tokens <= thinking_budget:
                max_tokens = thinking_budget + 4000
        elif temperature is None:
            temperature = config.NORMAL_TEMPERATURE

        request_params = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}]
        }

        if system_prompt:
            request_params["system"] = system_prompt

        if thinking_budget > 0:
            request_params["thinking"] = {
                "type": "enabled",
                "budget_tokens": thinking_budget
            }

        response = self.client.messages.create(**request_params)

        response_text = ""
        thinking_text = None

        for block in response.content:
            if block.type == "thinking":
                thinking_text = block.thinking
            elif block.type == "text":
                response_text += block.text

        prompt_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        thinking_tokens = getattr(response.usage, 'thinking_tokens', 0)

        pricing = config.get_model_pricing(self.model)
        cost = (
            prompt_tokens * pricing["input"] / 1_000_000 +
            (output_tokens + thinking_tokens) * pricing["output"] / 1_000_000
        )

        return LLMResponse(
            text=response_text,
            thinking=thinking_text,
            prompt_tokens=prompt_tokens,
            output_tokens=output_tokens,
            thinking_tokens=thinking_tokens,
            cost=cost,
            model=self.model,
            metadata={
                "stop_reason": response.stop_reason,
                "stop_sequence": response.stop_sequence,
            }
        )

    def generate_with_cache(
        self,
        cache_prefix: str,
        dynamic_suffix: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        thinking_budget: Optional[int] = None,
        **kwargs
    ) -> LLMResponse:
        if max_tokens is None:
            max_tokens = config.MAX_OUTPUT_TOKENS
        if thinking_budget is None:
            thinking_budget = config.EXTENDED_THINKING_BUDGET

        if thinking_budget > 0:
            temperature = 1.0
            if max_tokens <= thinking_budget:
                max_tokens = thinking_budget + 4000
        elif temperature is None:
            temperature = config.NORMAL_TEMPERATURE

        user_content = [
            {
                "type": "text",
                "text": cache_prefix,
                "cache_control": {"type": "ephemeral"}
            },
            {
                "type": "text",
                "text": dynamic_suffix
            }
        ]

        request_params = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": user_content}]
        }

        if system_prompt:
            request_params["system"] = [
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"}
                }
            ]

        if thinking_budget > 0:
            request_params["thinking"] = {
                "type": "enabled",
                "budget_tokens": thinking_budget
            }

        response = self.client.messages.create(
            **request_params,
            extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"}
        )

        response_text = ""
        thinking_text = None

        for block in response.content:
            if block.type == "thinking":
                thinking_text = block.thinking
            elif block.type == "text":
                response_text += block.text

        prompt_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        thinking_tokens = getattr(response.usage, 'thinking_tokens', 0)

        cache_creation_tokens = getattr(response.usage, 'cache_creation_input_tokens', 0)
        cache_read_tokens = getattr(response.usage, 'cache_read_input_tokens', 0)

        pricing = config.get_model_pricing(self.model)

        regular_tokens = max(0, prompt_tokens - cache_creation_tokens - cache_read_tokens)

        cost = (
            regular_tokens * pricing["input"] / 1_000_000 +
            cache_creation_tokens * pricing["input"] * 1.25 / 1_000_000 +
            cache_read_tokens * pricing["input"] * 0.1 / 1_000_000 +
            (output_tokens + thinking_tokens) * pricing["output"] / 1_000_000
        )

        return LLMResponse(
            text=response_text,
            thinking=thinking_text,
            prompt_tokens=prompt_tokens,
            output_tokens=output_tokens,
            thinking_tokens=thinking_tokens,
            cost=cost,
            model=self.model,
            metadata={
                "stop_reason": response.stop_reason,
                "stop_sequence": response.stop_sequence,
                "cache_creation_tokens": cache_creation_tokens,
                "cache_read_tokens": cache_read_tokens,
                "cache_hit": cache_read_tokens > 0,
                "cache_savings": (cache_read_tokens * pricing["input"] * 0.9 / 1_000_000) if cache_read_tokens > 0 else 0
            }
        )

    def generate_with_tools(
        self,
        prompt: str,
        tools: List[Dict[str, Any]],
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        thinking_budget: Optional[int] = None,
        enable_interleaved_thinking: bool = True,
        **kwargs
    ) -> LLMResponse:
        if max_tokens is None:
            max_tokens = config.MAX_OUTPUT_TOKENS

        if thinking_budget is None:
            thinking_budget = config.EXTENDED_THINKING_BUDGET

        if thinking_budget > 0:
            temperature = 1.0
            if max_tokens <= thinking_budget:
                max_tokens = min(thinking_budget + 12000, 64000)
        elif temperature is None:
            temperature = config.NORMAL_TEMPERATURE

        request_params = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
            "tools": tools
        }

        if system_prompt:
            request_params["system"] = system_prompt

        if thinking_budget > 0:
            request_params["thinking"] = {
                "type": "enabled",
                "budget_tokens": thinking_budget
            }

        extra_headers = {}
        if enable_interleaved_thinking and thinking_budget > 0 and config.ENABLE_INTERLEAVED_THINKING:
            extra_headers["anthropic-beta"] = "interleaved-thinking-2025-05-14"
            if config.DEBUG_LLM_CALLS:
                print("[debug] interleaved thinking enabled")

        if config.DEBUG_LLM_CALLS:
            print(f"[debug] request params: {list(request_params.keys())}")
            if 'thinking' in request_params:
                print(f"[debug] thinking config: {request_params['thinking']}")
            if extra_headers:
                print(f"[debug] extra headers: {extra_headers}")

        use_streaming = False
        if config.ENABLE_STREAMING and config.DEBUG_LLM_CALLS:
            print("[debug] streaming disabled pending tool_result support")
        if config.DEBUG_LLM_CALLS:
            print(f"[debug] thinking budget: {thinking_budget}, streaming: {use_streaming}")

        if use_streaming:
            response_text = ""
            thinking_text = None
            tool_calls = []
            usage = None
            thinking_events = 0

            with self.client.messages.stream(
                **request_params,
                extra_headers=extra_headers if extra_headers else None
            ) as stream:
                for event in stream:
                    if hasattr(event, 'type') and event.type == 'message_start':
                        usage = event.message.usage

                    if hasattr(event, 'type') and event.type == 'content_block_delta':
                        delta = event.delta
                        if hasattr(delta, 'type'):
                            if delta.type == 'thinking_delta':
                                if thinking_text is None:
                                    thinking_text = ""
                                thinking_text += delta.thinking
                                thinking_events += 1
                            elif delta.type == 'text_delta':
                                response_text += delta.text

                final_message = stream.get_final_message()
                usage = final_message.usage

                if thinking_events > 0:
                    print(f"[debug] thinking events: {thinking_events}, chars: {len(thinking_text) if thinking_text else 0}")

                tool_calls = []
                for block in final_message.content:
                    if block.type == "tool_use":
                        tool_calls.append({
                            "id": block.id,
                            "name": block.name,
                            "input": block.input
                        })

                stop_reason = final_message.stop_reason
                stop_sequence = final_message.stop_sequence
        else:
            response = self.client.messages.create(
                **request_params,
                extra_headers=extra_headers if extra_headers else None
            )

            response_text = ""
            thinking_text = None
            tool_calls = []

            for block in response.content:
                if block.type == "thinking":
                    thinking_text = block.thinking
                elif block.type == "text":
                    response_text += block.text
                elif block.type == "tool_use":
                    tool_calls.append({
                        "id": block.id,
                        "name": block.name,
                        "input": block.input
                    })

            usage = response.usage
            stop_reason = response.stop_reason
            stop_sequence = response.stop_sequence

        prompt_tokens = usage.input_tokens
        output_tokens = usage.output_tokens
        thinking_tokens = getattr(usage, 'thinking_tokens', 0)

        if config.DEBUG_LLM_CALLS:
            print(f"[debug] usage: {usage}")
            print(f"[debug] thinking budget: {thinking_budget}, used: {thinking_tokens}")

        pricing = config.get_model_pricing(self.model)
        cost = (
            prompt_tokens * pricing["input"] / 1_000_000 +
            (output_tokens + thinking_tokens) * pricing["output"] / 1_000_000
        )

        return LLMResponse(
            text=response_text,
            thinking=thinking_text,
            prompt_tokens=prompt_tokens,
            output_tokens=output_tokens,
            thinking_tokens=thinking_tokens,
            cost=cost,
            model=self.model,
            tool_calls=tool_calls,
            metadata={
                "stop_reason": stop_reason,
                "stop_sequence": stop_sequence,
            }
        )

    def generate_with_tools_multi_turn(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        thinking_budget: Optional[int] = None,
        enable_interleaved_thinking: bool = True,
        enable_memory_tool: bool = False,
        enable_context_editing: bool = False,
        context_edit_trigger_tokens: int = 500,
        **kwargs
    ) -> LLMResponse:
        if max_tokens is None:
            max_tokens = config.MAX_OUTPUT_TOKENS

        if thinking_budget is None:
            thinking_budget = config.EXTENDED_THINKING_BUDGET

        if thinking_budget > 0 and thinking_budget < 1024:
            print(f"[warning] thinking budget {thinking_budget} below minimum 1024, increasing")
            thinking_budget = 1024

        if thinking_budget > 0:
            temperature = 1.0
            if max_tokens <= thinking_budget:
                max_tokens = min(thinking_budget + 12000, 64000)
        elif temperature is None:
            temperature = config.NORMAL_TEMPERATURE

        tools_payload = list(tools) if tools else []

        request_params = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
            "tools": tools_payload
        }

        if system_prompt:
            request_params["system"] = system_prompt

        if thinking_budget > 0:
            request_params["thinking"] = {
                "type": "enabled",
                "budget_tokens": thinking_budget
            }

        extra_headers = {}
        beta_features = []

        if (
            enable_interleaved_thinking
            and config.ENABLE_INTERLEAVED_THINKING
            and thinking_budget > 0
        ):
            beta_features.append("interleaved-thinking-2025-05-14")

        if enable_memory_tool or enable_context_editing:
            beta_features.append("context-management-2025-06-27")

        if beta_features:
            extra_headers["anthropic-beta"] = ",".join(beta_features)

        if enable_memory_tool:
            tools_payload.append({
                "type": "memory_20250818",
                "name": "memory"
            })

        if enable_context_editing:
            request_params["context_management"] = {
                "edits": [
                    {
                        "type": "clear_tool_uses_20250919",
                        "trigger": {"type": "input_tokens", "value": context_edit_trigger_tokens},
                        "keep": {"type": "tool_uses", "value": 2},
                        "clear_at_least": {"type": "input_tokens", "value": 100}
                    }
                ]
            }

        if config.DEBUG_LLM_CALLS:
            print(f"[debug multi-turn] messages: {len(messages)}, budget: {thinking_budget}")
            if 'thinking' in request_params:
                print(f"[debug multi-turn] thinking: {request_params['thinking']}")
            print(f"[debug multi-turn] model: {request_params.get('model')}")
            print(f"[debug multi-turn] max_tokens: {request_params.get('max_tokens')}")
            print(f"[debug multi-turn] temp: {request_params.get('temperature')}")
            print(f"[debug multi-turn] tools: {len(request_params.get('tools', []))}")
            print(f"[debug multi-turn] system: {'system' in request_params}")
            print(f"[debug multi-turn] beta: {beta_features}")

        use_streaming = False
        if config.ENABLE_STREAMING and config.DEBUG_LLM_CALLS:
            print("[debug multi-turn] streaming disabled pending tool_result support")

        if use_streaming:
            response_text = ""
            thinking_text = None
            tool_calls = []
            usage = None
            thinking_events = 0

            with self.client.messages.stream(
                **request_params,
                extra_headers=extra_headers if extra_headers else None
            ) as stream:
                for event in stream:
                    if hasattr(event, 'type') and event.type == 'message_start':
                        usage = event.message.usage

                    if hasattr(event, 'type') and event.type == 'content_block_delta':
                        delta = event.delta
                        if hasattr(delta, 'type'):
                            if delta.type == 'thinking_delta':
                                if thinking_text is None:
                                    thinking_text = ""
                                thinking_text += delta.thinking
                                thinking_events += 1
                            elif delta.type == 'text_delta':
                                response_text += delta.text

                final_message = stream.get_final_message()
                usage = final_message.usage

                if thinking_events > 0:
                    print(f"[debug] thinking events: {thinking_events}, chars: {len(thinking_text) if thinking_text else 0}")

                tool_calls = []
                for block in final_message.content:
                    if block.type == "tool_use":
                        tool_calls.append({
                            "id": block.id,
                            "name": block.name,
                            "input": block.input
                        })

                stop_reason = final_message.stop_reason
                stop_sequence = final_message.stop_sequence
        else:
            if config.DEBUG_LLM_CALLS:
                import time
                start = time.time()
                print(f"[debug multi-turn] calling api at {time.strftime('%H:%M:%S')}")

            response = self.client.messages.create(
                **request_params,
                extra_headers=extra_headers if extra_headers else None
            )

            if config.DEBUG_LLM_CALLS:
                elapsed = time.time() - start
                print(f"[debug multi-turn] returned after {elapsed:.1f}s")

            response_text = ""
            thinking_text = None
            tool_calls = []

            for block in response.content:
                if block.type == "thinking":
                    thinking_text = block.thinking
                elif block.type == "text":
                    response_text += block.text
                elif block.type == "tool_use":
                    tool_calls.append({
                        "id": block.id,
                        "name": block.name,
                        "input": block.input
                    })

            usage = response.usage
            stop_reason = response.stop_reason
            stop_sequence = response.stop_sequence

        prompt_tokens = usage.input_tokens
        output_tokens = usage.output_tokens
        thinking_tokens = getattr(usage, 'thinking_tokens', 0)

        pricing = config.get_model_pricing(self.model)
        cost = (
            prompt_tokens * pricing["input"] / 1_000_000 +
            (output_tokens + thinking_tokens) * pricing["output"] / 1_000_000
        )

        return LLMResponse(
            text=response_text,
            thinking=thinking_text,
            prompt_tokens=prompt_tokens,
            output_tokens=output_tokens,
            thinking_tokens=thinking_tokens,
            cost=cost,
            model=self.model,
            tool_calls=tool_calls,
            metadata={
                "stop_reason": stop_reason,
                "stop_sequence": stop_sequence,
                "raw_content": response.content
            }
        )
