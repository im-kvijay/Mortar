"""xai grok backend direct integration with xai sdk for grok models. based on the xai_sdk stateful c..."""

import json
import os
import time
import threading
from typing import Dict, Any, Optional, List, Tuple, Type
from copy import deepcopy

import grpc

from xai_sdk import Client
from xai_sdk.chat import system, tool_result, user, tool

from pydantic import BaseModel

from .base import LLMBackend, LLMResponse
from config import config

# chat history retention limit to prevent memory bloat
MAX_CHAT_MESSAGES = 50


class GrokBackend(LLMBackend):
    """backend for xai's grok models using the official xai sdk. this backend uses the xai_sdk's statefu..."""

#    # class-level lock for thread safety across all chat operations
    _chat_lock = threading.RLock()

    def __init__(self, model: str, api_key: Optional[str] = None):
        """initialize the grok backend. args: model: model name (e.g., "grok-4.1-fast", "grok-4.1") can also..."""
        normalized = config.MODEL_ALIASES.get(model, model)
#        # retain canonical identifier (with provider prefix) for logging + config lookups.
        super().__init__(normalized)
        if normalized.startswith("x-ai/"):
            self.api_model = normalized.split("/", 1)[1]
        else:
            self.api_model = normalized

#        # get api key from parameter or environment
        if api_key is None:
            api_key = os.getenv("XAI_API_KEY")
        if not api_key:
            raise ValueError(
                "XAI_API_KEY environment variable not set. "
                "Please set it to your xAI API key."
            )

#        # initialize xai client
        self.client = Client(
            api_key=api_key,
            timeout=3600,  # 1 hour timeout for long reasoning sessions
        )

#        # track current chat session (created once, reused)
# instance-level lock for per-instance thread safety
        self._instance_lock = threading.RLock()
        self.chat = None
        self._system_prompt = None
        self._tools_hash = None  # track tool configuration
        self._messages_processed = 0  # track how many messages we've already appended
        self._reasoning_effort: Optional[str] = None  # pending effort for reasoning models
        self._applied_reasoning_effort: Optional[str] = None  # effort applied to current chat session

    def _reset_chat(self, system_prompt: Optional[str] = None, tools: Optional[List[Dict]] = None):
        """reset the chat session with new system prompt and tools. thread-safe: acquires instance lock befo..."""
# caller should hold _instance_lock, but we verify here for safety
        tools_hash = self._compute_tools_hash(tools)

        extra_kwargs: Dict[str, Any] = {}
        if self._reasoning_effort in ("low", "high"):
            extra_kwargs["reasoning_effort"] = self._reasoning_effort

        if tools:
            normalized_tools = [self._normalize_tool_definition(t) for t in tools]
            xai_tools: List[Any] = []
            for entry in normalized_tools:
                if entry.get("type") == "function" and "function" in entry:
                    fn = entry["function"]
                    xai_tools.append(
                        tool(
                            name=fn.get("name", "unnamed_tool"),
                            description=fn.get("description", ""),
                            parameters=fn.get("parameters", {"type": "object", "properties": {}}),
                        )
                    )
                else:
                    xai_tools.append(entry)

            self.chat = self.client.chat.create(
                model=self.api_model,
                tools=xai_tools,
                **extra_kwargs,
            )
        else:
            self.chat = self.client.chat.create(model=self.api_model, **extra_kwargs)

        if system_prompt:
            self.chat.append(system(system_prompt))

        self._system_prompt = system_prompt
        self._tools_hash = tools_hash
        self._applied_reasoning_effort = self._reasoning_effort
        self._messages_processed = 0

    def _trim_chat_history(self):
        """trim chat history to prevent memory bloat. thread-safe."""
# caller should hold _instance_lock
        if not self.chat or not hasattr(self.chat, 'messages'):
            return

        if len(self.chat.messages) > MAX_CHAT_MESSAGES:
#            # find system message if it exists
            system_msgs = [msg for msg in self.chat.messages
                           if hasattr(msg, 'role') and msg.role == 'system']

            if system_msgs:
#                # keep system message + last n-1 messages
                self.chat.messages = system_msgs[:1] + self.chat.messages[-(MAX_CHAT_MESSAGES-1):]
            else:
#                # no system message, just keep last n
                self.chat.messages = self.chat.messages[-MAX_CHAT_MESSAGES:]

    def _calculate_cost(self, prompt_tokens: int, output_tokens: int, thinking_tokens: int = 0) -> float:
        """calculate cost based on token usage. args: prompt_tokens: number of input tokens output_tokens: n..."""
#        # use config.py as source of truth for pricing
        prices = config.get_model_pricing(self.model)

#        # separate cost calculation for reasoning tokens
        input_cost = (prompt_tokens / 1_000_000) * prices["input"]
        output_cost = (output_tokens / 1_000_000) * prices["output"]
        reasoning_cost = (thinking_tokens / 1_000_000) * prices.get("reasoning_output", prices["output"])

        total_cost = input_cost + output_cost + reasoning_cost
        return total_cost

    def _normalize_tool_definition(self, tool_def: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """normalize tool definitions for xai server-side or function tools."""
        if not tool_def:
            return {}

        tool_type = tool_def.get("type")
        if tool_type in {"web_search", "x_search", "code_execution"}:
            return deepcopy(tool_def)

#        # already in function schema format
        if tool_type == "function" and tool_def.get("function"):
            normalized = deepcopy(tool_def)
            params = normalized["function"].get("parameters") or {}
            if "type" not in params:
                params = {"type": "object", **params}
            normalized["function"]["parameters"] = params
            return normalized

        name = tool_def.get("name") or tool_def.get("function", {}).get("name") or "unnamed_tool"
        description = tool_def.get("description") or tool_def.get("function", {}).get("description", "")
        parameters = tool_def.get("parameters") or tool_def.get("input_schema") or {"type": "object", "properties": {}}
        if "type" not in parameters:
            parameters = {"type": "object", **parameters}

        return {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": parameters,
            },
        }

    def _compute_tools_hash(self, tools: Optional[List[Dict[str, Any]]]) -> Optional[int]:
        """compute a hash for the tool definition list to detect changes."""
        if not tools:
            return None

        try:
            return hash(json.dumps(tools, sort_keys=True))
        except TypeError:
            normalized = [self._normalize_tool_definition(t) for t in tools]
            try:
                return hash(json.dumps(normalized, sort_keys=True))
            except TypeError:
                return hash(str(normalized))

    def supports_structured_outputs(self) -> bool:
        return True

    def _prepare_session(
        self,
        *,
        system_prompt: Optional[str],
        tools: Optional[List[Dict]],
        reasoning_effort: Optional[str],
        force_reset: bool,
        _retry_reasoning: bool
    ) -> Tuple[Optional[str], Optional[int]]:
        from config import config as _cfg
        registry_entry = _cfg.MODEL_REGISTRY.get(self.model, {})
        support = registry_entry.get("reasoning_support")
        default_effort = registry_entry.get("reasoning_default", {}).get("effort")
        env_effort = os.getenv("GROK_EFFORT")
        if _retry_reasoning:
            eff = reasoning_effort or (env_effort if env_effort in ("low", "high") else None) or default_effort
        else:
            eff = reasoning_effort
        if support == "effort" and eff in ("low", "high"):
            self._reasoning_effort = eff
        else:
            self._reasoning_effort = None

        tools_hash = self._compute_tools_hash(tools)
        should_reset = (
            self.chat is None
            or system_prompt != self._system_prompt
            or tools_hash != self._tools_hash
            or self._applied_reasoning_effort != self._reasoning_effort
            or force_reset
        )
        if should_reset:
            self._reset_chat(system_prompt, tools)
        return tools_hash, eff

    def _package_response(
        self,
        *,
        response,
        prompt: str,
        system_prompt: Optional[str],
        text: str,
        tool_calls_list: List[Dict[str, Any]],
        parsed: Optional[BaseModel] = None,
    ) -> LLMResponse:
        usage = getattr(response, "usage", None)
        sdk_completion = getattr(usage, "completion_tokens", None) if usage else None
        sdk_reasoning = getattr(usage, "reasoning_tokens", None) if usage else None

        if sdk_completion is not None:
            output_tokens = int(sdk_completion)
        else:
            output_tokens = int(len(text) / 3.5)

        thinking_tokens = int(sdk_reasoning) if sdk_reasoning is not None else 0
        prompt_tokens = int(len(prompt) / 3.5) + (int(len(system_prompt) / 3.5) if system_prompt else 0)
        cost = self._calculate_cost(prompt_tokens, output_tokens, thinking_tokens)
        citations = getattr(response, "citations", None)
        server_side_tool_usage = getattr(response, "server_side_tool_usage", None)

        return LLMResponse(
            text=text,
            thinking=None,
            prompt_tokens=prompt_tokens,
            output_tokens=output_tokens,
            thinking_tokens=thinking_tokens,
            cost=cost,
            model=self.model,
            metadata={
                "has_tool_calls": len(tool_calls_list) > 0,
                "citations": citations,
                "server_side_tool_usage": server_side_tool_usage,
                "structured": parsed is not None,
            },
            tool_calls=tool_calls_list,
            parsed=parsed,
        )

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4000,
        temperature: float = 0.7,
        tools: Optional[List[Dict]] = None,
        reasoning_effort: Optional[str] = None,
        force_reset: bool = False,
        _retry_reasoning: bool = True,
        **kwargs
    ) -> LLMResponse:
        """generate text using xai grok. this is a single-shot generation (no tool execution loop). for agen..."""
#        # thread-safe chat operations
        with self._instance_lock:
#            # configure reasoning effort for grok reasoning models (low/high)
            self._prepare_session(
                system_prompt=system_prompt,
                tools=tools,
                reasoning_effort=reasoning_effort,
                force_reset=force_reset,
                _retry_reasoning=_retry_reasoning,
            )

#            # add user message
            self.chat.append(user(prompt))

#            # trim chat history to prevent memory bloat
            self._trim_chat_history()

#            # get response
            max_sleep = int(os.getenv("XAI_BACKOFF_MAX_SECONDS", "60"))
            backoff = 5
            for attempt in range(5):
                try:
                    response = self.chat.sample()
                    break
                except grpc.RpcError as exc:
#                    # retry once if reasoning effort rejected
                    if _retry_reasoning and "reasoningEffort" in str(exc) and self._reasoning_effort is not None:
                        print("[WARN] Grok model rejected reasoning_effort; retrying without it.")
                        self._reasoning_effort = None
                        self._applied_reasoning_effort = None
                        self.chat = None
                        return self.generate(
                            prompt=prompt,
                            system_prompt=system_prompt,
                            max_tokens=max_tokens,
                            temperature=temperature,
                            tools=tools,
                            reasoning_effort=None,
                            _retry_reasoning=False,
                            **kwargs,
                        )
                    if exc.code() == grpc.StatusCode.RESOURCE_EXHAUSTED and attempt < 4:
                        print(f"[WARN] xAI quota hit (attempt {attempt+1}); sleeping {backoff}s")
                        time.sleep(backoff)
                        backoff = min(backoff * 2, max_sleep)
                        continue
                    raise

            text = response.content if response.content else ""
            tool_calls_list = []

            if response.tool_calls:
                for tc in response.tool_calls:
#                    # debug: log tool calls
                    args_preview = (tc.function.arguments or "{}")[:100]
                    print(f"[DEBUG] xAI Response: Tool '{tc.function.name}' | Args: {args_preview}...")

                    tool_calls_list.append({
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments or "{}"
                        }
                    })

            return self._package_response(
                response=response,
                prompt=prompt,
                system_prompt=system_prompt,
                text=text,
                tool_calls_list=tool_calls_list,
            )

    def generate_structured(
        self,
        *,
        prompt: str,
        response_model: Type[BaseModel],
        system_prompt: Optional[str] = None,
        max_tokens: int = 4000,
        temperature: float = 0.7,
        tools: Optional[List[Dict]] = None,
        reasoning_effort: Optional[str] = None,
        force_reset: bool = False,
        _retry_reasoning: bool = True,
        **kwargs
    ) -> Tuple[LLMResponse, BaseModel]:
        self._prepare_session(
            system_prompt=system_prompt,
            tools=tools,
            reasoning_effort=reasoning_effort,
            force_reset=force_reset,
            _retry_reasoning=_retry_reasoning,
        )

        self.chat.append(user(prompt))

        try:
            response, parsed = self.chat.parse(response_model)
        except grpc.RpcError as exc:
            if _retry_reasoning and "reasoningEffort" in str(exc) and self._reasoning_effort is not None:
                print("[WARN] Grok model rejected reasoning_effort; retrying without it.")
                self._reasoning_effort = None
                self._applied_reasoning_effort = None
                self.chat = None
                return self.generate_structured(
                    prompt=prompt,
                    response_model=response_model,
                    system_prompt=system_prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    tools=tools,
                    reasoning_effort=None,
                    force_reset=force_reset,
                    _retry_reasoning=False,
                    **kwargs,
                )
            raise

        text = response.content if response.content else json.dumps(parsed.model_dump(), ensure_ascii=False)
        llm_response = self._package_response(
            response=response,
            prompt=prompt,
            system_prompt=system_prompt,
            text=text,
            tool_calls_list=[],
            parsed=parsed,
        )
        return llm_response, parsed

    def generate_with_tools(
        self,
        prompt: str,
        tools: List[Dict],
        tool_functions: Dict[str, callable],
        system_prompt: Optional[str] = None,
        max_tokens: int = 4000,
        temperature: float = 0.7,
        max_iterations: int = None,
        reasoning_effort: Optional[str] = None,
        _retry_reasoning: bool = True,
        **kwargs
    ) -> LLMResponse:
        """generate text with full agentic tool calling loop. this implements the pattern from your sample s..."""
#        # configure reasoning effort
        from config import config as _cfg
        registry_entry = _cfg.MODEL_REGISTRY.get(self.model, {})
        support = registry_entry.get("reasoning_support")
        default_effort = registry_entry.get("reasoning_default", {}).get("effort")
        env_effort = os.getenv("GROK_EFFORT")
        if _retry_reasoning:
            eff = reasoning_effort or (env_effort if env_effort in ("low", "high") else None) or default_effort
        else:
            eff = reasoning_effort
        if support == "effort" and eff in ("low", "high"):
            self._reasoning_effort = eff
        else:
            self._reasoning_effort = None

#        # respect env override for tool loop to avoid hangs
        if max_iterations is None:
            try:
                max_iterations = int(os.getenv("XAI_TOOLS_MAX_ITERATIONS", "20"))
            except ValueError:
                max_iterations = 20

        self._reset_chat(system_prompt, tools)

#        # add user message
        self.chat.append(user(prompt))

#        # trim chat history to prevent memory bloat
        self._trim_chat_history()

        backoff = 5
        for attempt in range(5):
            try:
                response = self.chat.sample()
                break
            except grpc.RpcError as exc:
                if _retry_reasoning and "reasoningEffort" in str(exc) and self._reasoning_effort is not None:
                    print("[WARN] Grok model rejected reasoning_effort; retrying without it.")
                    self._reasoning_effort = None
                    self._applied_reasoning_effort = None
                    self.chat = None
                    return self.generate_with_tools(
                        prompt=prompt,
                        tools=tools,
                        tool_functions=tool_functions,
                        system_prompt=system_prompt,
                        max_tokens=max_tokens,
                        temperature=temperature,
                        max_iterations=max_iterations,
                        reasoning_effort=None,
                        _retry_reasoning=False,
                        **kwargs,
                    )
                if exc.code() == grpc.StatusCode.RESOURCE_EXHAUSTED and attempt < 4:
                    sleep_for = min(backoff, int(os.getenv("XAI_BACKOFF_MAX_SECONDS", "60")))
                    print(f"[WARN] xAI quota hit (tools, attempt {attempt+1}); sleeping {sleep_for}s")
                    time.sleep(sleep_for)
                    backoff = min(backoff * 2, sleep_for * 2 or 5)
                    continue
                raise

#        # track metrics
        total_prompt_tokens = int(len(prompt) / 3.5) + (int(len(system_prompt) / 3.5) if system_prompt else 0)
        total_output_tokens = int(len(response.content) / 3.5) if response.content else 0
        total_tool_calls = 0
        final_text = response.content if response.content else ""
        iteration = 0

#        # tool calling loop
        while response.tool_calls and iteration < max_iterations:
            iteration += 1

#            # append response with tool calls
            self.chat.append(response)

#            # execute each tool call
            for tc in response.tool_calls:
                total_tool_calls += 1
                func_name = tc.function.name

#                # get function
                if func_name not in tool_functions:
                    result = f"Error: Unknown function '{func_name}'"
                else:
                    try:
#                        # parse arguments
                        args = json.loads(tc.function.arguments or "{}")

#                        # call function
                        result = tool_functions[func_name](**args)

#                        # convert result to string if needed
                        if not isinstance(result, str):
                            result = str(result)
                    except Exception as e:
                        result = f"Error calling {func_name}: {str(e)}"

#                # append tool result
                self.chat.append(tool_result(result))

#                # track tokens from tool result
                total_prompt_tokens += int(len(result) / 3.5)

#            # get next response with retry/backoff on quota
            backoff = 5
            for attempt in range(5):
                try:
                    response = self.chat.sample()
                    break
                except grpc.RpcError as exc:
                    if _retry_reasoning and "reasoningEffort" in str(exc) and self._reasoning_effort is not None:
                        print("[WARN] Grok model rejected reasoning_effort mid-session; retrying without it.")
                        self._reasoning_effort = None
                        self._applied_reasoning_effort = None
                        self.chat = None
                        return self.generate_with_tools(
                            prompt=prompt,
                            tools=tools,
                            tool_functions=tool_functions,
                            system_prompt=system_prompt,
                            max_tokens=max_tokens,
                            temperature=temperature,
                            max_iterations=max_iterations,
                            reasoning_effort=None,
                            _retry_reasoning=False,
                            **kwargs,
                        )
                    if exc.code() == grpc.StatusCode.RESOURCE_EXHAUSTED and attempt < 4:
                        sleep_for = min(backoff, int(os.getenv("XAI_BACKOFF_MAX_SECONDS", "60")))
                        print(f"[WARN] xAI quota hit (tools loop, attempt {attempt+1}); sleeping {sleep_for}s")
                        time.sleep(sleep_for)
                        backoff = min(backoff * 2, sleep_for * 2 or 5)
                        continue
                    raise

#            # update metrics
            if response.content:
                total_output_tokens += int(len(response.content) / 3.5)
                final_text = response.content

#        # calculate final cost
        cost = self._calculate_cost(total_prompt_tokens, total_output_tokens, thinking_tokens=0)

        citations = getattr(response, "citations", None)
        server_side_tool_usage = getattr(response, "server_side_tool_usage", None)

        return LLMResponse(
            text=final_text,
            thinking=None,
            prompt_tokens=total_prompt_tokens,
            output_tokens=total_output_tokens,
            thinking_tokens=0,
            cost=cost,
            model=self.model,
            metadata={
                "iterations": iteration,
                "total_tool_calls": total_tool_calls,
                "max_iterations_reached": iteration >= max_iterations,
                "citations": citations,
                "server_side_tool_usage": server_side_tool_usage,
            },
            tool_calls=[]  # final response has no pending tool calls
        )

    def generate_with_tools_multi_turn(
        self,
        messages: List[Dict[str, str]],
        tools: List[Dict],
        system_prompt: Optional[str] = None,
        tool_functions: Optional[Dict[str, callable]] = None,  # accept for compatibility
        thinking_budget: Optional[int] = None,  # not used by xai (server-side reasoning)
        enable_interleaved_thinking: bool = False,  # not used by xai
        max_tokens: int = 4000,
        temperature: float = 0.7,
        reasoning_effort: Optional[str] = None,
        _retry_reasoning: bool = True,
        **kwargs
    ) -> LLMResponse:
        """generate a single response with tool calls in a multi-turn conversation. unlike generate_with_too..."""
        from config import config as _cfg
        registry_entry = _cfg.MODEL_REGISTRY.get(self.model, {})
        support = registry_entry.get("reasoning_support")
        default_effort = registry_entry.get("reasoning_default", {}).get("effort")
        env_effort = os.getenv("GROK_EFFORT")
        if _retry_reasoning:
            eff = reasoning_effort or (env_effort if env_effort in ("low", "high") else None) or default_effort
        else:
            eff = reasoning_effort
        if support == "effort" and eff in ("low", "high"):
            self._reasoning_effort = eff
        else:
            self._reasoning_effort = None

        tools_hash = self._compute_tools_hash(tools)

        if (
            self.chat is None
            or system_prompt != self._system_prompt
            or tools_hash != self._tools_hash
            or self._applied_reasoning_effort != self._reasoning_effort
        ):
            self._reset_chat(system_prompt, tools)

        new_messages = messages[self._messages_processed:] if messages else []

        for msg in new_messages:
            role = msg.get("role")
            content = msg.get("content", "")

            if role == "user":
                if isinstance(content, list):
                    text_blocks: List[str] = []
                    for block in content:
                        if isinstance(block, dict):
                            if block.get("type") == "tool_result":
                                result_content = block.get("content", "Success")
                                self.chat.append(tool_result(result_content))
                            elif block.get("type") == "text":
                                text_value = block.get("text", "")
                                if text_value:
                                    text_blocks.append(text_value)
                    if text_blocks:
                        combined_text = "\n".join(text_blocks)
                        self.chat.append(user(combined_text))
                else:
                    self.chat.append(user(content))

#            # skip assistant messages - they're already in chat from sample()
#            # (sample() returns the response which is already part of chat state)

#        # update message counter
        self._messages_processed = len(messages) if messages else 0

#        # trim chat history to prevent memory bloat
        self._trim_chat_history()

#        # get response (single shot, no tool execution)
        print(f"[DEBUG xAI] Calling sample() with {len(messages)} messages...", flush=True)
        try:
            response = self.chat.sample()
        except grpc.RpcError as exc:
            if _retry_reasoning and "reasoningEffort" in str(exc) and self._reasoning_effort is not None:
                print("[WARN] Grok model rejected reasoning_effort; retrying without it.")
                self._reasoning_effort = None
                self._applied_reasoning_effort = None
                self.chat = None
                return self.generate_with_tools_multi_turn(
                    messages=messages,
                    tools=tools,
                    system_prompt=system_prompt,
                    tool_functions=tool_functions,
                    thinking_budget=thinking_budget,
                    enable_interleaved_thinking=enable_interleaved_thinking,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    reasoning_effort=None,
                    _retry_reasoning=False,
                    **kwargs,
                )
            raise
        print(f"[DEBUG xAI] sample() returned successfully", flush=True)

# if response has tool_calls, append it to chat history
        if response.tool_calls:
            self.chat.append(response)

        text = response.content if response.content else ""
        tool_calls_list = []

        if response.tool_calls:
            for tc in response.tool_calls:
#                # debug: log tool calls
                args_preview = (tc.function.arguments or "{}")[:100]
                print(f"[DEBUG] xAI Response: Tool '{tc.function.name}' | Args: {args_preview}...")

                tool_calls_list.append({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments or "{}"
                    }
                })

#        # track metrics
        total_prompt_tokens = sum(int(len(msg.get("content", "")) / 3.5) for msg in messages)
        total_prompt_tokens += int(len(system_prompt) / 3.5) if system_prompt else 0
        total_output_tokens = int(len(text) / 3.5)

#        # calculate cost
        cost = self._calculate_cost(total_prompt_tokens, total_output_tokens, thinking_tokens=0)

        citations = getattr(response, "citations", None)
        server_side_tool_usage = getattr(response, "server_side_tool_usage", None)

        return LLMResponse(
            text=text,
            thinking=None,  # grok handles reasoning server-side
            prompt_tokens=total_prompt_tokens,
            output_tokens=total_output_tokens,
            thinking_tokens=0,  # server-side reasoning not exposed
            cost=cost,
            model=self.model,
            metadata={
                "has_tool_calls": len(tool_calls_list) > 0,
                "citations": citations,
                "server_side_tool_usage": server_side_tool_usage,
            },
            tool_calls=tool_calls_list  # return tool calls for specialist to execute
        )

    def is_available(self) -> bool:
        """check if xai backend is available. returns: true if xai_api_key is set, false otherwise"""
        return os.getenv("XAI_API_KEY") is not None
