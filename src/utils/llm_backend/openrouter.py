from typing import Dict, Any, Optional, List
from pathlib import Path
from copy import deepcopy
import json
import sys
import time
import random

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config import config
from utils.llm_backend.base import LLMBackend, LLMResponse


class OpenRouterBackend(LLMBackend):
    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None,
                 base_url: Optional[str] = None, provider: str = "openrouter"):
        if model is None:
            model = config.MODEL_GLM_4_6
        super().__init__(model)

        if api_key is None:
            if config.OPENROUTER_API_KEY:
                api_key, provider = config.OPENROUTER_API_KEY, "openrouter"
            elif config.COMETAPI_API_KEY:
                api_key, provider = config.COMETAPI_API_KEY, "cometapi"
            elif config.NOVITA_API_KEY:
                api_key, provider = config.NOVITA_API_KEY, "novita"
            else:
                raise ValueError("No GLM API key found. Set OPENROUTER_API_KEY, COMETAPI_API_KEY, or NOVITA_API_KEY")

        if base_url is None:
            base_urls = {
                "openrouter": "https://openrouter.ai/api/v1",
                "cometapi": "https://api.cometapi.com/v1",
                "novita": "https://api.novita.ai/v3"
            }
            base_url = base_urls.get(provider)
            if not base_url:
                raise ValueError(f"Unknown provider: {provider}")

        self.provider = provider

        try:
            from openai import OpenAI
            import httpx
            timeout = httpx.Timeout(300.0, connect=30.0, read=300.0)
            self._http_client = httpx.Client(timeout=timeout)
            self.client = OpenAI(api_key=api_key, base_url=base_url, http_client=self._http_client)
        except ImportError:
            raise ImportError("openai package required for GLMBackend. Install with: pip install openai")

        if config.DEBUG_LLM_CALLS:
            print(f"[DEBUG OpenRouter] initialized provider={provider}, model={self.model}")

    def __del__(self):
        try:
            if hasattr(self, '_http_client') and self._http_client:
                self._http_client.close()
        except Exception:
            pass

    def is_available(self) -> bool:
        try:
            return self.client is not None
        except Exception:
            return False

    def _is_retryable_error(self, error: Exception) -> bool:
        error_str = str(error).lower()
        retryable_patterns = [
            "connection", "connect", "network", "socket", "reset by peer", "broken pipe", "eof",
            "ssl", "tls", "handshake", "closed", "timeout", "timed out", "deadline exceeded",
            "rate limit", "rate_limit", "too many requests", "quota exceeded", "throttl",
            "429", "500", "502", "503", "504", "520", "521", "522", "523", "524",
            "service unavailable", "bad gateway", "gateway timeout", "internal server error",
            "server error", "temporarily unavailable", "overloaded", "capacity", "upstream",
            "provider", "model unavailable",
        ]
        return any(pattern in error_str for pattern in retryable_patterns)

    def _retry_with_backoff(self, func, max_retries: int = 8, base_delay: float = 3.0):
        last_exception = None
        start_time = time.time()
        MAX_TOTAL_TIME = 300

        for attempt in range(max_retries + 1):
            if time.time() - start_time > MAX_TOTAL_TIME:
                raise RuntimeError(f"Retry timeout exceeded ({MAX_TOTAL_TIME}s elapsed)")
            try:
                return func()
            except Exception as e:
                last_exception = e
                if not self._is_retryable_error(e):
                    raise
                if attempt >= max_retries:
                    if config.DEBUG_LLM_CALLS:
                        print(f"[ERROR OpenRouter] All {max_retries + 1} attempts failed: {e}")
                    raise
                delay = min(120.0, base_delay * (2 ** attempt)) + random.uniform(0, 2)
                if config.DEBUG_LLM_CALLS:
                    print(f"[RETRY OpenRouter] Attempt {attempt + 1}/{max_retries + 1} failed: {e}")
                    print(f"[RETRY OpenRouter] Retrying in {delay:.1f}s...")
                time.sleep(delay)
        raise last_exception

    def _get_reasoning_params(self, effort_override: Optional[str] = None) -> Dict[str, Any]:
        model_info = config.MODEL_REGISTRY.get(self.model, {})
        reasoning_support = model_info.get("reasoning_support")
        if not reasoning_support:
            return {}

        reasoning_params = {}
        if reasoning_support == "openrouter_unified":
            defaults = model_info.get("reasoning_default", {})
            enabled = defaults.get("enabled", True)
            effort = effort_override or config.REASONING_EFFORT or defaults.get("effort", "medium")
            reasoning_config = {"enabled": enabled, "effort": effort}
            if config.REASONING_EXCLUDE:
                reasoning_config["exclude"] = True
            reasoning_params["reasoning"] = reasoning_config
            if config.DEBUG_LLM_CALLS:
                print(f"[DEBUG OpenRouter] {self.model}: reasoning enabled={enabled}, effort={effort}")
        elif reasoning_support == "always_on":
            if config.DEBUG_LLM_CALLS:
                print(f"[DEBUG OpenRouter] {self.model}: reasoning always on")
        elif reasoning_support == "effort":
            effort = effort_override or config.REASONING_EFFORT or model_info.get("reasoning_default", {}).get("effort", "low")
            if "grok-3-mini" in self.model.lower():
                effort = "high" if effort in ("high", "medium") else "low"
            reasoning_config = {"effort": effort}
            if config.REASONING_EXCLUDE:
                reasoning_config["exclude"] = True
            reasoning_params["reasoning"] = reasoning_config
            if config.DEBUG_LLM_CALLS:
                print(f"[DEBUG OpenRouter] Reasoning: effort={effort}")
        elif reasoning_support == "native":
            reasoning_params["thinking"] = {"type": config.GLM_THINKING_TYPE}
            if config.DEBUG_LLM_CALLS:
                print(f"[DEBUG GLM] thinking enabled")
        elif reasoning_support == "max_tokens":
            reasoning_params["reasoning"] = {"max_tokens": getattr(config, "REASONING_MAX_TOKENS", 2000)}
            if config.DEBUG_LLM_CALLS:
                print(f"[DEBUG OpenRouter] reasoning max_tokens={reasoning_params['reasoning']['max_tokens']}")
        return reasoning_params

    def _extract_reasoning_info(self, message: Any) -> Dict[str, Any]:
        result = {"thinking": None, "reasoning_details": None, "thinking_tokens": 0}
        if hasattr(message, "reasoning") and message.reasoning:
            result["thinking"] = message.reasoning
            if config.DEBUG_LLM_CALLS:
                print(f"[DEBUG OpenRouter] extracted reasoning: {len(message.reasoning)} chars")
        if hasattr(message, "reasoning_details") and message.reasoning_details:
            result["reasoning_details"] = message.reasoning_details
            thinking_parts = []
            for detail in message.reasoning_details:
                dtype = detail.get("type", "")
                if dtype == "reasoning.text":
                    thinking_parts.append(detail.get("text", ""))
                elif dtype == "reasoning.summary":
                    thinking_parts.append(detail.get("summary", ""))
            if thinking_parts:
                result["thinking"] = "\n\n".join(thinking_parts)
            if config.DEBUG_LLM_CALLS:
                print(f"[DEBUG OpenRouter] extracted {len(message.reasoning_details)} reasoning blocks")
        return result

    def _normalize_tools_for_openai(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized = []
        for tool in tools or []:
            if not tool:
                continue
            if tool.get("type") == "function" and "function" in tool:
                fn_def = deepcopy(tool["function"])
                parameters = fn_def.pop("parameters", None) or fn_def.pop("input_schema", None)
                if not isinstance(parameters, dict):
                    parameters = {"type": "object", "properties": {}}
                normalized.append({"type": "function", "function": {
                    "name": fn_def.get("name"), "description": fn_def.get("description", ""),
                    "parameters": parameters}})
                continue
            name = tool.get("name")
            if not name:
                if config.DEBUG_LLM_CALLS:
                    print(f"[DEBUG GLM] Skipping tool without name: {tool}")
                continue
            parameters = tool.get("parameters") or tool.get("input_schema")
            if not isinstance(parameters, dict):
                parameters = {"type": "object", "properties": {}}
            normalized.append({"type": "function", "function": {
                "name": name, "description": tool.get("description", ""), "parameters": parameters}})
        return normalized

    def _convert_messages_for_openai(self, messages: List[Dict[str, Any]],
                                      system_prompt: Optional[str] = None) -> List[Dict[str, Any]]:
        def _clean_str(v):
            return v if isinstance(v, str) else json.dumps(v) if not isinstance(v, str) else str(v)

        converted = []
        if system_prompt:
            converted.append({"role": "system", "content": system_prompt})

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            if isinstance(content, str):
                converted.append({"role": role if role in {"user", "assistant", "system", "tool"} else "user", "content": content})
                continue

            if isinstance(content, list):
                if content and all(b.get("type") == "tool_result" for b in content):
                    for b in content:
                        converted.append({"role": "tool", "tool_call_id": b.get("tool_use_id"),
                                        "name": b.get("name"), "content": _clean_str(b.get("content", ""))})
                    continue

                text_parts, tool_calls = [], []
                for block in content:
                    btype = block.get("type")
                    if btype == "text" and block.get("text"):
                        text_parts.append(block["text"])
                    elif btype == "thinking" and block.get("thinking"):
                        text_parts.append(f"[thinking]\n{block['thinking']}\n[/thinking]")
                    elif btype == "tool_use":
                        args = block.get("input")
                        if not isinstance(args, str):
                            try:
                                args = json.dumps(args)
                            except TypeError:
                                args = json.dumps({"raw": str(args)})
                        tool_calls.append({"id": block.get("id"), "type": "function",
                                         "function": {"name": block.get("name"), "arguments": args or "{}"}})
                    elif btype == "tool_result":
                        converted.append({"role": "tool", "tool_call_id": block.get("tool_use_id"),
                                        "name": block.get("name"), "content": _clean_str(block.get("content", ""))})
                    else:
                        text_parts.append(_clean_str(block))

                norm_role = role if role in {"user", "assistant", "system"} else "assistant"
                msg_payload = {"role": norm_role}
                combined = "\n".join(p for p in text_parts if p).strip()
                msg_payload["content"] = combined if combined else (None if tool_calls else "")
                if tool_calls:
                    msg_payload["tool_calls"] = tool_calls
                if msg_payload.get("content") is not None or tool_calls:
                    converted.append(msg_payload)
                continue

            converted.append({"role": role if role in {"user", "assistant", "system", "tool"} else "user",
                            "content": _clean_str(content)})
        return converted

    def _calculate_cost(self, usage, reasoning_tokens_from_msg=0):
        if not usage:
            if config.DEBUG_LLM_CALLS:
                print("[WARNING OpenRouter] response missing usage info")
            return 0, 0, 0, 0.0

        prompt_tokens = getattr(usage, 'prompt_tokens', 0)
        completion_tokens = getattr(usage, 'completion_tokens', 0)
        reasoning_tokens = getattr(usage, 'reasoning_tokens', 0) or reasoning_tokens_from_msg

        pricing = config.get_model_pricing(self.model)
        input_cost = (prompt_tokens / 1_000_000) * pricing["input"]
        regular_output_tokens = max(0, completion_tokens - reasoning_tokens)
        output_cost = (regular_output_tokens / 1_000_000) * pricing["output"]
        reasoning_price = pricing.get("reasoning_output", pricing["output"])
        reasoning_cost = (reasoning_tokens / 1_000_000) * reasoning_price
        return prompt_tokens, completion_tokens, reasoning_tokens, input_cost + output_cost + reasoning_cost

    def generate(self, prompt: str, system_prompt: Optional[str] = None, max_tokens: int = 4000,
                 temperature: float = 0.7, enable_thinking: bool = True, **kwargs) -> LLMResponse:
        max_tokens = max_tokens or config.MAX_OUTPUT_TOKENS
        converted_messages = self._convert_messages_for_openai([{"role": "user", "content": prompt}], system_prompt)

        extra_body = {}
        if enable_thinking and config.MODEL_REGISTRY.get(self.model, {}).get("reasoning_support"):
            extra_body.update(self._get_reasoning_params())

        request_params = {"model": self.model, "messages": converted_messages,
                         "max_tokens": max_tokens, "temperature": temperature}
        if extra_body:
            request_params["extra_body"] = extra_body

        def _make_request():
            response = self.client.chat.completions.create(**request_params, **kwargs)
            if not response.choices:
                raise ValueError("OpenRouter API returned empty choices array")
            return response

        try:
            response = self._retry_with_backoff(_make_request)
            message = response.choices[0].message
            reasoning_info = self._extract_reasoning_info(message)
            prompt_tokens, completion_tokens, reasoning_tokens, cost = self._calculate_cost(
                response.usage, reasoning_info["thinking_tokens"])

            return LLMResponse(text=message.content or "", thinking=reasoning_info["thinking"],
                             reasoning_details=reasoning_info["reasoning_details"],
                             prompt_tokens=prompt_tokens, output_tokens=completion_tokens,
                             thinking_tokens=reasoning_tokens, cost=cost, model=self.model,
                             metadata={"provider": self.provider, "stop_reason": response.choices[0].finish_reason,
                                     "reasoning_enabled": bool(extra_body.get("reasoning"))})
        except Exception as e:
            if config.DEBUG_LLM_CALLS:
                print(f"[ERROR GLM] Failed to generate: {e}")
            raise

    def _parse_tool_calls(self, response):
        tool_calls = []
        for choice in response.choices:
            if hasattr(choice.message, 'tool_calls') and choice.message.tool_calls:
                for tc in choice.message.tool_calls:
                    raw_args = getattr(tc.function, "arguments", None)
                    parsed = raw_args
                    if isinstance(raw_args, str):
                        try:
                            parsed = json.loads(raw_args)
                        except json.JSONDecodeError as e:
                            if config.DEBUG_LLM_CALLS:
                                print(f"[WARNING OpenRouter] failed to parse tool args: {e}")
                            parsed = {"raw": raw_args, "parse_error": str(e)}
                    tool_calls.append({"id": tc.id, "name": tc.function.name, "input": parsed})
        return tool_calls

    def generate_with_tools(self, prompt: str, tools: List[Dict[str, Any]], system_prompt: Optional[str] = None,
                           max_tokens: Optional[int] = None, temperature: Optional[float] = None,
                           enable_thinking: bool = True, **kwargs) -> LLMResponse:
        max_tokens = max_tokens or config.MAX_OUTPUT_TOKENS
        temperature = temperature or config.NORMAL_TEMPERATURE
        converted_messages = self._convert_messages_for_openai([{"role": "user", "content": prompt}], system_prompt)
        openai_tools = self._normalize_tools_for_openai(tools)

        if config.DEBUG_LLM_CALLS:
            print(f"[DEBUG GLM] calling with {len(openai_tools)} tools (thinking: {enable_thinking})")

        extra_body = {}
        if enable_thinking and config.MODEL_REGISTRY.get(self.model, {}).get("reasoning_support"):
            extra_body.update(self._get_reasoning_params())

        request_params = {"model": self.model, "messages": converted_messages,
                         "max_tokens": max_tokens, "temperature": temperature}
        if openai_tools:
            request_params.update({"tools": openai_tools, "tool_choice": "auto"})
        if extra_body:
            request_params["extra_body"] = extra_body

        if config.DEBUG_LLM_CALLS:
            print(f"[DEBUG API REQUEST] model: {self.model}, max_tokens: {max_tokens}, "
                  f"extra_body: {extra_body}, tools: {len(openai_tools)}")

        def _make_request():
            response = self.client.chat.completions.create(**request_params, **kwargs)
            if not response.choices:
                raise ValueError("OpenRouter API returned empty choices array")
            return response

        try:
            response = self._retry_with_backoff(_make_request)
            reasoning_info = self._extract_reasoning_info(response.choices[0].message)
            prompt_tokens, completion_tokens, reasoning_tokens, cost = self._calculate_cost(
                response.usage, reasoning_info["thinking_tokens"])

            if config.DEBUG_LLM_CALLS:
                print(f"[DEBUG API RESPONSE] prompt_tokens: {prompt_tokens}, completion_tokens: {completion_tokens}, "
                      f"stop_reason: {response.choices[0].finish_reason}")

            text = "".join(c.message.content or "" for c in response.choices)
            tool_calls = self._parse_tool_calls(response)

            if config.DEBUG_LLM_CALLS and tool_calls:
                print(f"[DEBUG GLM] extracted {len(tool_calls)} tool calls")

            return LLMResponse(text=text, thinking=reasoning_info["thinking"],
                             reasoning_details=reasoning_info["reasoning_details"],
                             prompt_tokens=prompt_tokens, output_tokens=completion_tokens,
                             thinking_tokens=reasoning_tokens, cost=cost, model=self.model,
                             tool_calls=tool_calls,
                             metadata={"provider": self.provider, "stop_reason": response.choices[0].finish_reason,
                                     "reasoning_enabled": bool(extra_body.get("reasoning"))})
        except Exception as e:
            if config.DEBUG_LLM_CALLS:
                print(f"[ERROR GLM] Failed to generate with tools: {e}")
            raise

    def _convert_multi_turn_messages(self, msgs):
        oa = []
        for m in msgs:
            role, content = m.get("role"), m.get("content")
            if isinstance(content, str):
                if role in ("system", "user", "assistant"):
                    oa.append({"role": role, "content": content})
            elif isinstance(content, list):
                if role == "assistant":
                    texts, tcalls = [], []
                    for b in content:
                        bt = b.get("type")
                        if bt == "text":
                            texts.append(b.get("text", ""))
                        elif bt == "thinking":
                            continue
                        elif bt == "tool_use":
                            args = b.get("input", {})
                            try:
                                arg_str = args if isinstance(args, str) else json.dumps(args)
                            except Exception:
                                arg_str = json.dumps({"raw": str(args)})
                            tcalls.append({"id": b.get("id") or f"toolu_{len(tcalls)+1}", "type": "function",
                                         "function": {"name": b.get("name"), "arguments": arg_str}})
                    amsg = {"role": "assistant"}
                    if texts:
                        amsg["content"] = "\n".join(t for t in texts if t).strip()
                    if tcalls:
                        amsg["tool_calls"] = tcalls
                    if amsg.get("content") or tcalls:
                        oa.append(amsg)
                elif role == "user":
                    utexts = []
                    for b in content:
                        if b.get("type") == "tool_result":
                            oa.append({"role": "tool", "tool_call_id": b.get("tool_use_id") or b.get("id"),
                                     "name": b.get("name"), "content": str(b.get("content", ""))})
                        elif b.get("type") == "text":
                            utexts.append(b.get("text", ""))
                    if utexts:
                        oa.append({"role": "user", "content": "\n".join(utexts)})
                else:
                    oa.append({"role": role or "user", "content": json.dumps(content)})
            else:
                if content is not None:
                    oa.append({"role": role or "user", "content": str(content)})
        return oa

    def _parse_xml_tool_calls(self, text):
        if not text or '<xai:function_call' not in text:
            return [], text
        import re
        xml_pattern = r'<xai:function_call name="([^"]+)">(.*?)</xai:function_call>'
        matches = re.findall(xml_pattern, text, re.DOTALL)
        if not matches:
            return [], text
        tool_calls = []
        for i, (fname, params_xml) in enumerate(matches):
            params = {}
            param_matches = re.findall(r'<parameter name="([^"]+)">([^<]*)</parameter>', params_xml)
            for pname, pval in param_matches:
                params[pname] = pval.strip()
            tool_calls.append({"id": f"call_{i}_{fname[:8]}", "name": fname, "input": params})
        if config.DEBUG_LLM_CALLS:
            print(f"  - parsed {len(tool_calls)} tool calls from grok xml")
        return tool_calls, ""

    def generate_with_tools_multi_turn(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]],
                                      max_tokens: Optional[int] = None, temperature: Optional[float] = None,
                                      system_prompt: Optional[str] = None, enable_thinking: bool = True,
                                      **kwargs) -> LLMResponse:
        max_tokens = max_tokens or config.MAX_OUTPUT_TOKENS
        temperature = temperature or config.NORMAL_TEMPERATURE
        msgs = messages.copy() if messages else []
        if system_prompt and msgs and msgs[0].get("role") != "system":
            msgs.insert(0, {"role": "system", "content": system_prompt})

        messages_openai = self._convert_multi_turn_messages(msgs)
        openai_tools = self._normalize_tools_for_openai(tools)

        extra_body = {}
        if enable_thinking and config.MODEL_REGISTRY.get(self.model, {}).get("reasoning_support"):
            extra_body.update(self._get_reasoning_params())

        request_params = {"model": self.model, "messages": messages_openai,
                         "max_tokens": max_tokens, "temperature": temperature}
        if openai_tools:
            request_params.update({"tools": openai_tools, "tool_choice": "auto"})
        if extra_body:
            request_params["extra_body"] = extra_body

        if config.DEBUG_LLM_CALLS:
            eb = request_params.get('extra_body', {})
            print(f"[DEBUG GLM Multi-Turn] model: {self.model}, max_tokens: {max_tokens}, "
                  f"messages: {len(messages_openai)} turns, tools: {len(openai_tools)}, extra_body: {eb}")
            if "thinking" in eb:
                print(f"  - thinking enabled (glm): {eb['thinking']}")
            elif "reasoning" in eb:
                print(f"  - reasoning enabled (openrouter): {eb['reasoning']}")

        def _make_request():
            response = self.client.chat.completions.create(**request_params, **kwargs)
            if not response.choices:
                raise ValueError("OpenRouter API returned empty choices array")
            return response

        try:
            response = self._retry_with_backoff(_make_request)
            text = "".join(c.message.content or "" for c in response.choices)
            tool_calls = self._parse_tool_calls(response)
            xml_calls, text = self._parse_xml_tool_calls(text)
            if xml_calls:
                tool_calls.extend(xml_calls)

            reasoning_info = self._extract_reasoning_info(response.choices[0].message)
            prompt_tokens, completion_tokens, reasoning_tokens, cost = self._calculate_cost(
                response.usage, reasoning_info["thinking_tokens"])

            if config.DEBUG_LLM_CALLS or completion_tokens < 100:
                print(f"[DEBUG GLM Multi-Turn] api response: input_tokens={prompt_tokens}, "
                      f"output_tokens={completion_tokens}, tool_calls={len(tool_calls)}, "
                      f"text_length={len(text)}, reasoning_tokens={reasoning_tokens}")
                if completion_tokens < 100:
                    print(f"  - warning: low output tokens, text: {text[:200] if text else 'EMPTY'}, "
                          f"tool_calls: {tool_calls[:2] if tool_calls else 'NONE'}")
                if completion_tokens == 343:
                    print(f"  - warning: exactly 343 tokens (suspicious)")

            return LLMResponse(text=text, thinking=reasoning_info["thinking"],
                             reasoning_details=reasoning_info["reasoning_details"],
                             prompt_tokens=prompt_tokens, output_tokens=completion_tokens,
                             thinking_tokens=reasoning_tokens, cost=cost, model=self.model,
                             tool_calls=tool_calls,
                             metadata={"provider": self.provider, "stop_reason": response.choices[0].finish_reason,
                                     "reasoning_enabled": bool(extra_body.get("reasoning"))})
        except Exception as e:
            if config.DEBUG_LLM_CALLS:
                print(f"[ERROR GLM] Failed in multi-turn: {e}")
            raise
