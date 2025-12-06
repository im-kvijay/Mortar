"""s for LLM backend retry logic and error handling."""

import unittest
from unittest.mock import patch, MagicMock, Mock, call
import time
import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

class MockOpenAIResponse:
    """Mock OpenAI SDK response for OpenRouter backend."""
    def __init__(self, content="test response", tool_calls=None, usage=None):
        self.choices = [
            type('Choice', (), {
                'message': type('Message', (), {
                    'content': content,
                    'tool_calls': tool_calls or [],
                    'reasoning': None,
                    'reasoning_details': None
                })(),
                'finish_reason': 'stop'
            })()
        ]
        if usage is None:
            usage = type('Usage', (), {
                'prompt_tokens': 100,
                'completion_tokens': 50,
                'reasoning_tokens': 0
            })()
        self.usage = usage

class TestExponentialBackoff(unittest.TestCase):
    """Test exponential backoff behavior."""

    @patch('time.sleep')
    def test_backoff_increases_exponentially(self, mock_sleep):
        # import here to avoid module-level issues
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI') as mock_openai_class:
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")
            mock_client = MagicMock()
            backend.client = mock_client

            call_count = [0]
            def side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] < 4:
                    raise Exception("Connection reset by peer")
                return MockOpenAIResponse()

            mock_client.chat.completions.create.side_effect = side_effect

            # generate should succeed after retries
            response = backend.generate("test prompt")
            self.assertEqual(response.text, "test response")
            # base delay is 3.0s, so delays should be ~3s, ~6s, ~12s
            self.assertEqual(len(mock_sleep.call_args_list), 3)
            delays = [call[0][0] for call in mock_sleep.call_args_list]
            self.assertGreater(delays[1], delays[0])
            self.assertGreater(delays[2], delays[1])
            self.assertGreater(delays[0], 3.0)
            self.assertLess(delays[0], 5.0)

    @patch('time.sleep')
    def test_backoff_respects_max_delay(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            # raise errors for many retries to test max delay cap
            call_count = [0]
            def side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] < 7:  # fail 6 times
                    raise Exception("timeout")
                return MockOpenAIResponse()

            mock_client.chat.completions.create.side_effect = side_effect

            response = backend.generate("test prompt")
            self.assertEqual(response.text, "test response")
            delays = [call[0][0] for call in mock_sleep.call_args_list]
            for delay in delays:
                self.assertLessEqual(delay, 122.0)

    @patch('time.sleep')
    def test_jitter_applied(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            call_count = [0]
            def side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] < 3:
                    raise Exception("connection timeout")
                return MockOpenAIResponse()

            mock_client.chat.completions.create.side_effect = side_effect

            backend.generate("test prompt")

            # jitter is random.uniform(0, 2), so delays should vary
            delays = [call[0][0] for call in mock_sleep.call_args_list]

            # first delay: base_delay (3.0) + jitter (0-2) = 3.0 to 5.0
            self.assertGreaterEqual(delays[0], 3.0)
            self.assertLessEqual(delays[0], 5.0)

class TestRetryLogic(unittest.TestCase):
    """Test retry behavior on failures."""

    @patch('time.sleep')
    def test_retry_on_rate_limit(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            call_count = [0]
            def side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] < 3:
                    raise Exception("429 rate limit exceeded")
                return MockOpenAIResponse()

            mock_client.chat.completions.create.side_effect = side_effect

            response = backend.generate("test prompt")
            self.assertEqual(response.text, "test response")
            self.assertEqual(call_count[0], 3)
            self.assertEqual(len(mock_sleep.call_args_list), 2)

    @patch('time.sleep')
    def test_retry_on_server_error(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            call_count = [0]
            def side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise Exception("502 bad gateway")
                elif call_count[0] == 2:
                    raise Exception("503 service unavailable")
                return MockOpenAIResponse()

            mock_client.chat.completions.create.side_effect = side_effect

            response = backend.generate("test prompt")
            self.assertEqual(response.text, "test response")
            self.assertEqual(call_count[0], 3)
            self.assertEqual(len(mock_sleep.call_args_list), 2)

    @patch('time.sleep')
    def test_no_retry_on_client_error(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            # 400 Bad Request should NOT retry
            mock_client.chat.completions.create.side_effect = Exception("400 bad request")

            with self.assertRaises(Exception) as context:
                backend.generate("test prompt")

            self.assertIn("400", str(context.exception))
            self.assertEqual(len(mock_sleep.call_args_list), 0)

    @patch('time.sleep')
    def test_max_retries_exceeded(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            # fail all attempts
            mock_client.chat.completions.create.side_effect = Exception("timeout")

            with self.assertRaises(Exception) as context:
                backend.generate("test prompt")

            self.assertIn("timeout", str(context.exception))
            # max retries is 8, so we should have 8 sleep calls (attempts 0-7 failed, attempt 8 failed)
            self.assertEqual(len(mock_sleep.call_args_list), 8)

    @patch('time.sleep')
    def test_retry_count_tracking(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            attempts = []
            def side_effect(*args, **kwargs):
                attempts.append(len(attempts))
                if len(attempts) < 4:
                    raise Exception("connection reset")
                return MockOpenAIResponse()

            mock_client.chat.completions.create.side_effect = side_effect

            response = backend.generate("test prompt")
            self.assertEqual(response.text, "test response")
            self.assertEqual(attempts, [0, 1, 2, 3])

class TestTimeoutHandling(unittest.TestCase):
    """Test timeout behavior."""

    @patch('time.time')
    @patch('time.sleep')
    def test_total_timeout(self, mock_sleep, mock_time):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            # simulate time passing
            times = [0, 100, 200, 310]  # 310s > 300s MAX_TOTAL_TIME
            mock_time.side_effect = times

            # always fail
            mock_client.chat.completions.create.side_effect = Exception("timeout")

            with self.assertRaises(RuntimeError) as context:
                backend.generate("test prompt")

            self.assertIn("Retry timeout exceeded", str(context.exception))
            self.assertIn("300s", str(context.exception))

    def test_request_timeout_configured(self):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")
            # the timeout is set in __init__
            self.assertIsNotNone(backend._http_client)

class TestResponseValidation(unittest.TestCase):
    """Test response validation."""

    @patch('time.sleep')
    def test_empty_response_handling(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            # return response with empty choices (should trigger retry via valueerror)
            empty_response = type('Response', (), {
                'choices': [],
                'usage': None
            })()

            call_count = [0]
            def side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] < 3:
                    return empty_response
                return MockOpenAIResponse()

            mock_client.chat.completions.create.side_effect = side_effect
            # note: the valueerror from empty choices is not retryable (it's a validation error)
            # so this should actually raise valueerror, not succeed
            with self.assertRaises(ValueError) as context:
                backend.generate("test prompt")
            self.assertIn("empty choices", str(context.exception).lower())

    def test_missing_usage_handling(self):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            # response with none usage - mockopenairesponse provides default usage if none
            # so we need to create a proper mock with actual none usage
            mock_response = type('Response', (), {
                'choices': [
                    type('Choice', (), {
                        'message': type('Message', (), {
                            'content': 'test response',
                            'tool_calls': [],
                            'reasoning': None,
                            'reasoning_details': None
                        })(),
                        'finish_reason': 'stop'
                    })()
                ],
                'usage': None
            })()

            mock_client.chat.completions.create.return_value = mock_response
            response = backend.generate("test prompt")
            self.assertEqual(response.prompt_tokens, 0)
            self.assertEqual(response.output_tokens, 0)
            self.assertEqual(response.cost, 0.0)

class TestCostCalculation(unittest.TestCase):
    """Test cost calculation for different backends."""

    def test_token_cost_calculation(self):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client
            usage = type('Usage', (), {
                'prompt_tokens': 1000,
                'completion_tokens': 500,
                'reasoning_tokens': 100
            })()

            mock_response = MockOpenAIResponse(usage=usage)
            mock_client.chat.completions.create.return_value = mock_response

            response = backend.generate("test prompt")
            self.assertEqual(response.prompt_tokens, 1000)
            self.assertEqual(response.output_tokens, 500)
            self.assertEqual(response.thinking_tokens, 100)

            # cost should be calculated correctly
            # cost formula: (prompt * input_price + regular_output * output_price + reasoning * reasoning_price) / 1m
            self.assertGreater(response.cost, 0.0)

    def test_negative_token_protection(self):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client
            # this should result in max(0, completion - reasoning) = 0 regular tokens
            usage = type('Usage', (), {
                'prompt_tokens': 100,
                'completion_tokens': 50,
                'reasoning_tokens': 100  # more than completion!
            })()

            mock_response = MockOpenAIResponse(usage=usage)
            mock_client.chat.completions.create.return_value = mock_response

            response = backend.generate("test prompt")
            self.assertGreaterEqual(response.cost, 0.0)
            self.assertEqual(response.output_tokens, 50)
            self.assertEqual(response.thinking_tokens, 100)

class TestConnectionErrors(unittest.TestCase):
    """Test handling of various connection errors."""

    @patch('time.sleep')
    def test_connection_reset_by_peer(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            call_count = [0]
            def side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] < 3:
                    raise Exception("Connection reset by peer")
                return MockOpenAIResponse()

            mock_client.chat.completions.create.side_effect = side_effect

            response = backend.generate("test prompt")
            self.assertEqual(response.text, "test response")
            self.assertEqual(call_count[0], 3)

    @patch('time.sleep')
    def test_ssl_handshake_error(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            call_count = [0]
            def side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] < 2:
                    raise Exception("SSL handshake failed")
                return MockOpenAIResponse()

            mock_client.chat.completions.create.side_effect = side_effect

            response = backend.generate("test prompt")
            self.assertEqual(response.text, "test response")
            self.assertEqual(call_count[0], 2)

    @patch('time.sleep')
    def test_cloudflare_errors(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            errors = ["520 error", "522 connection timeout", "524 timeout"]
            call_count = [0]

            def side_effect(*args, **kwargs):
                if call_count[0] < len(errors):
                    error = errors[call_count[0]]
                    call_count[0] += 1
                    raise Exception(error)
                call_count[0] += 1
                return MockOpenAIResponse()

            mock_client.chat.completions.create.side_effect = side_effect

            response = backend.generate("test prompt")
            self.assertEqual(response.text, "test response")
            self.assertEqual(call_count[0], 4)  # 3 errors + 1 success

class TestToolCallRetry(unittest.TestCase):
    """Test retry logic with tool calls."""

    @patch('time.sleep')
    def test_tool_call_retry_on_error(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            # create mock tool calls
            tool_calls = [
                type('ToolCall', (), {
                    'id': 'call_123',
                    'function': type('Function', (), {
                        'name': 'test_tool',
                        'arguments': '{"param": "value"}'
                    })()
                })()
            ]

            call_count = [0]
            def side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] < 2:
                    raise Exception("network error")
                return MockOpenAIResponse(tool_calls=tool_calls)

            mock_client.chat.completions.create.side_effect = side_effect

            response = backend.generate_with_tools(
                prompt="test",
                tools=[{"type": "function", "function": {"name": "test_tool"}}]
            )

            self.assertEqual(len(response.tool_calls), 1)
            self.assertEqual(response.tool_calls[0]['name'], 'test_tool')
            self.assertEqual(call_count[0], 2)

class TestMultiTurnRetry(unittest.TestCase):
    """Test retry logic in multi-turn conversations."""

    @patch('time.sleep')
    def test_multi_turn_retry_on_failure(self, mock_sleep):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            mock_client = MagicMock()
            backend.client = mock_client

            messages = [
                {"role": "user", "content": "message 1"},
                {"role": "assistant", "content": "response 1"},
                {"role": "user", "content": "message 2"}
            ]

            call_count = [0]
            def side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] < 2:
                    raise Exception("timeout")
                return MockOpenAIResponse()

            mock_client.chat.completions.create.side_effect = side_effect

            response = backend.generate_with_tools_multi_turn(
                messages=messages,
                tools=[]
            )

            self.assertEqual(response.text, "test response")
            self.assertEqual(call_count[0], 2)

class TestRetryableErrors(unittest.TestCase):
    """Test identification of retryable vs non-retryable errors."""

    def test_is_retryable_error_method(self):
        from src.utils.llm_backend.openrouter import OpenRouterBackend

        with patch('openai.OpenAI'):
            backend = OpenRouterBackend(model="x-ai/grok-4.1-fast", api_key="test-key")

            # retryable errors
            self.assertTrue(backend._is_retryable_error(Exception("connection reset")))
            self.assertTrue(backend._is_retryable_error(Exception("429 rate limit")))
            self.assertTrue(backend._is_retryable_error(Exception("502 bad gateway")))
            self.assertTrue(backend._is_retryable_error(Exception("timeout")))
            self.assertTrue(backend._is_retryable_error(Exception("522 cloudflare")))
            self.assertTrue(backend._is_retryable_error(Exception("network error")))

            # non-retryable errors
            self.assertFalse(backend._is_retryable_error(Exception("400 bad request")))
            self.assertFalse(backend._is_retryable_error(Exception("401 unauthorized")))
            self.assertFalse(backend._is_retryable_error(Exception("invalid input")))

if __name__ == "__main__":
    unittest.main()
