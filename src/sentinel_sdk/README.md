# Sentinel Stream SDK

**Drop-in Python instrumentation for any LLM app.**

Track every prompt, tool call, and model response in 3 lines of code. Events stream to your Sentinel Stream instance for real-time threat detection.

## Install

```bash
pip install -e .   # or just add src/sentinel_sdk to your PYTHONPATH
export SENTINEL_API_URL=http://localhost:8000
export SENTINEL_APP_ID=my-app
```

## Quickstart

### 1. Function calls

```python
from sentinel_sdk import track_prompt, track_tool_call, track_response

track_prompt(agent_id="support-bot", payload="What's the return policy?")
track_tool_call(agent_id="support-bot", tool="search.query", args={"q": "return policy"})
track_response(agent_id="support-bot", payload="You can return within 30 days...")
```

### 2. Decorator (auto-tracks input + output)

```python
from sentinel_sdk import instrument_agent

@instrument_agent(agent_id="research-bot")
def handle(prompt: str) -> str:
    return llm.complete(prompt)

handle("Summarize this article.")  # auto-tracked
```

### 3. Context manager (multi-turn sessions)

```python
from sentinel_sdk import agent_session

with agent_session(agent_id="support-bot", user_id="u123") as s:
    s.prompt("What's the return policy?")
    s.tool_call("search.query", {"q": "return policy"})
    s.tool_response("search.query", [{"title": "Return Policy", ...}])
    s.response("You can return within 30 days...", tokens_in=42, tokens_out=128)
```

## Configuration (env vars)

| Env var | Default | Description |
|---|---|---|
| `SENTINEL_API_URL` | `http://localhost:8000` | Sentinel Stream API URL |
| `SENTINEL_APP_ID` | `default` | Application identifier |
| `SENTINEL_ENABLED` | `1` | Set to `0` to disable tracking (no-op) |
| `SENTINEL_BATCH_SIZE` | `100` | Max events per batch |
| `SENTINEL_FLUSH_INTERVAL_SEC` | `1.0` | Background flush interval |

## Why use it

- **Zero-overhead**: events are batched and sent in a background thread; your LLM call latency is unaffected
- **Drop-in**: no code changes to your LLM framework (LangChain, LlamaIndex, OpenAI SDK all work)
- **Production-ready**: graceful degradation — if Sentinel Stream is down, events are silently dropped
- **MIT-licensed**: same as Sentinel Stream itself

## Integration with LangChain

```python
from langchain.chat_models import ChatOpenAI
from langchain.schema import HumanMessage
from sentinel_sdk import track_prompt, track_response

llm = ChatOpenAI()

def tracked_chat(prompt: str) -> str:
    track_prompt(agent_id="langchain-bot", payload=prompt)
    resp = llm([HumanMessage(content=prompt)])
    track_response(agent_id="langchain-bot", payload=resp.content,
                   tokens_in=resp.llm_output["token_usage"]["prompt_tokens"],
                   tokens_out=resp.llm_output["token_usage"]["completion_tokens"])
    return resp.content
```

## Integration with OpenAI SDK

```python
import openai
from sentinel_sdk import track_prompt, track_response

def tracked_complete(prompt: str) -> str:
    track_prompt(agent_id="openai-bot", payload=prompt)
    resp = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )
    track_response(agent_id="openai-bot", payload=resp.choices[0].message.content,
                   tokens_in=resp.usage.prompt_tokens,
                   tokens_out=resp.usage.completion_tokens)
    return resp.choices[0].message.content
```

## Shutdown

Call `shutdown()` on app exit to flush pending events:

```python
from sentinel_sdk import shutdown
import atexit
atexit.register(shutdown)
```
