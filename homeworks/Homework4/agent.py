# rallaf2022
"""Homework 4 security agent.

Connects Gemini to two MCP servers over stdio:
- the local Security Log Analyzer in this folder
- the published Time MCP server

The agent must use those tools for the security report.
"""

import asyncio
import os
import sys
from pathlib import Path

from langchain.agents import create_agent
from langchain_core.messages import ToolMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_mcp_adapters.client import MultiServerMCPClient

# python-dotenv is optional. The key can also be set in the shell.
try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


# This file and mcp-server.py live in the same Homework4 folder.
HOMEWORK_DIR = Path(__file__).resolve().parent
MCP_SERVER_PATH = HOMEWORK_DIR / "mcp-server.py"
DEFAULT_MODEL = "gemini-2.5-flash"
REPORT_TIMEZONE = "America/New_York"

SYSTEM_PROMPT = """You are a security analyst assistant.
You can analyze sample login logs, count failed login attempts, identify suspicious IP addresses, and get the current time.

Use the actual MCP tools for every fact in the report:
- get_login_logs for the login records
- count_failed_logins for the failed-attempt total
- find_suspicious_ips for IP addresses with 3 or more failures
- get_current_time with timezone America/New_York for the report timestamp

Do not invent security findings, counts, usernames, IP addresses, or timestamps.
If a tool does not return a value, say that it was not available.
"""

USER_TASK = """Analyze all login activity and generate a security report.
Include the current timestamp in America/New_York.
Cover the login records, the number of failed attempts, and any suspicious IP addresses.
Use the actual MCP tools. Do not invent findings or timestamps.
"""


def load_environment() -> None:
    """Load GOOGLE_API_KEY and GOOGLE_MODEL from a .env file when available."""
    if load_dotenv is None:
        return
    # Check the homework folder first, then the current working directory.
    load_dotenv(HOMEWORK_DIR / ".env")
    load_dotenv()


def build_mcp_config() -> dict[str, dict[str, str | list[str]]]:
    """Return stdio settings for the local analyzer and the Time server."""
    return {
        "security_log_analyzer": {
            "transport": "stdio",
            "command": sys.executable,
            "args": [str(MCP_SERVER_PATH)],
        },
        "time": {
            "transport": "stdio",
            "command": "uvx",
            "args": ["mcp-server-time"],
        },
    }


def create_llm() -> ChatGoogleGenerativeAI:
    """Create the Gemini chat model from environment variables."""
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise SystemExit(
            "GOOGLE_API_KEY is not set. Add it to the environment or a .env file."
        )
    model_name = os.getenv("GOOGLE_MODEL") or DEFAULT_MODEL
    print(f"Model: {model_name}")
    return ChatGoogleGenerativeAI(model=model_name, google_api_key=api_key)


def read_message_text(message: object) -> str:
    """Return the text inside a LangChain message."""
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                text_parts.append(block)
            elif isinstance(block, dict) and block.get("text"):
                text_parts.append(str(block["text"]))
        return "\n".join(text_parts)
    return str(content)


def print_loaded_tools(tools: list) -> None:
    """Print tool names so both MCP servers can be confirmed."""
    print("Loaded MCP tools:")
    for tool in tools:
        print(f"- {tool.name}")


def print_agent_result(messages: list) -> None:
    """Print each tool call, its result, and the final security report."""
    print("\nTool calls and results")
    print("----------------------")
    for message in messages:
        tool_calls = getattr(message, "tool_calls", None) or []
        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "unknown")
            tool_args = tool_call.get("args", {})
            print(f"Call: {tool_name} {tool_args}")
        if isinstance(message, ToolMessage):
            print(f"Result ({message.name}): {read_message_text(message)}")
    print("\nSecurity report")
    print("---------------")
    if not messages:
        print("The agent did not return a report.")
        return
    print(read_message_text(messages[-1]))


async def main() -> None:
    """Load both MCP servers, run the security task, and print the report."""
    load_environment()
    if not MCP_SERVER_PATH.is_file():
        raise SystemExit(f"MCP server not found: {MCP_SERVER_PATH}")
    llm = create_llm()
    client = MultiServerMCPClient(build_mcp_config())
    tools = await client.get_tools()
    print_loaded_tools(tools)
    agent = create_agent(model=llm, tools=tools, system_prompt=SYSTEM_PROMPT)
    result = await agent.ainvoke({"messages": [("user", USER_TASK)]})
    print_agent_result(result.get("messages", []))


if __name__ == "__main__":
    asyncio.run(main())
