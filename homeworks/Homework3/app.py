"""LangChain security assistant.
Rallaf2022
Homework 3 interactive security agent. The language
model is Google Gemini through ChatGoogleGenerativeAI. The Gemini API
key is read from the GOOGLE_API_KEY environment variable and is never
stored in source. The analyze_password_strength tool scores a password
without storing, printing, or logging it. The calculate_file_hash tool
returns a checksum for a file. A Python REPL tool is available for
Python execution. The terminal loop accepts requests until the user
types exit or quit.
"""

import hashlib
import os
import sys
from pathlib import Path
from typing import Protocol

from langchain.agents import create_agent
from langchain_core.tools import BaseTool, tool
from langchain_experimental.tools import PythonREPLTool
from langchain_google_genai import ChatGoogleGenerativeAI

MODEL_NAME = "gemini-3.5-flash-lite"
API_KEY_ENV_VAR = "GOOGLE_API_KEY"
MIN_RECOMMENDED_LENGTH = 12
MAX_LENGTH_SCORE = 40
CHARACTER_CLASS_SCORE = 15
VERY_STRONG_SCORE = 90
STRONG_SCORE = 70
FAIR_SCORE = 40
HASH_CHUNK_SIZE = 65536
DEFAULT_HASH_ALGORITHM = "sha256"
SUPPORTED_HASH_ALGORITHMS = {
    "sha256": "SHA-256",
    "sha1": "SHA-1",
    "md5": "MD5",
}
EXIT_COMMANDS = {"exit", "quit"}
SECURITY_SYSTEM_PROMPT = (
    "You are a security assistant. Use analyze_password_strength to check "
    "passwords, calculate_file_hash to checksum files, and the Python REPL "
    "tool when a task needs Python execution. Do not repeat passwords in "
    "your replies."
)


class AgentRunner(Protocol):
    """Agent that accepts one user turn and returns message state."""

    def invoke(self, agent_input: dict[str, object]) -> dict[str, object]:
        """Run one agent turn."""


def load_google_api_key() -> str:
    """Load the Gemini API key from the environment.

    Returns:
        The value of the GOOGLE_API_KEY environment variable.

    Raises:
        RuntimeError: If GOOGLE_API_KEY is missing or blank.
    """
    api_key = os.environ.get(API_KEY_ENV_VAR, "").strip()
    if not api_key:
        raise RuntimeError(
            "Set the GOOGLE_API_KEY environment variable before starting "
            "the security assistant."
        )
    return api_key


def create_chat_model(api_key: str) -> ChatGoogleGenerativeAI:
    """Create the Gemini chat model used by the security assistant.

    Args:
        api_key: Gemini API key loaded from the environment.

    Returns:
        A configured ChatGoogleGenerativeAI instance with no tools bound.
    """
    return ChatGoogleGenerativeAI(
        model=MODEL_NAME,
        api_key=api_key,
        temperature=0,
    )


def _length_score(length: int) -> int:
    """Score password length, with full credit at the recommended length.

    Args:
        length: Number of characters in the password.

    Returns:
        Points from 0 through MAX_LENGTH_SCORE.
    """
    if length >= MIN_RECOMMENDED_LENGTH:
        return MAX_LENGTH_SCORE
    return length * MAX_LENGTH_SCORE // MIN_RECOMMENDED_LENGTH


def _strength_label(score: int) -> str:
    """Map a numeric score to a short strength label.

    Args:
        score: Strength score from 0 through 100.

    Returns:
        One of Very strong, Strong, Fair, or Weak.
    """
    if score >= VERY_STRONG_SCORE:
        return "Very strong"
    if score >= STRONG_SCORE:
        return "Strong"
    if score >= FAIR_SCORE:
        return "Fair"
    return "Weak"


def _recommendations(
    length: int,
    uppercase_count: int,
    lowercase_count: int,
    number_count: int,
    special_count: int,
) -> list[str]:
    """Build improvement suggestions from character-class counts.

    Args:
        length: Number of characters in the password.
        uppercase_count: Count of uppercase letters.
        lowercase_count: Count of lowercase letters.
        number_count: Count of digits.
        special_count: Count of characters that are not letters or digits.

    Returns:
        Recommendations that do not include the password itself.
    """
    recommendations: list[str] = []
    if length < MIN_RECOMMENDED_LENGTH:
        recommendations.append(
            f"Use at least {MIN_RECOMMENDED_LENGTH} characters."
        )
    if uppercase_count == 0:
        recommendations.append("Add at least one uppercase letter.")
    if lowercase_count == 0:
        recommendations.append("Add at least one lowercase letter.")
    if number_count == 0:
        recommendations.append("Add at least one number.")
    if special_count == 0:
        recommendations.append(
            "Add at least one special character, such as punctuation."
        )
    if not recommendations:
        recommendations.append(
            "No character-mix changes are needed. Keep the password unique "
            "and avoid reusing it on other accounts."
        )
    return recommendations


@tool
def analyze_password_strength(password: str) -> str:
    """Analyze a password and return a strength score with recommendations.

    Counts length, uppercase letters, lowercase letters, numbers, and
    special characters. Scores those checks from 0 to 100 and lists ways
    to improve the password. The password is not stored, printed, or logged,
    and it is not included in the result.

    Args:
        password: Password to analyze. Used only to count character types.

    Returns:
        Strength score, character counts, and improvement recommendations.
    """
    length = len(password)
    uppercase_count = sum(1 for character in password if character.isupper())
    lowercase_count = sum(1 for character in password if character.islower())
    number_count = sum(1 for character in password if character.isdigit())
    special_count = sum(1 for character in password if not character.isalnum())
    score = _length_score(length)
    if uppercase_count > 0:
        score += CHARACTER_CLASS_SCORE
    if lowercase_count > 0:
        score += CHARACTER_CLASS_SCORE
    if number_count > 0:
        score += CHARACTER_CLASS_SCORE
    if special_count > 0:
        score += CHARACTER_CLASS_SCORE
    recommendations = _recommendations(
        length,
        uppercase_count,
        lowercase_count,
        number_count,
        special_count,
    )
    recommendation_lines = "\n".join(
        f"- {recommendation}" for recommendation in recommendations
    )
    return (
        f"Strength score: {score}/100 ({_strength_label(score)})\n"
        f"Length: {length}\n"
        f"Uppercase letters: {uppercase_count}\n"
        f"Lowercase letters: {lowercase_count}\n"
        f"Numbers: {number_count}\n"
        f"Special characters: {special_count}\n"
        f"Recommendations:\n{recommendation_lines}"
    )


def _normalize_hash_algorithm(algorithm: str) -> str | None:
    """Map a requested algorithm name to a hashlib name.

    Args:
        algorithm: Algorithm name such as SHA-256, SHA-1, or MD5.

    Returns:
        The hashlib algorithm name, or None when it is unsupported.
    """
    normalized = algorithm.strip().lower().replace("-", "").replace("_", "")
    if normalized not in SUPPORTED_HASH_ALGORITHMS:
        return None
    return normalized


def _digest_file(path: Path, algorithm: str) -> str:
    """Hash a file in binary chunks.

    Args:
        path: File to read.
        algorithm: hashlib algorithm name.

    Returns:
        Lowercase hexadecimal digest.
    """
    hasher = hashlib.new(algorithm)
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(HASH_CHUNK_SIZE), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


@tool
def calculate_file_hash(file_path: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """Calculate a file hash using SHA-256, SHA-1, or MD5.

    Reads the file in binary mode and processes it in chunks so large
    files are not loaded all at once. SHA-256 is used when no algorithm
    is given. Missing files, invalid paths, permission errors, and
    unsupported algorithms are returned as messages.

    Args:
        file_path: Path to the file to hash.
        algorithm: Hash algorithm. Accepts SHA-256, SHA-1, or MD5.
            Defaults to SHA-256.

    Returns:
        The algorithm, file path, and hexadecimal digest, or an error
        message when the file or algorithm cannot be used.
    """
    selected_algorithm = algorithm or DEFAULT_HASH_ALGORITHM
    normalized_algorithm = _normalize_hash_algorithm(selected_algorithm)
    if normalized_algorithm is None:
        return "Unsupported hashing algorithm. Choose SHA-256, SHA-1, or MD5."
    stripped_path = file_path.strip()
    if not stripped_path or "\0" in file_path:
        return "Invalid file path. Provide a path to an existing file."
    path = Path(stripped_path)
    try:
        if path.is_dir():
            return f"Invalid file path. Expected a file: {stripped_path}"
        digest = _digest_file(path, normalized_algorithm)
    except FileNotFoundError:
        return f"File not found: {stripped_path}"
    except PermissionError:
        return f"Permission denied while reading: {stripped_path}"
    except IsADirectoryError:
        return f"Invalid file path. Expected a file: {stripped_path}"
    except OSError:
        return f"Invalid file path: {stripped_path}"
    algorithm_label = SUPPORTED_HASH_ALGORITHMS[normalized_algorithm]
    return (
        f"Algorithm: {algorithm_label}\n"
        f"File: {stripped_path}\n"
        f"Hash: {digest}"
    )


def _content_to_text(content: object) -> str:
    """Convert model message content into printable text.

    Args:
        content: A string, a list of text blocks, or another content value.

    Returns:
        The text to show in the terminal.
    """
    if isinstance(content, str):
        return content.strip()
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block.strip())
        elif isinstance(block, dict):
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text.strip())
    return "\n".join(part for part in parts if part)


def _message_text(message: object) -> str:
    """Read the assistant text from one agent message.

    Args:
        message: A LangChain message from the agent result.

    Returns:
        Printable reply text, or an empty string when none is present.
    """
    if isinstance(message, dict):
        return _content_to_text(message.get("content"))
    text = _content_to_text(getattr(message, "content", None))
    if text:
        return text
    return _content_to_text(getattr(message, "content_blocks", None))


def _public_error_text(error: Exception) -> str:
    """Format an error for the terminal without exposing the API key.

    Args:
        error: Exception raised while handling a request.

    Returns:
        The error text with the Gemini API key removed.
    """
    message = str(error)
    api_key = os.environ.get(API_KEY_ENV_VAR, "")
    if api_key:
        message = message.replace(api_key, "[redacted]")
    return message


def create_security_tools() -> list[BaseTool]:
    """Collect the tools the security agent is allowed to call.

    Returns:
        Password analysis, file hashing, and the LangChain Python REPL.
    """
    # PythonREPLTool is the assignment's Python execution tool.
    # It runs code locally in this process.
    python_repl = PythonREPLTool()
    return [analyze_password_strength, calculate_file_hash, python_repl]


def create_security_agent(model: ChatGoogleGenerativeAI) -> AgentRunner:
    """Create the Gemini agent with all three security tools.

    Args:
        model: Gemini chat model built by create_chat_model.

    Returns:
        An agent that can call the password, hash, and Python REPL tools.
    """
    return create_agent(
        model=model,
        tools=create_security_tools(),
        system_prompt=SECURITY_SYSTEM_PROMPT,
    )


def run_chat_loop(agent: AgentRunner) -> None:
    """Read terminal requests until the user types exit or quit.

    Args:
        agent: Security agent that handles one request at a time.
    """
    print("Type a request, or enter exit or quit to stop.")
    while True:
        try:
            request = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSecurity assistant stopped.")
            return
        if not request:
            continue
        # Stop before calling the model when the session is over.
        if request.lower() in EXIT_COMMANDS:
            print("Security assistant stopped.")
            return
        try:
            result = agent.invoke(
                {"messages": [{"role": "user", "content": request}]}
            )
        except Exception as error:
            error_text = _public_error_text(error)
            print(f"Assistant: The request could not be completed. {error_text}")
            continue
        messages = result.get("messages", [])
        if not isinstance(messages, list) or not messages:
            print("Assistant: The assistant did not return a response.")
            continue
        reply = _message_text(messages[-1])
        print(f"Assistant: {reply or 'The assistant did not return any text.'}")


def main() -> None:
    """Initialize the language model and run the terminal chat loop.

    Loads the Gemini API key from the environment, builds the security
    agent, and accepts requests until the user types exit or quit.
    """
    try:
        api_key = load_google_api_key()
        model = create_chat_model(api_key)
        agent = create_security_agent(model)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
    print("Security assistant started. Gemini model is ready.")
    run_chat_loop(agent)


if __name__ == "__main__":
    main()