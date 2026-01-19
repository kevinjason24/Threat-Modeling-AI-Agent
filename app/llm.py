"""LLM client wrapper for Threat Modeling Agent using Groq."""

import json
import logging
from typing import TypeVar

from groq import Groq
from pydantic import BaseModel, ValidationError
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class LLMSettings(BaseSettings):
    """LLM configuration from environment variables."""

    # Groq
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"

    # LLM Settings
    llm_temperature: float = 0.1
    llm_max_tokens: int = 8192

    class Config:
        env_file = ".env"
        extra = "ignore"


class LLMClient:
    """LLM client for Threat Modeling Agent using Groq."""

    def __init__(self, settings: LLMSettings | None = None):
        self.settings = settings or LLMSettings()
        self._client: Groq | None = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize the Groq client."""
        if not self.settings.groq_api_key:
            raise ValueError("GROQ_API_KEY is required")

        self._client = Groq(api_key=self.settings.groq_api_key)
        logger.info(f"Initialized Groq client with model: {self.settings.groq_model}")

    @property
    def client(self) -> Groq:
        if self._client is None:
            raise RuntimeError("LLM client not initialized")
        return self._client

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Send a completion request and return the response text."""
        response = self.client.chat.completions.create(
            model=self.settings.groq_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature or self.settings.llm_temperature,
            max_tokens=max_tokens or self.settings.llm_max_tokens,
        )

        content = response.choices[0].message.content
        if content is None:
            raise ValueError("LLM returned empty response")

        return content

    def complete_json(
        self,
        system_prompt: str,
        user_prompt: str,
        response_model: type[T],
        temperature: float | None = None,
        max_tokens: int | None = None,
        max_retries: int = 2,
    ) -> T:
        """Send a completion request and parse the response as JSON into a Pydantic model."""
        last_error: Exception | None = None

        # Add JSON instruction to system prompt
        json_system_prompt = f"""{system_prompt}

CRITICAL: You MUST respond with a valid JSON object only.
- Start with {{ and end with }}
- No markdown code blocks
- No explanation text before or after
- Follow the exact structure shown in the prompt"""

        for attempt in range(max_retries + 1):
            try:
                raw_response = self.complete(
                    system_prompt=json_system_prompt,
                    user_prompt=user_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )

                # Extract JSON from response (handle markdown code blocks)
                json_str = self._extract_json(raw_response)

                # Parse and validate
                data = json.loads(json_str)
                return response_model.model_validate(data)

            except (json.JSONDecodeError, ValidationError) as e:
                last_error = e
                logger.warning(f"JSON parsing attempt {attempt + 1} failed: {e}")
                if attempt < max_retries:
                    # Add error context to retry
                    user_prompt = (
                        f"{user_prompt}\n\n"
                        f"PREVIOUS RESPONSE HAD ERROR: {e}\n"
                        f"Please return ONLY a valid JSON object."
                    )
                continue

        raise ValueError(f"Failed to parse LLM response after {max_retries + 1} attempts: {last_error}")

    def _extract_json(self, text: str) -> str:
        """Extract JSON from LLM response, handling markdown code blocks."""
        text = text.strip()

        # Handle ```json ... ``` blocks
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("```", start)
            if end != -1:
                return text[start:end].strip()

        # Handle ``` ... ``` blocks
        if text.startswith("```") and text.endswith("```"):
            lines = text.split("\n")
            return "\n".join(lines[1:-1]).strip()

        # Try to find JSON object or array
        if "{" in text:
            start = text.find("{")
            # Find matching closing brace
            depth = 0
            for i, char in enumerate(text[start:], start):
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        return text[start : i + 1]

        if "[" in text:
            start = text.find("[")
            depth = 0
            for i, char in enumerate(text[start:], start):
                if char == "[":
                    depth += 1
                elif char == "]":
                    depth -= 1
                    if depth == 0:
                        return text[start : i + 1]

        return text


def get_llm_client() -> LLMClient:
    """Factory function to get an LLM client instance."""
    return LLMClient()
