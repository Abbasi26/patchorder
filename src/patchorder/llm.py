"""Optional summary hook. Off unless --llm is passed.

The request body is CVE identifiers and description text. Inventory fields are
not arguments of the builder, so they cannot be included by accident.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from patchorder.errors import PatchorderError
from patchorder.report import Finding

_MAX_CVES = 20
_MAX_CHARS = 1200


def cve_texts(findings: list[Finding]) -> list[tuple[str, str]]:
    """The only data the hook is allowed to see."""
    ordered = sorted(findings, key=lambda item: -item.points)
    seen: set[str] = set()
    texts: list[tuple[str, str]] = []
    for finding in ordered:
        if finding.cve_id in seen:
            continue
        seen.add(finding.cve_id)
        description = (finding.description or "").strip()
        if len(description) > _MAX_CHARS:
            description = description[:_MAX_CHARS - 3].rstrip() + "..."
        texts.append((finding.cve_id, description))
        if len(texts) >= _MAX_CVES:
            break
    return texts


def build_messages(texts: list[tuple[str, str]]) -> list[dict[str, str]]:
    blocks = []
    for cve_id, description in texts:
        blocks.append(f"{cve_id}\n{description}")
    user = (
        "Summarize the following public CVE descriptions for an operator.\n"
        "You do not have an inventory. Do not guess host counts, owners, exposure, "
        "or which local version is installed. If a fixed version is not in the text, say so.\n\n"
        + "\n\n".join(blocks)
    )
    return [
        {
            "role": "system",
            "content": (
                "You summarize public CVE description text. "
                "You have no asset inventory. Do not invent affected hosts."
            ),
        },
        {"role": "user", "content": user},
    ]


def request_body(texts: list[tuple[str, str]], model: str) -> dict:
    return {"model": model, "temperature": 0.2, "messages": build_messages(texts)}


def preview_json(texts: list[tuple[str, str]], model: str) -> str:
    return json.dumps(request_body(texts, model), indent=2)


def chat_url(base_url: str) -> str:
    parsed = urlsplit(base_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise PatchorderError("PATCHORDER_LLM_BASE_URL must be an http or https URL")
    if parsed.username or parsed.password:
        raise PatchorderError("put the API key in PATCHORDER_LLM_API_KEY, not in the URL")
    path = parsed.path.rstrip("/")
    if not path.endswith("/chat/completions"):
        path = path + "/chat/completions"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def parse_chat_response(payload: dict) -> str:
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise PatchorderError("LLM endpoint returned an unexpected body") from exc
    if not isinstance(content, str) or not content.strip():
        raise PatchorderError("LLM endpoint returned an empty summary")
    return content.strip()
