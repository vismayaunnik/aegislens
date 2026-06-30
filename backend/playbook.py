from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
from openai import APIConnectionError, APIStatusError, OpenAI, RateLimitError


_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(_ROOT_DIR, ".env"))

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile").strip()
_DEFAULT_TIMEOUT_S = 30

SYSTEM_PROMPT = (
    "You are a SOC analyst assistant. Generate a DRAFT incident response "
    "playbook based on the provided context. Always begin your response with "
    "'DRAFT — review before acting.' This is a suggestion for human review, "
    "not an automated action."
)


def _build_user_prompt(
    log_text: str,
    ioc: str,
    enrichment_result: dict[str, Any],
) -> str:
    risk_score = enrichment_result.get("risk_score")
    source = enrichment_result.get("source", "unknown")
    ioc_type = enrichment_result.get("ioc_type", "unknown")
    status = enrichment_result.get("status", "unknown")

    return (
        "Generate a numbered 3-5 step incident response playbook as plain text.\n\n"
        "Context:\n"
        f"- IOC: {ioc}\n"
        f"- IOC type: {ioc_type}\n"
        f"- Enrichment risk score: {risk_score}\n"
        f"- Enrichment source: {source}\n"
        f"- Enrichment status: {status}\n\n"
        "Raw log text:\n"
        f"{log_text.strip()}\n\n"
        "Requirements:\n"
        "- Use numbered steps only (1., 2., 3., etc.)\n"
        "- Provide 3 to 5 actionable steps for a SOC analyst\n"
        "- Keep each step concise and practical\n"
        "- Do not include markdown headings or bullet lists"
    )


def generate_playbook(
    log_text: str,
    ioc: str,
    enrichment_result: dict[str, Any],
) -> str:
    """
    Generate a draft SOC incident response playbook using the Groq API.

    Returns plain-text playbook on success, or a clear error message string
    if the API call fails.
    """
    if not GROQ_API_KEY:
        return "Error generating playbook: missing GROQ_API_KEY"

    client = OpenAI(
        api_key=GROQ_API_KEY,
        base_url="https://api.groq.com/openai/v1",
        timeout=_DEFAULT_TIMEOUT_S,
    )

    try:
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": _build_user_prompt(log_text, ioc, enrichment_result),
                },
            ],
            temperature=0.3,
            max_tokens=800,
        )
    except RateLimitError:
        return "Error generating playbook: rate limited by Groq API"
    except APIConnectionError:
        return "Error generating playbook: connection error contacting Groq API"
    except APIStatusError as e:
        if e.status_code in (401, 403):
            return "Error generating playbook: invalid Groq API key or forbidden"
        return f"Error generating playbook: Groq API error (HTTP {e.status_code})"
    except Exception as e:
        return f"Error generating playbook: {e}"

    content = response.choices[0].message.content if response.choices else None
    if not content or not content.strip():
        return "Error generating playbook: empty response from Groq API"

    return content.strip()


if __name__ == "__main__":
    sample_log = (
        "2026-06-30 14:22:11Z ALERT firewall blocked outbound connection "
        "from workstation WS-042 (10.0.4.87) to 185.220.101.5 "
        "(update-secure-login.com) over HTTPS. User clicked link in "
        "phishing email subject 'Urgent payroll update'. 14 failed auth "
        "attempts observed in the last 10 minutes."
    )
    sample_ioc = "update-secure-login.com"
    sample_enrichment = {
        "ioc": sample_ioc,
        "ioc_type": "domain",
        "risk_score": 92,
        "source": "virustotal",
        "raw": {"last_analysis_stats": {"malicious": 18, "suspicious": 4}},
        "status": "ok",
        "error": None,
    }

    print(generate_playbook(sample_log, sample_ioc, sample_enrichment))
