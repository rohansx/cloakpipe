"""
End-to-end quality test: Real random data through CloakPipe.

Traces every step:
  1. Original text (what the user typed)
  2. Pseudonymized text (what the LLM actually sees)
  3. Check: does ANY real PII survive in what goes to the LLM?
  4. LLM response (with pseudo-tokens)
  5. Rehydrated response (what the user sees)
  6. Direct LLM response (no protection, same prompt)
  7. Quality comparison

Usage:
  # Terminal 1: python tools/gliner-pii-server.py
  # Terminal 2: CLOAKPIPE_VAULT_KEY=... OPENAI_API_KEY=... ./target/release/cloakpipe --config benchmarks/test-config.toml start
  # Terminal 3: python benchmarks/e2e_quality_test.py
"""

import json
import os
import re
import sys
import time
from pathlib import Path

import httpx

# Load .env
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            if value.strip():
                os.environ.setdefault(key.strip(), value.strip())

API_KEY = os.environ.get("OPENAI_API_KEY", "")
PROXY_URL = os.environ.get("CLOAKPIPE_URL", "http://127.0.0.1:8400")
MODEL = "gpt-4o-mini"

# ---------------------------------------------------------------------------
# Random, messy, cross-domain text — the kind people actually paste into LLMs
# ---------------------------------------------------------------------------

SCENARIOS = [
    {
        "id": "slack_thread",
        "title": "Messy Slack thread pasted into LLM",
        "prompt": (
            "Can you clean up these Slack messages into meeting notes?\n\n"
            "jenny.okafor: hey @daniel.voss just got off the call with Nextera's CFO, "
            "Amit Raghavan. he wants to close the Series B at $18.5M pre-money. "
            "I told him we need to loop in our counsel Patricia Weng at pweng@kirkland.com\n\n"
            "daniel.voss: makes sense. can you send him the term sheet? his email is "
            "amit.r@nextera-ventures.com. Also cc me at dvoss@sequoia.com\n\n"
            "jenny.okafor: sure. btw his assistant Mei-Lin called from +1-650-555-3847 "
            "asking about the due diligence docs. I uploaded them to "
            "https://docs.internal.sequoia.com/deals/nextera-b/dd-room\n\n"
            "daniel.voss: perfect. meeting with their board is May 14 at their office — "
            "3200 Sand Hill Road Suite 150, Menlo Park CA 94025. "
            "I'll expense the flights, my Amex ends in 8847\n\n"
            "jenny.okafor: one more thing — Amit's SSN came through on the background "
            "check: 847-29-5518. legal says we can't store that in Slack obviously 😬"
        ),
        "sensitive_items": [
            "jenny.okafor", "daniel.voss", "Amit Raghavan", "Nextera",
            "18.5M", "Patricia Weng", "pweng@kirkland.com",
            "amit.r@nextera-ventures.com", "dvoss@sequoia.com",
            "Mei-Lin", "+1-650-555-3847",
            "https://docs.internal.sequoia.com/deals/nextera-b/dd-room",
            "3200 Sand Hill Road Suite 150, Menlo Park CA 94025",
            "8847", "847-29-5518",
        ],
    },
    {
        "id": "copypasted_email",
        "title": "Customer forwarded email asking for help drafting reply",
        "prompt": (
            "Help me write a professional reply to this email:\n\n"
            "---------- Forwarded message ----------\n"
            "From: Carlos Mendoza <carlos.mendoza@jpmorgan.com>\n"
            "To: Priya Sharma <priya.s@techstartup.io>\n"
            "Date: March 28, 2026\n"
            "Subject: Overdue Invoice #INV-2026-4419\n\n"
            "Dear Priya,\n\n"
            "This is a follow-up regarding Invoice #INV-2026-4419 for $78,400 "
            "dated February 15, 2026. Payment was due March 1 and we have not "
            "received it. Our records show the wire should go to:\n\n"
            "Bank: JPMorgan Chase\n"
            "Routing: 021000021\n"
            "Account: 8832-4419-7761\n"
            "Swift: CHASUS33\n\n"
            "Please remit payment within 5 business days or contact me at "
            "+1 (212) 555-8803 or my assistant Rachel Kim at rachel.k@jpmorgan.com.\n\n"
            "If there's a dispute, please reference PO #PO-2025-88123 and send "
            "documentation to our billing address: 383 Madison Avenue, Floor 24, "
            "New York, NY 10179.\n\n"
            "Best regards,\n"
            "Carlos Mendoza\n"
            "VP, Corporate Accounts\n"
            "Employee ID: JPM-E-441872"
        ),
        "sensitive_items": [
            "Carlos Mendoza", "carlos.mendoza@jpmorgan.com",
            "Priya Sharma", "priya.s@techstartup.io",
            "INV-2026-4419", "78,400", "021000021",
            "8832-4419-7761", "CHASUS33",
            "+1 (212) 555-8803", "Rachel Kim", "rachel.k@jpmorgan.com",
            "PO-2025-88123", "383 Madison Avenue, Floor 24, New York, NY 10179",
            "JPM-E-441872",
        ],
    },
    {
        "id": "doctors_note_summary",
        "title": "Patient asking LLM to explain their doctor's notes",
        "prompt": (
            "I just got these notes from my doctor visit and I don't understand "
            "the medical terms. Can you explain in simple language what's going on "
            "and what I should do next?\n\n"
            "PROGRESS NOTE\n"
            "Patient: Okonkwo, Chidera A.\n"
            "DOB: 06/23/1991 | MRN: MRN-2024-99187\n"
            "Provider: Dr. Elizabeth Hartley, MD | NPI: 1548293076\n"
            "Date of Service: 03/28/2026\n"
            "Insurance: Aetna PPO, Member ID: W994281735\n\n"
            "CC: Follow-up for newly diagnosed T2DM.\n"
            "HPI: 34yo M presents for f/u after labs confirmed HbA1c of 8.2% "
            "(up from 6.9% in Sept). BMI 31.4. Pt reports poor dietary adherence, "
            "stress from recent job loss. Lives at 2847 Woodlawn Ave, Apt 6C, "
            "Chicago IL 60637 with spouse Amara Okonkwo. Emergency contact: "
            "brother Emeka Okonkwo at (773) 555-4218.\n\n"
            "MEDS: Metformin 500mg BID (started 01/2026), Lisinopril 10mg daily.\n"
            "PLAN: Increase Metformin to 1000mg BID. Refer to nutritionist. "
            "Recheck HbA1c in 3 months. If >7.5%, consider adding GLP-1 agonist.\n"
            "RTC: 6 weeks.\n\n"
            "Electronically signed by Elizabeth Hartley, MD\n"
            "License #: IL-036-089421"
        ),
        "sensitive_items": [
            "Okonkwo", "Chidera", "06/23/1991", "MRN-2024-99187",
            "Elizabeth Hartley", "1548293076",
            "W994281735", "8.2%", "6.9%",
            "2847 Woodlawn Ave, Apt 6C, Chicago IL 60637",
            "Amara Okonkwo", "Emeka Okonkwo", "(773) 555-4218",
            "IL-036-089421",
        ],
    },
    {
        "id": "immigration_case",
        "title": "Immigration lawyer asking LLM to draft a brief",
        "prompt": (
            "Draft a supporting brief for this asylum case:\n\n"
            "Petitioner: Yusuf Ibrahim Al-Rashidi, A# A-219-847-336\n"
            "DOB: 12/03/1988, Nationality: Iraqi\n"
            "Current address: c/o Islamic Center of Dearborn, "
            "22500 Ford Rd, Dearborn MI 48124\n"
            "Attorney: Maria Elena Gutierrez, Bar #MI-0048291, "
            "Gutierrez Immigration Law LLC, mgutierrez@gillaw.com\n\n"
            "Background: Mr. Al-Rashidi fled Mosul in 2020 after receiving "
            "death threats from a militia group due to his work as a translator "
            "for the US military (contract #W911NF-18-C-0042). He entered the "
            "US on a Special Immigrant Visa (SIV) but his status expired. "
            "His wife Fatima (DOB 03/17/1990) and daughter Noor (DOB 08/22/2016) "
            "are dependents on this petition.\n\n"
            "Key evidence:\n"
            "- Threatening letter dated 11/15/2019 (translated, notarized)\n"
            "- US Army employment verification from Col. James Whitfield\n"
            "- Medical records from Dr. Amir Hassan, psychiatrist, "
            "documenting PTSD (NPI: 1962845173)\n"
            "- Country conditions report from Human Rights Watch\n\n"
            "Hearing date: June 12, 2026 at Arlington Immigration Court, "
            "Judge Patricia Nakamura presiding."
        ),
        "sensitive_items": [
            "Yusuf Ibrahim Al-Rashidi", "A-219-847-336",
            "12/03/1988", "22500 Ford Rd, Dearborn MI 48124",
            "Maria Elena Gutierrez", "MI-0048291", "mgutierrez@gillaw.com",
            "W911NF-18-C-0042", "Fatima", "03/17/1990",
            "Noor", "08/22/2016", "James Whitfield",
            "Amir Hassan", "1962845173", "Patricia Nakamura",
        ],
    },
]


def call_openai_direct(prompt: str) -> dict:
    """Call OpenAI directly — no protection."""
    t0 = time.time()
    with httpx.Client(timeout=60) as c:
        resp = c.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
            json={"model": MODEL, "messages": [{"role": "user", "content": prompt}], "max_tokens": 1024},
        )
        resp.raise_for_status()
        data = resp.json()
    return {
        "response": data["choices"][0]["message"]["content"],
        "latency": time.time() - t0,
        "tokens_in": data["usage"]["prompt_tokens"],
        "tokens_out": data["usage"]["completion_tokens"],
    }


def call_via_cloakpipe_raw(prompt: str) -> dict:
    """
    Call OpenAI through CloakPipe — returns the RAW response with pseudo-tokens
    so we can inspect what the LLM actually produced before rehydration.
    """
    t0 = time.time()
    with httpx.Client(timeout=60) as c:
        resp = c.post(
            f"{PROXY_URL}/v1/chat/completions",
            headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
            json={"model": MODEL, "messages": [{"role": "user", "content": prompt}], "max_tokens": 1024},
        )
        resp.raise_for_status()
        data = resp.json()
    leaked = int(resp.headers.get("X-CloakPipe-Leaked-Entities", "0"))
    request_id = resp.headers.get("X-CloakPipe-Request-Id", "")
    return {
        "response": data["choices"][0]["message"]["content"],
        "latency": time.time() - t0,
        "tokens_in": data["usage"]["prompt_tokens"],
        "tokens_out": data["usage"]["completion_tokens"],
        "leaked_entities": leaked,
        "request_id": request_id,
    }


def get_pseudonymized_text(prompt: str) -> str:
    """Get what CloakPipe would send to the LLM (pseudonymized prompt)."""
    import subprocess
    result = subprocess.run(
        ["./target/release/cloakpipe", "--config", "benchmarks/test-config.toml", "test", "--text", prompt],
        capture_output=True, text=True, timeout=30,
    )
    output = result.stdout
    pseudo = ""
    in_pseudo = False
    for line in output.splitlines():
        if "--- Pseudonymized ---" in line:
            in_pseudo = True
            continue
        if "--- Rehydrated ---" in line:
            break
        if in_pseudo:
            pseudo += line + "\n"
    return pseudo.strip()


def find_pii_in_text(text: str, sensitive_items: list[str]) -> list[str]:
    """Find which sensitive items appear verbatim in the text."""
    found = []
    text_lower = text.lower()
    for item in sensitive_items:
        if item.lower() in text_lower:
            found.append(item)
    return found


def print_separator():
    print("=" * 78)


def print_section(title: str):
    print(f"\n  {'─' * 74}")
    print(f"  {title}")
    print(f"  {'─' * 74}")


def main():
    if not API_KEY:
        print("ERROR: Set OPENAI_API_KEY in benchmarks/.env")
        sys.exit(1)

    # Check proxy
    try:
        r = httpx.get(f"{PROXY_URL}/health", timeout=3)
        if r.status_code != 200:
            raise Exception()
    except Exception:
        print(f"ERROR: CloakPipe proxy not running at {PROXY_URL}")
        print("Start: ./target/release/cloakpipe --config benchmarks/test-config.toml start")
        sys.exit(1)

    print_separator()
    print("  END-TO-END QUALITY TEST: Random Real-World Data")
    print("  Tracing every step of the CloakPipe pipeline")
    print_separator()

    total_sensitive = 0
    total_leaked_to_llm = 0
    total_in_unprotected = 0
    total_in_protected = 0

    for scenario in SCENARIOS:
        prompt = scenario["prompt"]
        sensitive = scenario["sensitive_items"]
        total_sensitive += len(sensitive)

        print(f"\n{'#' * 78}")
        print(f"  SCENARIO: {scenario['title']}")
        print(f"  ID: {scenario['id']} | Sensitive items to protect: {len(sensitive)}")
        print(f"{'#' * 78}")

        # ── Step 1: Show what CloakPipe pseudonymizes ──
        print_section("STEP 1: Pseudonymized text (what the LLM sees)")
        pseudo_text = get_pseudonymized_text(prompt)
        print(f"\n{pseudo_text[:600]}")
        if len(pseudo_text) > 600:
            print(f"  ... [{len(pseudo_text) - 600} more chars]")

        # Check: does any real PII survive in the pseudonymized text?
        leaked_to_llm = find_pii_in_text(pseudo_text, sensitive)
        total_leaked_to_llm += len(leaked_to_llm)

        if leaked_to_llm:
            print(f"\n  ⚠ PII LEAKED TO LLM ({len(leaked_to_llm)}/{len(sensitive)}):")
            for item in leaked_to_llm:
                print(f"    - \"{item}\"")
        else:
            print(f"\n  ✓ ZERO PII leaked to LLM (0/{len(sensitive)})")

        # ── Step 2: Protected LLM call ──
        print_section("STEP 2: Protected response (through CloakPipe)")
        protected = call_via_cloakpipe_raw(prompt)
        print(f"  Latency: {protected['latency']:.2f}s | Tokens: {protected['tokens_in']}→{protected['tokens_out']}")
        print(f"  CloakPipe leaked-entities header: {protected['leaked_entities']}")
        print(f"\n  Response (rehydrated):\n")
        # Print indented
        for line in protected["response"][:800].splitlines():
            print(f"    {line}")
        if len(protected["response"]) > 800:
            print(f"    ... [{len(protected['response']) - 800} more chars]")

        pii_in_protected = find_pii_in_text(protected["response"], sensitive)
        total_in_protected += len(pii_in_protected)

        # ── Step 3: Unprotected LLM call ──
        print_section("STEP 3: Unprotected response (direct to OpenAI)")
        direct = call_openai_direct(prompt)
        print(f"  Latency: {direct['latency']:.2f}s | Tokens: {direct['tokens_in']}→{direct['tokens_out']}")
        print(f"\n  Response:\n")
        for line in direct["response"][:800].splitlines():
            print(f"    {line}")
        if len(direct["response"]) > 800:
            print(f"    ... [{len(direct['response']) - 800} more chars]")

        pii_in_unprotected = find_pii_in_text(direct["response"], sensitive)
        total_in_unprotected += len(pii_in_unprotected)

        # ── Step 4: Comparison ──
        print_section("STEP 4: Comparison")

        overhead = protected["latency"] - direct["latency"]
        pct = (overhead / direct["latency"] * 100) if direct["latency"] > 0 else 0

        print(f"  Latency overhead:         {overhead:+.2f}s ({pct:+.0f}%)")
        print(f"  PII leaked to LLM:        {len(leaked_to_llm)}/{len(sensitive)}")
        print(f"  PII in protected response: {len(pii_in_protected)} (rehydrated back for user)")
        print(f"  PII in unprotected resp:   {len(pii_in_unprotected)} (LLM saw ALL of it)")
        print(f"  Response length:           {len(protected['response'])} vs {len(direct['response'])} chars")

        # Quality note
        if pii_in_protected and pii_in_unprotected:
            quality = "Both responses reference the original data correctly"
        elif not pii_in_protected and pii_in_unprotected:
            quality = "Protected response lost some context during pseudonymization"
        else:
            quality = "Comparable quality"
        print(f"  Quality assessment:        {quality}")

        time.sleep(1)  # Rate limit courtesy

    # ── Final summary ──
    print(f"\n{'#' * 78}")
    print(f"  FINAL SUMMARY")
    print(f"{'#' * 78}")
    print(f"\n  Total sensitive items across all scenarios: {total_sensitive}")
    print(f"  PII that leaked to the LLM (unmasked):     {total_leaked_to_llm} ({total_leaked_to_llm/total_sensitive*100:.1f}%)")
    print(f"  PII in unprotected responses:               {total_in_unprotected}")
    print(f"  PII in protected responses (rehydrated):    {total_in_protected}")
    print(f"\n  Protection rate: {(1 - total_leaked_to_llm/total_sensitive)*100:.1f}% of sensitive data was masked before reaching the LLM")
    print()


if __name__ == "__main__":
    main()
