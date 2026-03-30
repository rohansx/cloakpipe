"""
Real-World PII Detection & LLM Flow Evaluation

Tests CloakPipe and nvidia/gliner-PII against realistic text that real users
would send to an LLM — customer emails, medical notes, legal memos, HR docs,
insurance claims, etc. None of these are crafted for CloakPipe's patterns.

Then tests the full flow:
  1. Raw prompt → OpenAI (no protection) — baseline
  2. Prompt → CloakPipe proxy → OpenAI → rehydrate — protected

Compares: PII leakage, response quality, latency.

Usage:
  export OPENAI_API_KEY=sk-...
  export CLOAKPIPE_VAULT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
  # Terminal 1: cargo run -p cloakpipe-cli -- start
  # Terminal 2: python benchmarks/realworld_eval.py
"""

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

# Load .env from benchmarks/ directory
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            value = value.strip()
            if value:
                os.environ.setdefault(key.strip(), value)

# ---------------------------------------------------------------------------
# Real-world text samples — messy, natural, NOT crafted for any system
# ---------------------------------------------------------------------------

REAL_WORLD_SAMPLES: list[dict] = [
    {
        "id": "customer_complaint",
        "category": "Customer Support",
        "prompt": (
            "Summarize this customer complaint and suggest a resolution:\n\n"
            "From: Angela Morrison <angela.morrison@outlook.com>\n"
            "Subject: Billing error on account #4829-7731\n\n"
            "Hi, my name is Angela Morrison and I've been a customer since 2019. "
            "My credit card ending in 4532 was charged $347.89 on March 12th but "
            "I never authorized this. I called your support line at 1-888-555-0142 "
            "last week and spoke with someone named Kevin who said he'd fix it, but "
            "nothing happened. My address is 1847 Birchwood Lane, Apt 3B, Portland, "
            "OR 97205. My phone is (503) 555-8291. I want a refund immediately or "
            "I'm filing a complaint with the BBB. My SSN was requested during "
            "verification: 529-48-7163."
        ),
        "expected_pii": [
            "Angela Morrison", "angela.morrison@outlook.com", "4829-7731",
            "4532", "347.89", "1-888-555-0142", "Kevin",
            "1847 Birchwood Lane, Apt 3B, Portland, OR 97205",
            "(503) 555-8291", "529-48-7163",
        ],
    },
    {
        "id": "medical_referral",
        "category": "Healthcare",
        "prompt": (
            "Write a referral letter based on these clinical notes:\n\n"
            "Patient: Priya Natarajan, DOB 08/14/1987, MRN 2024-MED-55891\n"
            "Address: 42 Rosewood Crescent, Bangalore 560034\n"
            "Aadhaar: 7291 8340 5567, Phone: +91 9845012378\n\n"
            "Chief complaint: Persistent migraines for 6 months, worsening. "
            "Current meds: Sumatriptan 50mg PRN, Propranolol 40mg BID. "
            "MRI brain (03/15/2026) showed a 4mm pineal cyst, likely incidental. "
            "BP today 138/88. BMI 27.3. Family history: mother had stroke at 62. "
            "Referring to Dr. Ramesh Iyer at Manipal Hospital neurology for "
            "further evaluation. Insurance: Star Health policy #SH-2024-889012."
        ),
        "expected_pii": [
            "Priya Natarajan", "08/14/1987", "2024-MED-55891",
            "42 Rosewood Crescent, Bangalore 560034",
            "7291 8340 5567", "+91 9845012378", "Ramesh Iyer",
            "SH-2024-889012",
        ],
    },
    {
        "id": "legal_memo",
        "category": "Legal",
        "prompt": (
            "Draft a case summary from these notes:\n\n"
            "Re: Williams v. TechNova Inc., Case No. 3:24-cv-01892\n"
            "Plaintiff James R. Williams, residing at 890 Sycamore Drive, "
            "Austin, TX 78704, alleges wrongful termination after 12 years of "
            "employment. His employee ID was TN-40892 and his last salary was "
            "$142,500/year. Attorney: Sarah Chen, Bar #TX-28491, from Morrison "
            "& Blackwell LLP. Key witness: former HR director Lisa Park, "
            "reachable at lisa.park@gmail.com or 512-555-3847. "
            "Settlement demand: $1.2M plus attorney fees. Mediation scheduled "
            "for April 22, 2026 at the Travis County courthouse. "
            "Opposing counsel: David Goldstein, david.g@technova-legal.com."
        ),
        "expected_pii": [
            "James R. Williams", "890 Sycamore Drive, Austin, TX 78704",
            "TN-40892", "142,500", "Sarah Chen", "TX-28491",
            "Lisa Park", "lisa.park@gmail.com", "512-555-3847",
            "1.2M", "David Goldstein", "david.g@technova-legal.com",
        ],
    },
    {
        "id": "hr_review",
        "category": "HR / People Ops",
        "prompt": (
            "Rewrite this performance review to be more constructive:\n\n"
            "Employee: Marcus Thompson, ID: EMP-2019-4471\n"
            "Department: Engineering, Manager: Jennifer Liu\n"
            "Review period: Q4 2025\n\n"
            "Marcus has been underperforming since September. His commit rate "
            "dropped 40% and he missed the December 15th deadline for the Apex "
            "project. He's been logging into VPN from 10.42.88.156 (home) but "
            "his Jira tickets show minimal progress. I spoke with him on Jan 3rd "
            "and he mentioned personal issues — his wife Elena was hospitalized. "
            "His salary ($128,000) is above the L4 band midpoint. "
            "I recommend a 60-day PIP. Contact HR: hr-reviews@company.internal "
            "or ext 4455. Marcus's personal email is mthompson92@yahoo.com."
        ),
        "expected_pii": [
            "Marcus Thompson", "EMP-2019-4471", "Jennifer Liu",
            "10.42.88.156", "Elena", "128,000",
            "hr-reviews@company.internal", "mthompson92@yahoo.com",
        ],
    },
    {
        "id": "insurance_claim",
        "category": "Insurance / Fintech",
        "prompt": (
            "Assess this insurance claim and determine payout eligibility:\n\n"
            "Claim #INS-2026-78432\n"
            "Policyholder: Robert and Maria Santos\n"
            "Policy: Homeowners HO-3, Premium $2,847/yr, Deductible $1,500\n"
            "Property: 2156 Magnolia Street, Tampa, FL 33629\n"
            "Date of loss: March 3, 2026 (Hurricane damage)\n\n"
            "Adjuster notes (field visit March 8):\n"
            "Roof damage — 60% of shingles displaced. Water intrusion in master "
            "bedroom, living room. Foundation crack on south wall (pre-existing?). "
            "Estimated repair: $47,250. Contractor quote from Bay Area Roofing "
            "(license #CRC-1330841): $52,100. Robert's cell: (813) 555-4129. "
            "Maria's email: maria.santos@icloud.com. Mortgage holder: Wells Fargo, "
            "loan #WF-2019-445821. Bank routing: 121000248, acct: 4478-9921-3356."
        ),
        "expected_pii": [
            "Robert", "Maria Santos", "INS-2026-78432",
            "2,847", "1,500", "2156 Magnolia Street, Tampa, FL 33629",
            "47,250", "52,100", "CRC-1330841",
            "(813) 555-4129", "maria.santos@icloud.com",
            "WF-2019-445821", "121000248", "4478-9921-3356",
        ],
    },
    {
        "id": "tech_incident",
        "category": "DevOps / Incident Response",
        "prompt": (
            "Write a post-mortem for this production incident:\n\n"
            "Incident: API outage on prod-east-1, March 25 2026 14:32 UTC\n"
            "Duration: 47 minutes. Affected: ~12,000 users.\n"
            "Root cause: Engineer Tomás Herrera deployed commit a3f7bc2 to "
            "prod without staging validation. The change introduced a null "
            "pointer in the auth middleware affecting endpoint "
            "https://api.acme-saas.com/v2/users/authenticate. "
            "PagerDuty alert fired to oncall rotation — picked up by Aisha Patel "
            "(aisha.p@acme-saas.com). SSH'd into bastion host 52.14.209.33 "
            "and rolled back at 15:19 UTC. "
            "AWS account 491827364520, region us-east-1. "
            "Slack thread: #incident-2026-0325 in workspace acme-eng. "
            "Action items: enforce staging gate, add null-check, "
            "rotate API key sk-prod-8f2a9c4b7e1d3 that was logged in plaintext."
        ),
        "expected_pii": [
            "Tomás Herrera", "https://api.acme-saas.com/v2/users/authenticate",
            "Aisha Patel", "aisha.p@acme-saas.com", "52.14.209.33",
            "491827364520", "sk-prod-8f2a9c4b7e1d3",
        ],
    },
    {
        "id": "real_estate_contract",
        "category": "Real Estate",
        "prompt": (
            "Review this purchase agreement summary for any red flags:\n\n"
            "Buyer: Chen Wei and Li Mei, jointly\n"
            "Seller: The Estate of Harold R. Finch (deceased Feb 2, 2026)\n"
            "Property: 4721 Lakeview Boulevard, Unit 12A, Chicago, IL 60614\n"
            "Purchase price: $685,000. Earnest money: $34,250 deposited with "
            "First Midwest Title (trust acct #FM-2026-11847).\n"
            "Buyer pre-approved by Chase, loan officer Diana Russo "
            "(diana.russo@chase.com, NMLS #1847293). "
            "30-year fixed at 6.75%, 20% down ($137,000). "
            "Inspection contingency expires April 10, 2026. "
            "Seller's attorney: Patrick O'Brien, (312) 555-8820. "
            "Title search revealed a 2018 mechanic's lien of $8,400 from "
            "Apex Plumbing (resolved). Property tax ID: 14-28-409-035-1012. "
            "Buyer SSN for title: 412-78-9034 and 518-23-6701."
        ),
        "expected_pii": [
            "Chen Wei", "Li Mei", "Harold R. Finch",
            "4721 Lakeview Boulevard, Unit 12A, Chicago, IL 60614",
            "685,000", "34,250", "FM-2026-11847",
            "Diana Russo", "diana.russo@chase.com", "1847293",
            "6.75%", "137,000", "Patrick O'Brien", "(312) 555-8820",
            "8,400", "14-28-409-035-1012", "412-78-9034", "518-23-6701",
        ],
    },
    {
        "id": "therapy_session_notes",
        "category": "Mental Health",
        "prompt": (
            "Summarize these therapy session notes for the treatment plan:\n\n"
            "Client: Samantha Brooks, DOB 11/22/1993\n"
            "Therapist: Dr. Michael Adeyemi, LPC #GA-12847\n"
            "Session 14, March 27, 2026, 2:00 PM\n\n"
            "Samantha reports increased anxiety since her divorce from Tyler Brooks "
            "was finalized on March 1st. She's living at her mother's house "
            "(Janet Brooks, 892 Peachtree Rd NE, Atlanta, GA 30309). "
            "Employer: Delta Air Lines, currently on FMLA leave. "
            "She mentioned suicidal ideation last Tuesday but denied current intent. "
            "Safety plan reviewed. Emergency contact: sister Rachel Miller, "
            "(404) 555-7123. Prescriber: Dr. Yuki Tanaka, psychiatry, "
            "prescribed Sertraline 100mg and Hydroxyzine 25mg PRN. "
            "Insurance: Anthem BCBS, member ID ANT-887421-SB. "
            "Next session: April 3, 2026."
        ),
        "expected_pii": [
            "Samantha Brooks", "11/22/1993", "Michael Adeyemi", "GA-12847",
            "Tyler Brooks", "Janet Brooks",
            "892 Peachtree Rd NE, Atlanta, GA 30309",
            "Rachel Miller", "(404) 555-7123", "Yuki Tanaka",
            "ANT-887421-SB",
        ],
    },
]

# ---------------------------------------------------------------------------
# Part 1: Detection comparison — CloakPipe vs nvidia/gliner-PII
# ---------------------------------------------------------------------------

CLOAKPIPE_BIN = os.path.join(
    os.path.dirname(__file__), "..", "target", "release", "cloakpipe"
)
CLOAKPIPE_CONFIG = os.path.join(os.path.dirname(__file__), "test-config.toml")


def run_cloakpipe_detect(text: str) -> tuple[list[str], str, str]:
    """Run CloakPipe detection via CLI. Returns (entity_lines, pseudonymized, rehydrated)."""
    try:
        result = subprocess.run(
            [CLOAKPIPE_BIN, "--config", CLOAKPIPE_CONFIG, "test", "--text", text],
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout + result.stderr

        entities = []
        pseudonymized = ""
        rehydrated = ""
        section = None

        for line in output.splitlines():
            stripped = line.strip()
            if "--- Detected Entities" in line:
                section = "entities"
                continue
            elif "--- Pseudonymized ---" in line:
                section = "pseudo"
                continue
            elif "--- Rehydrated ---" in line:
                section = "rehydrated"
                continue
            elif "--- Input ---" in line:
                section = "input"
                continue
            elif "Tokens rehydrated:" in line or "Roundtrip match:" in line:
                section = None
                continue

            if section == "entities" and stripped.startswith("["):
                entities.append(stripped)
            elif section == "pseudo" and stripped:
                pseudonymized += stripped + " "
            elif section == "rehydrated" and stripped:
                rehydrated += stripped + " "

        return entities, pseudonymized.strip(), rehydrated.strip()
    except Exception as e:
        return [f"ERROR: {e}"], "", ""


def run_nvidia_gliner_detect(model, text: str) -> list[dict]:
    """Run nvidia/gliner-PII detection."""
    labels = [
        "first_name", "last_name", "email", "phone_number", "ipv4", "url",
        "ssn", "credit_debit_card", "account_number", "password", "pin",
        "street_address", "city", "state", "country", "postcode",
        "company_name", "date", "date_of_birth", "date_time",
        "medical_record_number", "employee_id", "customer_id",
        "bank_routing_number", "swift_bic", "certificate_license_number",
        "fax_number", "mac_address",
    ]
    entities = model.predict_entities(text, labels, threshold=0.3)
    return entities


def count_pii_found(detected_texts: list[str], expected_pii: list[str]) -> tuple[int, list[str], list[str]]:
    """Count how many expected PII items were found. Returns (found, found_list, missed_list)."""
    found = []
    missed = []
    detected_lower = " ".join(detected_texts).lower()
    for pii in expected_pii:
        # Fuzzy: check if any substantial part of the PII appears in detections
        pii_parts = pii.lower().split()
        if any(part in detected_lower for part in pii_parts if len(part) > 2):
            found.append(pii)
        else:
            missed.append(pii)
    return len(found), found, missed


# ---------------------------------------------------------------------------
# Part 2: Full LLM flow — with and without CloakPipe
# ---------------------------------------------------------------------------

def call_openai_direct(api_key: str, prompt: str, model: str = "gpt-4o-mini") -> dict:
    """Call OpenAI directly (no protection)."""
    t0 = time.time()
    with httpx.Client(timeout=60) as client:
        resp = client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
            },
        )
        resp.raise_for_status()
        data = resp.json()
    elapsed = time.time() - t0
    return {
        "response": data["choices"][0]["message"]["content"],
        "latency_s": elapsed,
        "tokens_in": data["usage"]["prompt_tokens"],
        "tokens_out": data["usage"]["completion_tokens"],
    }


def call_via_cloakpipe(api_key: str, proxy_url: str, prompt: str, model: str = "gpt-4o-mini") -> dict:
    """Call OpenAI through CloakPipe proxy (protected)."""
    t0 = time.time()
    with httpx.Client(timeout=60) as client:
        resp = client.post(
            f"{proxy_url}/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
            },
        )
        resp.raise_for_status()
        data = resp.json()
    elapsed = time.time() - t0
    leaked = int(resp.headers.get("X-CloakPipe-Leaked-Entities", "0"))
    return {
        "response": data["choices"][0]["message"]["content"],
        "latency_s": elapsed,
        "tokens_in": data["usage"]["prompt_tokens"],
        "tokens_out": data["usage"]["completion_tokens"],
        "leaked_entities": leaked,
    }


def check_pii_in_text(text: str, pii_list: list[str]) -> list[str]:
    """Check which PII items appear in the text (leaked to/from LLM)."""
    leaked = []
    text_lower = text.lower()
    for pii in pii_list:
        # Check if the PII value appears verbatim (case-insensitive)
        if pii.lower() in text_lower:
            leaked.append(pii)
        # Also check significant parts (e.g., last 4 of SSN, email username)
        elif len(pii) > 6:
            parts = re.split(r'[,\s@.]+', pii)
            for part in parts:
                if len(part) > 3 and part.lower() in text_lower:
                    leaked.append(f"{pii} (partial: {part})")
                    break
    return leaked


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    api_key = os.environ.get("OPENAI_API_KEY", "")
    proxy_url = os.environ.get("CLOAKPIPE_URL", "http://127.0.0.1:8400")

    # Check if CloakPipe proxy is running
    proxy_running = False
    try:
        r = httpx.get(f"{proxy_url}/health", timeout=3)
        proxy_running = r.status_code == 200
    except Exception:
        pass

    # ── Part 1: Detection comparison ──
    print("=" * 72)
    print("  PART 1: PII Detection — CloakPipe vs nvidia/gliner-PII")
    print("=" * 72)

    # Load nvidia model
    print("\nLoading nvidia/gliner-PII model...")
    from gliner import GLiNER
    nvidia_model = GLiNER.from_pretrained("nvidia/gliner-pii")
    print("Model loaded.\n")

    cp_total_found = 0
    cp_total_expected = 0
    nv_total_found = 0
    nv_total_expected = 0

    for sample in REAL_WORLD_SAMPLES:
        text = sample["prompt"]
        expected = sample["expected_pii"]

        print(f"\n{'─' * 72}")
        print(f"  [{sample['category']}] {sample['id']}")
        print(f"  Expected PII items: {len(expected)}")
        print(f"{'─' * 72}")

        # --- CloakPipe detection ---
        cp_entities, cp_pseudo, cp_rehydrated = run_cloakpipe_detect(text)
        cp_texts = [e for e in cp_entities if not e.startswith("ERROR")]
        cp_found, cp_found_list, cp_missed = count_pii_found(cp_texts, expected)
        cp_total_found += cp_found
        cp_total_expected += len(expected)

        print(f"\n  CloakPipe: {cp_found}/{len(expected)} PII items detected")
        if cp_entities:
            for e in cp_entities[:10]:
                print(f"    {e}")
        if cp_missed:
            print(f"    MISSED: {cp_missed}")
        if cp_pseudo:
            print(f"    Pseudonymized preview: {cp_pseudo[:200]}...")

        # --- nvidia/gliner-PII detection ---
        nv_entities = run_nvidia_gliner_detect(nvidia_model, text)
        nv_texts = [f"{e['label']}: {e['text']} (score={e['score']:.2f})" for e in nv_entities]
        nv_raw_texts = [e["text"] for e in nv_entities]
        nv_found, nv_found_list, nv_missed = count_pii_found(
            nv_raw_texts + nv_texts, expected
        )
        nv_total_found += nv_found
        nv_total_expected += len(expected)

        print(f"  nvidia/gliner-PII: {nv_found}/{len(expected)} PII items detected")
        if nv_missed:
            print(f"    Missed: {nv_missed}")

        # Show what nvidia found
        if nv_entities:
            print(f"    Detected entities:")
            for e in nv_entities[:15]:  # cap at 15
                print(f"      [{e['label']}] \"{e['text']}\" (score={e['score']:.2f})")
            if len(nv_entities) > 15:
                print(f"      ... and {len(nv_entities) - 15} more")

    print(f"\n{'=' * 72}")
    print(f"  DETECTION SUMMARY")
    print(f"{'=' * 72}")
    print(f"  CloakPipe recall:        {cp_total_found}/{cp_total_expected} "
          f"({cp_total_found/cp_total_expected*100:.1f}%)")
    print(f"  nvidia/gliner-PII recall: {nv_total_found}/{nv_total_expected} "
          f"({nv_total_found/nv_total_expected*100:.1f}%)")

    # ── Part 2: Full LLM flow ──
    if not api_key:
        print(f"\n{'=' * 72}")
        print("  PART 2: SKIPPED — OPENAI_API_KEY not set")
        print(f"{'=' * 72}")
    elif not proxy_running:
        print(f"\n{'=' * 72}")
        print("  PART 2: SKIPPED — CloakPipe proxy not running")
        print(f"  Start it with: cargo run -p cloakpipe-cli -- start")
        print(f"{'=' * 72}")
    else:
        print(f"\n{'=' * 72}")
        print("  PART 2: Full LLM Flow — Protected vs Unprotected")
        print(f"{'=' * 72}")

        # Use a subset for LLM tests (to save tokens/cost)
        test_samples = REAL_WORLD_SAMPLES[:4]

        for sample in test_samples:
            text = sample["prompt"]
            expected = sample["expected_pii"]

            print(f"\n{'─' * 72}")
            print(f"  [{sample['category']}] {sample['id']}")
            print(f"{'─' * 72}")

            # --- Direct to OpenAI (unprotected) ---
            print("\n  [UNPROTECTED] Sending raw prompt to OpenAI...")
            try:
                direct = call_openai_direct(api_key, text)
                pii_in_response = check_pii_in_text(direct["response"], expected)
                print(f"    Latency: {direct['latency_s']:.2f}s")
                print(f"    Tokens: {direct['tokens_in']}→{direct['tokens_out']}")
                print(f"    PII in LLM response: {len(pii_in_response)} items")
                if pii_in_response:
                    print(f"    Leaked: {pii_in_response[:5]}")
                print(f"    Response preview: {direct['response'][:200]}...")
            except Exception as e:
                print(f"    ERROR: {e}")
                direct = None

            # --- Through CloakPipe (protected) ---
            print(f"\n  [PROTECTED] Sending through CloakPipe proxy...")
            try:
                protected = call_via_cloakpipe(api_key, proxy_url, text)
                pii_in_protected = check_pii_in_text(protected["response"], expected)
                print(f"    Latency: {protected['latency_s']:.2f}s")
                print(f"    Tokens: {protected['tokens_in']}→{protected['tokens_out']}")
                print(f"    CloakPipe leaked entities header: {protected['leaked_entities']}")
                print(f"    PII in rehydrated response: {len(pii_in_protected)} items")
                if pii_in_protected:
                    print(f"    Found: {pii_in_protected[:5]}")
                print(f"    Response preview: {protected['response'][:200]}...")
            except Exception as e:
                print(f"    ERROR: {e}")
                protected = None

            # --- Comparison ---
            if direct and protected:
                overhead = protected["latency_s"] - direct["latency_s"]
                print(f"\n  Comparison:")
                print(f"    Latency overhead: +{overhead:.2f}s ({overhead/direct['latency_s']*100:.0f}%)")
                print(f"    PII in unprotected response: {len(pii_in_response)}")
                print(f"    PII in protected response:   {len(pii_in_protected)}")

            # Be nice to rate limits
            time.sleep(1)

        # ── Final summary ──
        print(f"\n{'=' * 72}")
        print(f"  FLOW TEST COMPLETE")
        print(f"{'=' * 72}")

    print("\nDone.")


if __name__ == "__main__":
    main()
