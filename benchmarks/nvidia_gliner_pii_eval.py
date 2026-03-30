"""
nvidia/gliner-PII vs CloakPipe Detection Benchmark

Uses the same annotated dataset as cloakpipe-core/examples/pii_benchmark.rs
to evaluate nvidia/gliner-PII model and compare against CloakPipe's regex+financial layers.

Run: pip install gliner && python benchmarks/nvidia_gliner_pii_eval.py
"""

import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Dataset (mirrors pii_benchmark.rs)
# ---------------------------------------------------------------------------

@dataclass
class Annotation:
    text: str
    category: str
    start: int
    end: int

@dataclass
class Sample:
    text: str
    annotations: list[Annotation] = field(default_factory=list)


def build_dataset() -> list[Sample]:
    return [
        # ── Emails ──
        Sample(
            text="Please contact john.doe@example.com for details.",
            annotations=[Annotation("john.doe@example.com", "email", 15, 35)],
        ),
        Sample(
            text="Send reports to alice_w+work@company.co.uk and bob@startup.io by Friday.",
            annotations=[
                Annotation("alice_w+work@company.co.uk", "email", 16, 42),
                Annotation("bob@startup.io", "email", 47, 61),
            ],
        ),
        Sample(
            text="Her email is maria.garcia-lopez@hospital.org.mx and she works in radiology.",
            annotations=[Annotation("maria.garcia-lopez@hospital.org.mx", "email", 13, 47)],
        ),

        # ── Phone Numbers ──
        Sample(
            text="Call me at +1 (555) 123-4567 or +44 20 7946 0958 for urgent matters.",
            annotations=[
                Annotation("+1 (555) 123-4567", "phone", 11, 28),
                Annotation("+44 20 7946 0958", "phone", 32, 48),
            ],
        ),
        Sample(
            text="Reach us at 800-555-0199 or (212) 555-0147.",
            annotations=[
                Annotation("800-555-0199", "phone", 12, 24),
                Annotation("(212) 555-0147", "phone", 28, 42),
            ],
        ),
        Sample(
            text="Indian mobile: +91 98765 43210, landline: 011-2345-6789.",
            annotations=[
                Annotation("+91 98765 43210", "phone", 15, 30),
                Annotation("011-2345-6789", "phone", 42, 55),
            ],
        ),

        # ── IP Addresses ──
        Sample(
            text="Server at 192.168.1.100 responded, but 10.0.0.1 timed out.",
            annotations=[
                Annotation("192.168.1.100", "ip", 10, 23),
                Annotation("10.0.0.1", "ip", 38, 46),
            ],
        ),
        Sample(
            text="Blocked traffic from 203.0.113.42 and 2001:db8::1 on the firewall.",
            annotations=[Annotation("203.0.113.42", "ip", 21, 33)],
        ),

        # ── URLs ──
        Sample(
            text="Visit https://dashboard.example.com/settings and http://localhost:3000/api for docs.",
            annotations=[
                Annotation("https://dashboard.example.com/settings", "url", 6, 44),
                Annotation("http://localhost:3000/api", "url", 49, 73),
            ],
        ),

        # ── Secrets / API Keys ──
        Sample(
            text="Use API key sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx in the header.",
            annotations=[Annotation("sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx", "secret", 12, 63)],
        ),
        Sample(
            text="AWS secret: AKIAIOSFODNN7EXAMPLE, token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.",
            annotations=[
                Annotation("AKIAIOSFODNN7EXAMPLE", "secret", 12, 32),
                Annotation("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "secret", 41, 81),
            ],
        ),

        # ── Financial: Amounts ──
        Sample(
            text="The invoice total is $15,230.50 and includes a ₹2,50,000 consulting fee.",
            annotations=[
                Annotation("$15,230.50", "amount", 21, 31),
                Annotation("₹2,50,000", "amount", 47, 57),
            ],
        ),
        Sample(
            text="Revenue was €1.2M last quarter, up from £950K the previous year.",
            annotations=[
                Annotation("€1.2M", "amount", 12, 17),
                Annotation("£950K", "amount", 41, 46),
            ],
        ),
        Sample(
            text="Salary package: INR 18,00,000 per annum with 15% annual bonus.",
            annotations=[
                Annotation("INR 18,00,000", "amount", 16, 29),
                Annotation("15%", "amount", 45, 48),
            ],
        ),

        # ── Financial: Percentages ──
        Sample(
            text="Interest rate is 7.5% p.a. with a 2.5% processing fee.",
            annotations=[
                Annotation("7.5%", "amount", 17, 21),
                Annotation("2.5%", "amount", 34, 38),
            ],
        ),

        # ── Financial: Dates ──
        Sample(
            text="Filing deadline is March 31, 2026. Previous return filed on 15/01/2025.",
            annotations=[
                Annotation("March 31, 2026", "date", 19, 33),
                Annotation("15/01/2025", "date", 60, 70),
            ],
        ),

        # ── SSN-like patterns ──
        Sample(
            text="SSN: 123-45-6789, Aadhaar: 1234 5678 9012, PAN: ABCDE1234F.",
            annotations=[
                Annotation("123-45-6789", "ssn", 5, 16),
                Annotation("1234 5678 9012", "aadhaar", 27, 41),
                Annotation("ABCDE1234F", "pan", 48, 58),
            ],
        ),

        # ── Mixed PII in realistic paragraphs ──
        Sample(
            text="Dear Mr. Smith, your account (acct@bank.com) shows a balance of $4,521.33. "
                 "Please call +1-800-555-0123 or visit https://portal.bank.com/login to verify. "
                 "Your last login was from 172.16.0.42.",
            annotations=[
                Annotation("acct@bank.com", "email", 30, 43),
                Annotation("$4,521.33", "amount", 64, 73),
                Annotation("+1-800-555-0123", "phone", 88, 103),
                Annotation("https://portal.bank.com/login", "url", 113, 141),  # adjusted
                Annotation("172.16.0.42", "ip", 173, 184),
            ],
        ),
        Sample(
            text="Patient ID MRN-20240315 at 192.168.50.10. Contact: nurse.jan@hospital.org, "
                 "phone (555) 234-5678. Total charges: ₹3,45,000 paid via card ending 4242.",
            annotations=[
                Annotation("192.168.50.10", "ip", 27, 40),
                Annotation("nurse.jan@hospital.org", "email", 51, 73),
                Annotation("(555) 234-5678", "phone", 81, 95),
                Annotation("₹3,45,000", "amount", 113, 123),
            ],
        ),
        Sample(
            text="Deploy key: sk-live-51234567890abcdef. Server: 10.200.1.55, "
                 "admin email: ops-team@infra.internal. Budget: $125,000/year.",
            annotations=[
                Annotation("sk-live-51234567890abcdef", "secret", 12, 36),
                Annotation("10.200.1.55", "ip", 47, 58),
                Annotation("ops-team@infra.internal", "email", 74, 97),
                Annotation("$125,000", "amount", 107, 115),
            ],
        ),

        # ── Negative samples (no PII) ──
        Sample(text="The weather forecast predicts sunny skies with temperatures around 25 degrees."),
        Sample(text="Our quarterly review meeting is scheduled for next Tuesday at 3pm."),
        Sample(text="The algorithm uses a learning rate of 0.001 with batch size 32."),

        # ── Edge cases ──
        Sample(text="No PII here, just version 1.2.3.4 of the software and port 8080."),
        Sample(text="Meeting at 10:30 AM, room 555-A, building 12. Not a phone number."),

        # ── Additional NER-focused samples (names, orgs, locations) ──
        Sample(
            text="Dr. Sarah Johnson at Stanford Medical Center diagnosed the patient.",
            annotations=[
                Annotation("Sarah Johnson", "person", 4, 17),
                Annotation("Stanford Medical Center", "organization", 21, 44),
            ],
        ),
        Sample(
            text="CEO Rajesh Patel of Infosys Limited spoke at the conference in Mumbai.",
            annotations=[
                Annotation("Rajesh Patel", "person", 4, 16),
                Annotation("Infosys Limited", "organization", 20, 35),
                Annotation("Mumbai", "location", 63, 69),
            ],
        ),
        Sample(
            text="The contract between John Williams and Acme Corp was signed in New York on January 15, 2025.",
            annotations=[
                Annotation("John Williams", "person", 21, 34),
                Annotation("Acme Corp", "organization", 39, 48),
                Annotation("New York", "location", 63, 71),
                Annotation("January 15, 2025", "date", 75, 91),
            ],
        ),
        Sample(
            text="Maria Rodriguez, SSN 987-65-4321, lives at 42 Oak Street, San Francisco, CA 94102. "
                 "Contact: maria.r@gmail.com or +1 (415) 555-7890.",
            annotations=[
                Annotation("Maria Rodriguez", "person", 0, 15),
                Annotation("987-65-4321", "ssn", 21, 32),
                Annotation("42 Oak Street, San Francisco, CA 94102", "location", 44, 82),
                Annotation("maria.r@gmail.com", "email", 93, 110),
                Annotation("+1 (415) 555-7890", "phone", 114, 131),
            ],
        ),
        Sample(
            text="Patient: Emma Thompson, DOB: 03/15/1985, MRN: MRN-2024-78901, "
                 "Attending: Dr. Michael Chen at Mayo Clinic.",
            annotations=[
                Annotation("Emma Thompson", "person", 9, 22),
                Annotation("03/15/1985", "date", 29, 39),
                Annotation("Michael Chen", "person", 74, 86),
                Annotation("Mayo Clinic", "organization", 90, 101),
            ],
        ),
    ]


# ---------------------------------------------------------------------------
# Category mapping for nvidia/gliner-PII labels → our benchmark categories
# ---------------------------------------------------------------------------

NVIDIA_LABEL_MAP = {
    "first_name": "person",
    "last_name": "person",
    "date_of_birth": "date",
    "age": "person",
    "gender": "person",
    "email": "email",
    "phone_number": "phone",
    "fax_number": "phone",
    "street_address": "location",
    "city": "location",
    "county": "location",
    "state": "location",
    "postcode": "location",
    "country": "location",
    "coordinate": "location",
    "ssn": "ssn",
    "credit_debit_card": "secret",
    "cvv": "secret",
    "account_number": "secret",
    "bank_routing_number": "secret",
    "swift_bic": "secret",
    "customer_id": "custom",
    "occupation": "custom",
    "company_name": "organization",
    "license_plate": "custom",
    "mac_address": "ip",
    "ipv4": "ip",
    "url": "url",
    "pin": "secret",
    "password": "secret",
    "user_name": "person",
    "date": "date",
    "time": "date",
    "date_time": "date",
    "medical_record_number": "custom",
    "health_plan_beneficiary_number": "custom",
    "certificate_license_number": "custom",
    "device_identifier": "custom",
    "biometric_identifier": "custom",
    "vehicle_identifier": "custom",
    "employee_id": "custom",
    "education_level": "custom",
    "employment_status": "custom",
    "political_view": "custom",
    "religious_belief": "custom",
    "race_ethnicity": "custom",
    "sexuality": "custom",
    "blood_type": "custom",
}


def map_nvidia_label(label: str) -> str:
    """Map nvidia/gliner-PII label to our benchmark category."""
    return NVIDIA_LABEL_MAP.get(label, "custom")


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def spans_overlap(d_start, d_end, a_start, a_end, threshold=0.5) -> bool:
    """Check if detected span overlaps >= threshold of annotation."""
    overlap_start = max(d_start, a_start)
    overlap_end = min(d_end, a_end)
    if overlap_start >= overlap_end:
        return False
    overlap_len = overlap_end - overlap_start
    ann_len = a_end - a_start
    return (overlap_len / ann_len) >= threshold


# ---------------------------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------------------------

def main():
    print("Loading nvidia/gliner-PII model...")
    t0 = time.time()

    from gliner import GLiNER
    model = GLiNER.from_pretrained("nvidia/gliner-pii")
    load_time = time.time() - t0
    print(f"Model loaded in {load_time:.1f}s\n")

    dataset = build_dataset()

    # Entity labels to request from the model — covers all our benchmark categories
    labels = [
        "first_name", "last_name", "email", "phone_number", "ipv4", "url",
        "ssn", "credit_debit_card", "account_number", "password", "pin",
        "street_address", "city", "state", "country", "postcode",
        "company_name", "date", "date_of_birth", "date_time",
        "medical_record_number", "employee_id",
    ]

    overall = Metrics()
    per_cat: dict[str, Metrics] = {}
    total_time_ms = 0.0
    fp_details: list[str] = []
    fn_details: list[str] = []

    for sample in dataset:
        t1 = time.time()
        entities = model.predict_entities(sample.text, labels, threshold=0.3)
        total_time_ms += (time.time() - t1) * 1000

        # Map detections to our categories
        detections = []
        for e in entities:
            cat = map_nvidia_label(e["label"])
            # Merge first_name + last_name adjacent spans into "person"
            detections.append({
                "text": e["text"],
                "label": cat,
                "start": e["start"],
                "end": e["end"],
                "score": e["score"],
            })

        ann_matched = [False] * len(sample.annotations)
        det_matched = [False] * len(detections)

        # Match detections to annotations
        for di, det in enumerate(detections):
            for ai, ann in enumerate(sample.annotations):
                if ann_matched[ai]:
                    continue
                if det["label"] == ann.category and spans_overlap(
                    det["start"], det["end"], ann.start, ann.end
                ):
                    ann_matched[ai] = True
                    det_matched[di] = True
                    overall.tp += 1
                    per_cat.setdefault(ann.category, Metrics()).tp += 1
                    break

        # False positives
        for di, det in enumerate(detections):
            if not det_matched[di]:
                overall.fp += 1
                per_cat.setdefault(det["label"], Metrics()).fp += 1
                fp_details.append(
                    f"  FP: [{det['label']}] '{det['text']}' "
                    f"[{det['start']}-{det['end']}] score={det['score']:.2f} "
                    f"in \"{sample.text[:60]}...\""
                )

        # False negatives
        for ai, ann in enumerate(sample.annotations):
            if not ann_matched[ai]:
                overall.fn += 1
                per_cat.setdefault(ann.category, Metrics()).fn += 1
                fn_details.append(
                    f"  FN: [{ann.category}] '{ann.text}' "
                    f"[{ann.start}-{ann.end}] "
                    f"in \"{sample.text[:60]}...\""
                )

    # Print results
    n = len(dataset)
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║       nvidia/gliner-PII Detection Benchmark                ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Samples: {n:>4}  |  Avg latency: {total_time_ms/n:>8.1f} ms/sample       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ {'Category':>14} │ {'TP':>4} │ {'FP':>4} │ {'FN':>4} │ {'P':>5} {'R':>5} {'F1':>5} ║")
    print("╠══════════════════════════════════════════════════════════════╣")

    for cat in sorted(per_cat.keys()):
        m = per_cat[cat]
        print(f"║ {cat:>14} │ {m.tp:>4} │ {m.fp:>4} │ {m.fn:>4} │ {m.precision:.2f}  {m.recall:.2f}  {m.f1:.2f} ║")

    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ {'OVERALL':>14} │ {overall.tp:>4} │ {overall.fp:>4} │ {overall.fn:>4} │ {overall.precision:.2f}  {overall.recall:.2f}  {overall.f1:.2f} ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    if fp_details:
        print(f"\nFalse Positives ({len(fp_details)}):")
        for d in fp_details:
            print(d)

    if fn_details:
        print(f"\nFalse Negatives ({len(fn_details)}):")
        for d in fn_details:
            print(d)

    status = "PASSED" if overall.f1 >= 0.80 else "FAILED"
    sym = "✓" if overall.f1 >= 0.80 else "✗"
    print(f"\n{sym} Benchmark {status} (F1={overall.f1:.3f}, threshold=0.80)")


if __name__ == "__main__":
    main()
