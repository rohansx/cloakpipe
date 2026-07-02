//! PII Detection Benchmark
//!
//! Evaluates CloakPipe's detection engine (regex + financial layers) against
//! annotated PII samples. Computes precision, recall, and F1 per entity type.
//!
//! Run: cargo run --manifest-path crates/cloakpipe-core/Cargo.toml --example pii_benchmark

use cloakpipe_core::config::DetectionConfig;
use cloakpipe_core::detector::Detector;
use cloakpipe_core::EntityCategory;
use std::collections::HashMap;
use std::time::Instant;

/// A ground-truth annotated PII span.
struct Annotation {
    text: String,
    category: EntityCategory,
    start: usize,
    end: usize,
}

/// A benchmark sample: input text + expected PII spans.
struct Sample {
    text: String,
    annotations: Vec<Annotation>,
}

fn build_dataset() -> Vec<Sample> {
    vec![
        // ── Emails ──
        Sample {
            text: "Please contact john.doe@example.com for details.".into(),
            annotations: vec![Annotation {
                text: "john.doe@example.com".into(),
                category: EntityCategory::Email,
                start: 15,
                end: 35,
            }],
        },
        Sample {
            text: "Send reports to alice_w+work@company.co.uk and bob@startup.io by Friday.".into(),
            annotations: vec![
                Annotation { text: "alice_w+work@company.co.uk".into(), category: EntityCategory::Email, start: 16, end: 42 },
                Annotation { text: "bob@startup.io".into(), category: EntityCategory::Email, start: 47, end: 61 },
            ],
        },
        Sample {
            text: "Her email is maria.garcia-lopez@hospital.org.mx and she works in radiology.".into(),
            annotations: vec![Annotation {
                text: "maria.garcia-lopez@hospital.org.mx".into(),
                category: EntityCategory::Email,
                start: 13,
                end: 47,
            }],
        },

        // ── Phone Numbers ──
        Sample {
            text: "Call me at +1 (555) 123-4567 or +44 20 7946 0958 for urgent matters.".into(),
            annotations: vec![
                Annotation { text: "+1 (555) 123-4567".into(), category: EntityCategory::PhoneNumber, start: 11, end: 28 },
                Annotation { text: "+44 20 7946 0958".into(), category: EntityCategory::PhoneNumber, start: 32, end: 48 },
            ],
        },
        Sample {
            text: "Reach us at 800-555-0199 or (212) 555-0147.".into(),
            annotations: vec![
                Annotation { text: "800-555-0199".into(), category: EntityCategory::PhoneNumber, start: 12, end: 24 },
                Annotation { text: "(212) 555-0147".into(), category: EntityCategory::PhoneNumber, start: 28, end: 42 },
            ],
        },
        Sample {
            text: "Indian mobile: +91 98765 43210, landline: 011-2345-6789.".into(),
            annotations: vec![
                Annotation { text: "+91 98765 43210".into(), category: EntityCategory::PhoneNumber, start: 15, end: 30 },
                Annotation { text: "011-2345-6789".into(), category: EntityCategory::PhoneNumber, start: 42, end: 55 },
            ],
        },

        // ── IP Addresses ──
        Sample {
            text: "Server at 192.168.1.100 responded, but 10.0.0.1 timed out.".into(),
            annotations: vec![
                Annotation { text: "192.168.1.100".into(), category: EntityCategory::IpAddress, start: 10, end: 23 },
                Annotation { text: "10.0.0.1".into(), category: EntityCategory::IpAddress, start: 38, end: 46 },
            ],
        },
        Sample {
            text: "Blocked traffic from 203.0.113.42 and 2001:db8::1 on the firewall.".into(),
            annotations: vec![
                Annotation { text: "203.0.113.42".into(), category: EntityCategory::IpAddress, start: 21, end: 33 },
            ],
        },

        // ── URLs ──
        Sample {
            text: "Visit https://dashboard.example.com/settings and http://localhost:3000/api for docs.".into(),
            annotations: vec![
                Annotation { text: "https://dashboard.example.com/settings".into(), category: EntityCategory::Url, start: 6, end: 44 },
                Annotation { text: "http://localhost:3000/api".into(), category: EntityCategory::Url, start: 49, end: 73 },
            ],
        },

        // ── Secrets / API Keys ──
        Sample {
            text: "Use API key sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx in the header.".into(),
            annotations: vec![Annotation {
                text: "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx".into(),
                category: EntityCategory::Secret,
                start: 12,
                end: 63,
            }],
        },
        Sample {
            text: "AWS secret: AKIAIOSFODNN7EXAMPLE, token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.".into(),
            annotations: vec![
                Annotation { text: "AKIAIOSFODNN7EXAMPLE".into(), category: EntityCategory::Secret, start: 12, end: 32 },
                Annotation { text: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into(), category: EntityCategory::Secret, start: 41, end: 81 },
            ],
        },

        // ── Financial: Amounts ──
        Sample {
            text: "The invoice total is $15,230.50 and includes a ₹2,50,000 consulting fee.".into(),
            annotations: vec![
                Annotation { text: "$15,230.50".into(), category: EntityCategory::Amount, start: 21, end: 31 },
                Annotation { text: "₹2,50,000".into(), category: EntityCategory::Amount, start: 47, end: 57 },
            ],
        },
        Sample {
            text: "Revenue was €1.2M last quarter, up from £950K the previous year.".into(),
            annotations: vec![
                Annotation { text: "€1.2M".into(), category: EntityCategory::Amount, start: 12, end: 17 },
                Annotation { text: "£950K".into(), category: EntityCategory::Amount, start: 41, end: 46 },
            ],
        },
        Sample {
            text: "Salary package: INR 18,00,000 per annum with 15% annual bonus.".into(),
            annotations: vec![
                Annotation { text: "INR 18,00,000".into(), category: EntityCategory::Amount, start: 16, end: 29 },
                Annotation { text: "15%".into(), category: EntityCategory::Amount, start: 45, end: 48 },
            ],
        },

        // ── Financial: Percentages ──
        Sample {
            text: "Interest rate is 7.5% p.a. with a 2.5% processing fee.".into(),
            annotations: vec![
                Annotation { text: "7.5%".into(), category: EntityCategory::Amount, start: 17, end: 21 },
                Annotation { text: "2.5%".into(), category: EntityCategory::Amount, start: 34, end: 38 },
            ],
        },

        // ── Financial: Dates ──
        Sample {
            text: "Filing deadline is March 31, 2026. Previous return filed on 15/01/2025.".into(),
            annotations: vec![
                Annotation { text: "March 31, 2026".into(), category: EntityCategory::Date, start: 19, end: 33 },
                Annotation { text: "15/01/2025".into(), category: EntityCategory::Date, start: 60, end: 70 },
            ],
        },

        // ── SSN-like patterns ──
        Sample {
            text: "SSN: 123-45-6789, Aadhaar: 1234 5678 9012, PAN: ABCDE1234F.".into(),
            annotations: vec![
                Annotation { text: "123-45-6789".into(), category: EntityCategory::Custom("SSN".into()), start: 5, end: 16 },
                Annotation { text: "1234 5678 9012".into(), category: EntityCategory::Custom("AADHAAR".into()), start: 27, end: 41 },
                Annotation { text: "ABCDE1234F".into(), category: EntityCategory::Custom("PAN".into()), start: 48, end: 58 },
            ],
        },

        // ── Mixed PII in realistic paragraphs ──
        Sample {
            text: "Dear Mr. Smith, your account (acct@bank.com) shows a balance of $4,521.33. \
                   Please call +1-800-555-0123 or visit https://portal.bank.com/login to verify. \
                   Your last login was from 172.16.0.42.".into(),
            annotations: vec![
                Annotation { text: "acct@bank.com".into(), category: EntityCategory::Email, start: 30, end: 43 },
                Annotation { text: "$4,521.33".into(), category: EntityCategory::Amount, start: 64, end: 73 },
                Annotation { text: "+1-800-555-0123".into(), category: EntityCategory::PhoneNumber, start: 88, end: 103 },
                Annotation { text: "https://portal.bank.com/login".into(), category: EntityCategory::Url, start: 113, end: 141 },
                Annotation { text: "172.16.0.42".into(), category: EntityCategory::IpAddress, start: 173, end: 184 },
            ],
        },
        Sample {
            text: "Patient ID MRN-20240315 at 192.168.50.10. Contact: nurse.jan@hospital.org, \
                   phone (555) 234-5678. Total charges: ₹3,45,000 paid via card ending 4242.".into(),
            annotations: vec![
                Annotation { text: "192.168.50.10".into(), category: EntityCategory::IpAddress, start: 27, end: 40 },
                Annotation { text: "nurse.jan@hospital.org".into(), category: EntityCategory::Email, start: 51, end: 73 },
                Annotation { text: "(555) 234-5678".into(), category: EntityCategory::PhoneNumber, start: 81, end: 95 },
                Annotation { text: "₹3,45,000".into(), category: EntityCategory::Amount, start: 113, end: 123 },
            ],
        },
        Sample {
            text: "Deploy key: sk-live-51234567890abcdef. Server: 10.200.1.55, \
                   admin email: ops-team@infra.internal. Budget: $125,000/year.".into(),
            annotations: vec![
                Annotation { text: "sk-live-51234567890abcdef".into(), category: EntityCategory::Secret, start: 12, end: 36 },
                Annotation { text: "10.200.1.55".into(), category: EntityCategory::IpAddress, start: 47, end: 58 },
                Annotation { text: "ops-team@infra.internal".into(), category: EntityCategory::Email, start: 74, end: 97 },
                Annotation { text: "$125,000".into(), category: EntityCategory::Amount, start: 107, end: 115 },
            ],
        },

        // ── Negative samples (no PII — should detect nothing) ──
        Sample {
            text: "The weather forecast predicts sunny skies with temperatures around 25 degrees.".into(),
            annotations: vec![],
        },
        Sample {
            text: "Our quarterly review meeting is scheduled for next Tuesday at 3pm.".into(),
            annotations: vec![],
        },
        Sample {
            text: "The algorithm uses a learning rate of 0.001 with batch size 32.".into(),
            annotations: vec![],
        },

        // ── Edge cases ──
        Sample {
            text: "No PII here, just version 1.2.3.4 of the software and port 8080.".into(),
            annotations: vec![], // version numbers should NOT match as IP
        },
        Sample {
            text: "Meeting at 10:30 AM, room 555-A, building 12. Not a phone number.".into(),
            annotations: vec![], // room numbers should NOT match as phone
        },
    ]
}

/// Categorize a detected entity into a normalized bucket for comparison.
fn normalize_category(cat: &EntityCategory) -> &'static str {
    match cat {
        EntityCategory::Email => "email",
        EntityCategory::PhoneNumber => "phone",
        EntityCategory::IpAddress => "ip",
        EntityCategory::Url => "url",
        EntityCategory::Secret => "secret",
        EntityCategory::Amount => "amount",
        EntityCategory::Date => "date",
        EntityCategory::Person => "person",
        EntityCategory::Organization => "org",
        EntityCategory::Location => "location",
        EntityCategory::Percentage => "amount",
        EntityCategory::Project => "project",
        EntityCategory::Business => "custom",
        EntityCategory::Infra => "custom",
        EntityCategory::Custom(s) if s == "SSN" => "ssn",
        EntityCategory::Custom(s) if s == "AADHAAR" => "aadhaar",
        EntityCategory::Custom(s) if s == "PAN" => "pan",
        EntityCategory::Custom(s) if s == "PERCENTAGE" => "amount",
        EntityCategory::Custom(_) => "custom",
    }
}

/// Check if a detected span overlaps with an annotation (fuzzy match).
/// We use overlap ratio: if detected span covers >=50% of the annotation, it's a match.
fn spans_match(det_start: usize, det_end: usize, ann_start: usize, ann_end: usize) -> bool {
    let overlap_start = det_start.max(ann_start);
    let overlap_end = det_end.min(ann_end);
    if overlap_start >= overlap_end {
        return false;
    }
    let overlap_len = overlap_end - overlap_start;
    let ann_len = ann_end - ann_start;
    // At least 50% overlap with the annotation
    overlap_len as f64 / ann_len as f64 >= 0.5
}

struct Metrics {
    true_positives: usize,
    false_positives: usize,
    false_negatives: usize,
}

impl Metrics {
    fn new() -> Self {
        Self { true_positives: 0, false_positives: 0, false_negatives: 0 }
    }

    fn precision(&self) -> f64 {
        if self.true_positives + self.false_positives == 0 {
            return 1.0;
        }
        self.true_positives as f64 / (self.true_positives + self.false_positives) as f64
    }

    fn recall(&self) -> f64 {
        if self.true_positives + self.false_negatives == 0 {
            return 1.0;
        }
        self.true_positives as f64 / (self.true_positives + self.false_negatives) as f64
    }

    fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            return 0.0;
        }
        2.0 * p * r / (p + r)
    }
}

fn main() {
    let dataset = build_dataset();
    let config = DetectionConfig {
        secrets: true,
        financial: true,
        dates: true,
        emails: true,
        phone_numbers: true,
        ip_addresses: true,
        urls_internal: true,
        ner: Default::default(),
        custom: Default::default(),
        overrides: Default::default(),
        resolver: Default::default(),
    };
    let detector = Detector::from_config(&config).expect("Failed to create detector");

    let mut overall = Metrics::new();
    let mut per_category: HashMap<&'static str, Metrics> = HashMap::new();
    let mut total_samples = 0;
    let mut total_time_us = 0u128;
    let mut false_positive_details: Vec<String> = Vec::new();
    let mut false_negative_details: Vec<String> = Vec::new();

    for sample in &dataset {
        total_samples += 1;

        let start = Instant::now();
        let detected = detector.detect(&sample.text).expect("Detection failed");
        total_time_us += start.elapsed().as_micros();

        // Track which annotations were matched
        let mut ann_matched = vec![false; sample.annotations.len()];
        let mut det_matched = vec![false; detected.len()];

        // Match detections to annotations
        for (di, det) in detected.iter().enumerate() {
            let det_cat = normalize_category(&det.category);
            for (ai, ann) in sample.annotations.iter().enumerate() {
                if ann_matched[ai] {
                    continue;
                }
                let ann_cat = normalize_category(&ann.category);
                // Category must match (or be in same family) and spans must overlap
                if det_cat == ann_cat && spans_match(det.start, det.end, ann.start, ann.end) {
                    ann_matched[ai] = true;
                    det_matched[di] = true;

                    overall.true_positives += 1;
                    per_category.entry(ann_cat).or_insert_with(Metrics::new).true_positives += 1;
                    break;
                }
            }
        }

        // False positives: detected but no matching annotation
        for (di, det) in detected.iter().enumerate() {
            if !det_matched[di] {
                let det_cat = normalize_category(&det.category);
                overall.false_positives += 1;
                per_category.entry(det_cat).or_insert_with(Metrics::new).false_positives += 1;
                false_positive_details.push(format!(
                    "  FP: {:?} '{}' [{}-{}] in \"{}...\"",
                    det.category,
                    det.original,
                    det.start,
                    det.end,
                    &sample.text[..sample.text.len().min(60)]
                ));
            }
        }

        // False negatives: annotated but not detected
        for (ai, ann) in sample.annotations.iter().enumerate() {
            if !ann_matched[ai] {
                let ann_cat = normalize_category(&ann.category);
                overall.false_negatives += 1;
                per_category.entry(ann_cat).or_insert_with(Metrics::new).false_negatives += 1;
                false_negative_details.push(format!(
                    "  FN: {:?} '{}' [{}-{}] in \"{}...\"",
                    ann.category,
                    ann.text,
                    ann.start,
                    ann.end,
                    &sample.text[..sample.text.len().min(60)]
                ));
            }
        }
    }

    // Print results
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           CloakPipe PII Detection Benchmark                ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ Samples: {:>4}  |  Avg latency: {:>6.1} µs/sample           ║",
        total_samples,
        total_time_us as f64 / total_samples as f64
    );
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ {:^12} │ {:>5} │ {:>5} │ {:>5} │ {:>4} {:>4} {:>4} ║",
        "Category", "TP", "FP", "FN", "P", "R", "F1");
    println!("╠══════════════════════════════════════════════════════════════╣");

    let mut cats: Vec<_> = per_category.keys().copied().collect();
    cats.sort();
    for cat in &cats {
        let m = &per_category[cat];
        println!("║ {:>12} │ {:>5} │ {:>5} │ {:>5} │ {:.2} {:.2} {:.2} ║",
            cat,
            m.true_positives, m.false_positives, m.false_negatives,
            m.precision(), m.recall(), m.f1()
        );
    }

    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ {:>12} │ {:>5} │ {:>5} │ {:>5} │ {:.2} {:.2} {:.2} ║",
        "OVERALL",
        overall.true_positives, overall.false_positives, overall.false_negatives,
        overall.precision(), overall.recall(), overall.f1()
    );
    println!("╚══════════════════════════════════════════════════════════════╝");

    // Print details
    if !false_positive_details.is_empty() {
        println!("\nFalse Positives ({}):", false_positive_details.len());
        for detail in &false_positive_details {
            println!("{detail}");
        }
    }
    if !false_negative_details.is_empty() {
        println!("\nFalse Negatives ({}):", false_negative_details.len());
        for detail in &false_negative_details {
            println!("{detail}");
        }
    }

    // Exit code: 0 if F1 >= 0.80, 1 otherwise
    if overall.f1() >= 0.80 {
        println!("\n✓ Benchmark PASSED (F1 >= 0.80)");
    } else {
        println!("\n✗ Benchmark FAILED (F1 < 0.80)");
        std::process::exit(1);
    }
}
