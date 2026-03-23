//! Format-preserving token generators.
//!
//! Generates realistic-looking fake values that preserve the format of the
//! original (phone stays phone-shaped, email stays email-shaped) while
//! containing no real PII.

use crate::EntityCategory;

/// Generate a format-preserving fake token for the given category and id.
/// The id comes from the vault counter and ensures determinism.
pub fn generate(original: &str, category: &EntityCategory, id: u32) -> String {
    match category {
        EntityCategory::PhoneNumber => fake_phone(original, id),
        EntityCategory::Email => format!("user{:03}@masked.invalid", id),
        EntityCategory::IpAddress => format!("10.{}.{}.1", (id / 256) % 256, id % 256),
        EntityCategory::Amount => fake_amount(original, id),
        EntityCategory::Date => format!("DATE_{:03}", id),
        EntityCategory::Url => format!("https://masked-{:03}.invalid", id),
        EntityCategory::Secret => fake_secret(original, id),
        EntityCategory::Person => format!("User-{:03}", id),
        EntityCategory::Organization => format!("Org-{:03}", id),
        EntityCategory::Location => format!("Location-{:03}", id),
        EntityCategory::Custom(name) => {
            // For custom categories like Aadhaar, PAN, GSTIN, detect by name
            match name.to_uppercase().as_str() {
                "AADHAAR" | "AADHAAR_NUMBER" => fake_aadhaar(id),
                "PAN" | "PAN_CARD" => fake_pan(id),
                "GSTIN" => fake_gstin(id),
                "UPI" | "UPI_ID" => format!("user{:03}@okmasked", id),
                _ => format!("{}-{:03}", name.to_uppercase(), id),
            }
        }
        _ => format!("{}-{:03}", category_prefix(category), id),
    }
}

fn category_prefix(category: &EntityCategory) -> &'static str {
    match category {
        EntityCategory::Person => "PERSON",
        EntityCategory::Organization => "ORG",
        EntityCategory::Location => "LOC",
        EntityCategory::Amount => "AMOUNT",
        EntityCategory::Percentage => "PCT",
        EntityCategory::Date => "DATE",
        EntityCategory::Email => "EMAIL",
        EntityCategory::PhoneNumber => "PHONE",
        EntityCategory::IpAddress => "IP",
        EntityCategory::Secret => "SECRET",
        EntityCategory::Url => "URL",
        EntityCategory::Project => "PROJECT",
        EntityCategory::Business => "BUSINESS",
        EntityCategory::Infra => "INFRA",
        EntityCategory::Custom(_) => "CUSTOM",
    }
}

fn fake_phone(original: &str, id: u32) -> String {
    let n = id as u64;
    if original.starts_with("+91") || original.contains("91 ") {
        // India format: +91 XXXXX XXXXX
        let a = 55500 + (n % 99999);
        let b = 10000 + (n * 7 % 89999);
        format!("+91 {:05} {:05}", a, b)
    } else if original.starts_with("+1") || original.starts_with("1-") {
        // US format: +1-555-XXX-XXXX
        let a = 100 + (n % 899);
        let b = 1000 + (n * 3 % 8999);
        format!("+1-555-{:03}-{:04}", a, b)
    } else {
        // Generic
        let a = 5_550_000_000_u64 + (n * 13 % 9_999_999);
        format!("{:010}", a)
    }
}

fn fake_aadhaar(id: u32) -> String {
    let n = id as u64;
    let a = 5555 + (n % 4444);
    let b = 1000 + (n * 7 % 8999);
    let c = 1000 + (n * 13 % 8999);
    format!("{:04} {:04} {:04}", a, b, c)
}

fn fake_pan(id: u32) -> String {
    // PAN format: AAAAA9999A (5 letters, 4 digits, 1 letter)
    let letters = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    let n = id as usize;
    let l = |i: usize| letters[(n + i * 7) % letters.len()] as char;
    format!("{}{}{}{}{}{}{}{}{}{}",
        l(0), l(1), l(2), l(3), l(4),
        (id % 10), (id / 10 % 10), (id / 100 % 10), (id / 1000 % 10),
        l(5)
    )
}

fn fake_gstin(id: u32) -> String {
    // GSTIN: 2 digits + 10 PAN chars + 1 digit + 1 char + 1 char
    let pan = fake_pan(id);
    format!("{:02}{}1ZV", (id % 36) + 1, pan)
}

fn fake_amount(original: &str, id: u32) -> String {
    let n = (id as u64) * 1234 + 100;
    if original.contains('₹') || original.to_lowercase().contains("inr") {
        format!("₹{}", n)
    } else if original.contains('$') {
        format!("${}.{:02}", n / 100, n % 100)
    } else if original.contains('€') {
        format!("€{}.{:02}", n / 100, n % 100)
    } else if original.contains('£') {
        format!("£{}.{:02}", n / 100, n % 100)
    } else {
        format!("{}.{:02}", n / 100, n % 100)
    }
}

fn fake_secret(original: &str, id: u32) -> String {
    // Preserve the prefix (sk-, AKIA, etc.) if recognizable, mask the rest
    if let Some(prefix) = ["sk-", "pk-", "AKIA", "Bearer ", "ghp_", "glpat-"]
        .iter()
        .find(|p| original.starts_with(*p))
    {
        let suffix_len = original.len().saturating_sub(prefix.len()).min(20);
        let suffix: String = (0..suffix_len).map(|i| {
            let c = b"ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
            c[(id as usize + i * 7) % c.len()] as char
        }).collect();
        format!("{}{}", prefix, suffix)
    } else {
        format!("MASKED-SECRET-{:04}", id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntityCategory;

    #[test]
    fn test_india_phone_format() {
        let fake = generate("+91 98765 43210", &EntityCategory::PhoneNumber, 1);
        assert!(fake.starts_with("+91 "), "India phone should start with +91");
        assert_ne!(fake, "+91 98765 43210", "Should not return original");
    }

    #[test]
    fn test_aadhaar_format() {
        let fake = generate("2345 6789 0123", &EntityCategory::Custom("Aadhaar".into()), 1);
        // Should be XXXX XXXX XXXX format
        let parts: Vec<&str> = fake.split_whitespace().collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.len() == 4 && p.chars().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn test_pan_format() {
        let fake = generate("BNZPM2501F", &EntityCategory::Custom("PAN".into()), 1);
        assert_eq!(fake.len(), 10, "PAN should be 10 chars");
    }

    #[test]
    fn test_email_format() {
        let fake = generate("priya@example.com", &EntityCategory::Email, 5);
        assert!(fake.contains('@'), "Email fake should contain @");
        assert!(fake.ends_with(".invalid"), "Masked emails use .invalid TLD");
    }

    #[test]
    fn test_determinism() {
        // Same id → same output
        let a = generate("test@example.com", &EntityCategory::Email, 3);
        let b = generate("other@example.com", &EntityCategory::Email, 3);
        assert_eq!(a, b, "Same id should produce same format-preserving token");
    }

    #[test]
    fn test_different_ids_differ() {
        let a = generate("test@example.com", &EntityCategory::Email, 1);
        let b = generate("test@example.com", &EntityCategory::Email, 2);
        assert_ne!(a, b, "Different ids should produce different tokens");
    }
}
