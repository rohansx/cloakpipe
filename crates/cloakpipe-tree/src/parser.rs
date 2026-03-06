//! Document parser — extracts text and structure from PDF, TXT, and Markdown files.

use crate::indexer::{Heading, ParsedPage};
use anyhow::{bail, Result};
use regex::Regex;

/// Parse a document file and return structured pages.
pub fn parse_document(file_path: &str) -> Result<Vec<ParsedPage>> {
    let ext = std::path::Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    match ext.to_lowercase().as_str() {
        "pdf" => parse_pdf(file_path),
        "txt" | "md" => parse_text(file_path),
        _ => bail!("Unsupported file format: .{}", ext),
    }
}

/// Parse a PDF file and extract text per page.
fn parse_pdf(file_path: &str) -> Result<Vec<ParsedPage>> {
    let bytes = std::fs::read(file_path)?;
    let full_text = pdf_extract::extract_text_from_mem(&bytes)
        .map_err(|e| anyhow::anyhow!("PDF extraction failed: {}", e))?;

    // Split into pages by form feed characters, or treat as single page
    let raw_pages: Vec<&str> = if full_text.contains('\u{0C}') {
        full_text.split('\u{0C}').collect()
    } else {
        // Heuristic: split by double newlines into roughly equal chunks
        vec![&full_text]
    };

    let heading_re = Regex::new(r"(?m)^([A-Z][A-Z0-9 /&,\-]{2,80})$").unwrap();

    let mut pages = Vec::new();
    for (i, text) in raw_pages.iter().enumerate() {
        let text = text.trim().to_string();
        if text.is_empty() {
            continue;
        }

        let mut headings = Vec::new();
        for cap in heading_re.captures_iter(&text) {
            let h = cap[1].trim();
            if h.split_whitespace().count() >= 2 || h.len() > 5 {
                headings.push(Heading {
                    text: titlecase(h),
                    level: 1,
                    page: i + 1,
                });
            }
        }

        pages.push(ParsedPage {
            page_number: i + 1,
            text,
            headings,
        });
    }

    if pages.is_empty() {
        pages.push(ParsedPage {
            page_number: 1,
            text: full_text,
            headings: Vec::new(),
        });
    }

    Ok(pages)
}

/// Parse a plain text / markdown file into sections.
fn parse_text(file_path: &str) -> Result<Vec<ParsedPage>> {
    let content = std::fs::read_to_string(file_path)?;
    let mut headings = Vec::new();
    let mut sections: Vec<ParsedPage> = Vec::new();

    let mut current_text = String::new();
    let mut current_heading: Option<(String, usize)> = None;
    let mut section_idx = 0;

    for line in content.lines() {
        if let Some(h) = parse_markdown_heading(line) {
            // Save previous section
            if !current_text.is_empty() || current_heading.is_some() {
                section_idx += 1;
                sections.push(ParsedPage {
                    page_number: section_idx,
                    text: current_text.clone(),
                    headings: if let Some((ref ch, lvl)) = current_heading {
                        vec![Heading {
                            text: ch.clone(),
                            level: lvl,
                            page: section_idx,
                        }]
                    } else {
                        Vec::new()
                    },
                });
                current_text.clear();
            }

            headings.push(Heading {
                text: h.text.clone(),
                level: h.level,
                page: section_idx + 1,
            });
            current_heading = Some((h.text, h.level));
        } else {
            if !current_text.is_empty() {
                current_text.push('\n');
            }
            current_text.push_str(line);
        }
    }

    // Final section
    if !current_text.is_empty() || current_heading.is_some() {
        section_idx += 1;
        sections.push(ParsedPage {
            page_number: section_idx,
            text: current_text,
            headings: if let Some((ref ch, lvl)) = current_heading {
                vec![Heading {
                    text: ch.clone(),
                    level: lvl,
                    page: section_idx,
                }]
            } else {
                Vec::new()
            },
        });
    }

    // If no sections created, return the whole file as one page
    if sections.is_empty() {
        sections.push(ParsedPage {
            page_number: 1,
            text: content,
            headings: Vec::new(),
        });
    }

    Ok(sections)
}

struct HeadingInfo {
    text: String,
    level: usize,
}

fn parse_markdown_heading(line: &str) -> Option<HeadingInfo> {
    let trimmed = line.trim();
    if trimmed.starts_with("######") {
        Some(HeadingInfo { text: trimmed[6..].trim().to_string(), level: 6 })
    } else if trimmed.starts_with("#####") {
        Some(HeadingInfo { text: trimmed[5..].trim().to_string(), level: 5 })
    } else if trimmed.starts_with("####") {
        Some(HeadingInfo { text: trimmed[4..].trim().to_string(), level: 4 })
    } else if trimmed.starts_with("###") {
        Some(HeadingInfo { text: trimmed[3..].trim().to_string(), level: 3 })
    } else if trimmed.starts_with("##") {
        Some(HeadingInfo { text: trimmed[2..].trim().to_string(), level: 2 })
    } else if trimmed.starts_with("# ") {
        Some(HeadingInfo { text: trimmed[2..].trim().to_string(), level: 1 })
    } else {
        None
    }
}

/// Convert ALL CAPS to Title Case.
fn titlecase(s: &str) -> String {
    s.split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => {
                    c.to_uppercase().to_string() + &chars.as_str().to_lowercase()
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
