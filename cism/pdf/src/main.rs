//! Markdown -> PDF. One shot, or a watcher that renders every .md as it lands.
//!
//! Base-14 PDF fonts only, so there are no font files to ship or find at runtime.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use notify::{EventKind, RecursiveMode, Watcher};
use printpdf::{BuiltinFont, IndirectFontRef, Mm, PdfDocument, PdfLayerReference};
use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};

const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;
const MARGIN: f32 = 20.0;
const PT_MM: f32 = 0.352_777_8;
const SKIP: [&str; 6] = ["target", ".git", ".venv", "node_modules", "graphify-out", "__pycache__"];

enum Block {
    Heading(u8, String),
    Para(String),
    Code(String),
    Item(u8, String),
    Rule,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        None | Some("-h") | Some("--help") => {
            eprintln!("mdpdf <file.md> [out.pdf]   render one file");
            eprintln!("mdpdf --watch [dir]         render every .md created or changed under dir");
            return;
        }
        Some("--watch") => watch(Path::new(args.get(1).map(String::as_str).unwrap_or("."))),
        Some(src) => {
            let src = PathBuf::from(src);
            let out = args.get(1).map(PathBuf::from).unwrap_or_else(|| src.with_extension("pdf"));
            render(&src, &out)
        }
    };
    if let Err(e) = r {
        eprintln!("mdpdf: {e}");
        std::process::exit(1);
    }
}

fn watch(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = notify::recommended_watcher(tx)?;
    watcher.watch(root, RecursiveMode::Recursive)?;
    eprintln!("mdpdf: watching {}", root.display());

    // ponytail: last-render map never evicts; fine for a dev-box watcher, add a TTL if it ever runs for weeks.
    let mut last: HashMap<PathBuf, Instant> = HashMap::new();
    for event in rx {
        let event = match event {
            Ok(e) => e,
            Err(e) => {
                eprintln!("mdpdf: watch error: {e}");
                continue;
            }
        };
        if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            continue;
        }
        for path in event.paths {
            if !is_markdown(&path) || skipped(&path) {
                continue;
            }
            // Editors fire several events per save; one render per file per second is enough.
            if last.get(&path).is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
                continue;
            }
            let out = path.with_extension("pdf");
            if up_to_date(&path, &out) {
                continue;
            }
            last.insert(path.clone(), Instant::now());
            match render(&path, &out) {
                Ok(()) => eprintln!("mdpdf: {}", out.display()),
                Err(e) => eprintln!("mdpdf: {}: {e}", path.display()),
            }
        }
    }
    Ok(())
}

fn is_markdown(p: &Path) -> bool {
    p.extension().is_some_and(|e| e.eq_ignore_ascii_case("md"))
}

fn skipped(p: &Path) -> bool {
    p.components().any(|c| SKIP.contains(&c.as_os_str().to_string_lossy().as_ref()))
}

fn up_to_date(src: &Path, out: &Path) -> bool {
    let mtime = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    match (mtime(src), mtime(out)) {
        (Some(s), Some(o)) => o >= s,
        _ => false,
    }
}

fn render(src: &Path, out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let md = std::fs::read_to_string(src)?;
    let title = src.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let (doc, page, layer) = PdfDocument::new(&title, Mm(PAGE_W), Mm(PAGE_H), "text");
    let regular = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let mono = doc.add_builtin_font(BuiltinFont::Courier)?;

    let mut cur: PdfLayerReference = doc.get_page(page).get_layer(layer);
    let mut y = PAGE_H - MARGIN;

    for block in parse(&md) {
        let (lines, size, font, indent, lead): (Vec<String>, f32, &IndirectFontRef, f32, f32) = match &block {
            Block::Heading(level, text) => {
                let size = match level {
                    1 => 20.0,
                    2 => 15.5,
                    3 => 13.0,
                    _ => 11.5,
                };
                (wrap(text, cols(size, false)), size, &bold, 0.0, 2.5)
            }
            Block::Para(text) => (wrap(text, cols(10.5, false)), 10.5, &regular, 0.0, 1.0),
            Block::Item(depth, text) => {
                let indent = f32::from(*depth) * 5.0;
                let width = cols(10.5, false) - (indent / (0.5 * 10.5 * PT_MM)) as usize;
                let mut lines = wrap(text, width.max(10));
                if let Some(first) = lines.first_mut() {
                    *first = format!("\u{2022} {first}");
                }
                (lines, 10.5, &regular, indent, 0.6)
            }
            Block::Code(text) => {
                let lines = text
                    .lines()
                    .flat_map(|l| hard_wrap(l, cols(9.0, true)))
                    .collect::<Vec<_>>();
                (lines, 9.0, &mono, 4.0, 1.5)
            }
            Block::Rule => (vec!["\u{2014}".repeat(60)], 9.0, &regular, 0.0, 2.0),
        };

        y -= lead;
        let line_h = size * 1.35 * PT_MM;
        for line in lines {
            if y - line_h < MARGIN {
                let (p, l) = doc.add_page(Mm(PAGE_W), Mm(PAGE_H), "text");
                cur = doc.get_page(p).get_layer(l);
                y = PAGE_H - MARGIN;
            }
            y -= line_h;
            cur.use_text(line, size, Mm(MARGIN + indent), Mm(y), font);
        }
        y -= lead;
    }

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    doc.save(&mut BufWriter::new(File::create(out)?))?;
    Ok(())
}

/// Characters that fit one line. Courier is exactly 0.6em; Helvetica averages ~0.5em.
fn cols(size: f32, monospaced: bool) -> usize {
    let advance = if monospaced { 0.6 } else { 0.5 } * size * PT_MM;
    (((PAGE_W - 2.0 * MARGIN) / advance) as usize).max(10)
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if word.chars().count() > width {
            lines.extend(hard_wrap(word, width));
            continue;
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn hard_wrap(text: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return vec![String::new()];
    }
    chars.chunks(width).map(|c| c.iter().collect()).collect()
}

/// The base-14 fonts are WinAnsi (cp1252). printpdf drops anything outside it *silently*, so an
/// arrow or a box-drawing glyph would vanish mid-sentence; transliterate what has an ASCII reading.
fn winansi(s: &str) -> String {
    const CP1252_HIGH: &str = "\u{20AC}\u{201A}\u{0192}\u{201E}\u{2026}\u{2020}\u{2021}\u{02C6}\
        \u{2030}\u{0160}\u{2039}\u{0152}\u{017D}\u{2018}\u{2019}\u{201C}\u{201D}\u{2022}\u{2013}\
        \u{2014}\u{02DC}\u{2122}\u{0161}\u{203A}\u{0153}\u{017E}\u{0178}";
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            // Newlines carry the line structure of a code block; they must survive.
            '\n' => out.push('\n'),
            '\t' => out.push_str("    "),
            '\u{2192}' | '\u{2794}' => out.push_str("->"),
            '\u{2190}' => out.push_str("<-"),
            '\u{21D2}' => out.push_str("=>"),
            '\u{2713}' | '\u{2714}' => out.push_str("[ok]"),
            '\u{2717}' | '\u{2718}' => out.push_str("[x]"),
            '\u{2502}' | '\u{2503}' | '\u{2551}' => out.push('|'),
            '\u{2500}' | '\u{2501}' | '\u{2504}' | '\u{2550}' => out.push('-'),
            '\u{0020}'..='\u{007E}' | '\u{00A0}'..='\u{00FF}' => out.push(c),
            c if CP1252_HIGH.contains(c) => out.push(c),
            c if c.is_whitespace() => out.push(' '),
            // emoji, braille spinners, remaining box drawing — no ASCII reading, drop them
            _ => {}
        }
    }
    out
}

fn parse(md: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut buf = String::new();
    let mut depth: u8 = 0;
    let mut heading: Option<u8> = None;
    let mut in_code = false;

    let opts = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_FOOTNOTES;
    for event in Parser::new_ext(md, opts) {
        match event {
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(_) | CodeBlockKind::Indented)) => {
                in_code = true;
                buf.clear();
            }
            Event::End(TagEnd::CodeBlock) => {
                in_code = false;
                blocks.push(Block::Code(std::mem::take(&mut buf).trim_end().to_string()));
            }
            Event::Start(Tag::Heading { level, .. }) => {
                heading = Some(match level {
                    HeadingLevel::H1 => 1,
                    HeadingLevel::H2 => 2,
                    HeadingLevel::H3 => 3,
                    _ => 4,
                });
                buf.clear();
            }
            Event::End(TagEnd::Heading(_)) => {
                let level = heading.take().unwrap_or(4);
                blocks.push(Block::Heading(level, std::mem::take(&mut buf)));
            }
            Event::Start(Tag::List(_)) => depth += 1,
            Event::End(TagEnd::List(_)) => depth = depth.saturating_sub(1),
            Event::End(TagEnd::Item) => {
                blocks.push(Block::Item(depth, std::mem::take(&mut buf)));
            }
            // A loose list item wraps its text in a paragraph; that text belongs to the item.
            Event::End(TagEnd::Paragraph) if depth == 0 => {
                blocks.push(Block::Para(std::mem::take(&mut buf)));
            }
            Event::End(TagEnd::TableCell) => buf.push_str(" | "),
            Event::End(TagEnd::TableRow) | Event::End(TagEnd::TableHead) => {
                blocks.push(Block::Para(std::mem::take(&mut buf)));
            }
            Event::Rule => blocks.push(Block::Rule),
            Event::Text(t) | Event::Code(t) => buf.push_str(&winansi(&t)),
            Event::SoftBreak => buf.push(if in_code { '\n' } else { ' ' }),
            Event::HardBreak => buf.push('\n'),
            _ => {}
        }
    }
    if !buf.trim().is_empty() {
        blocks.push(Block::Para(buf));
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_without_losing_or_overflowing_words() {
        let lines = wrap("alpha beta gamma delta", 11);
        assert!(lines.iter().all(|l| l.chars().count() <= 11), "{lines:?}");
        assert_eq!(lines.join(" "), "alpha beta gamma delta");

        // A word longer than the line still has to go somewhere.
        assert_eq!(wrap("aaaaaaa", 3), vec!["aaa", "aaa", "a"]);
    }

    #[test]
    fn transliterates_what_winansi_cannot_hold() {
        assert_eq!(winansi("think \u{2192} act"), "think -> act");
        assert_eq!(winansi("\u{26A0}\u{FE0F} warn \u{2014} ok"), " warn \u{2014} ok");
        assert_eq!(winansi("a\nb"), "a\nb");

        // A fenced block keeps one Block::Code per fence, with its lines intact.
        let blocks = parse("```\none\ntwo\n```\n");
        match blocks.as_slice() {
            [Block::Code(code)] => assert_eq!(code, "one\ntwo"),
            other => panic!("expected one code block, got {}", other.len()),
        }
    }

    #[test]
    fn parses_each_block_kind() {
        let blocks = parse("# Title\n\ntext\n\n- one\n- two\n\n```\ncode\n```\n\n---\n");
        let shape: Vec<&str> = blocks
            .iter()
            .map(|b| match b {
                Block::Heading(..) => "h",
                Block::Para(_) => "p",
                Block::Item(..) => "i",
                Block::Code(_) => "c",
                Block::Rule => "r",
            })
            .collect();
        assert_eq!(shape, vec!["h", "p", "i", "i", "c", "r"]);
    }

    #[test]
    fn renders_a_real_pdf() {
        let dir = std::env::temp_dir().join("mdpdf-test");
        std::fs::create_dir_all(&dir).unwrap();
        let md = dir.join("in.md");
        let pdf = dir.join("out.pdf");
        std::fs::write(&md, "# Hi\n\nbody text\n\n- item\n\n```\nfn main() {}\n```\n").unwrap();
        render(&md, &pdf).unwrap();
        let bytes = std::fs::read(&pdf).unwrap();
        assert!(bytes.starts_with(b"%PDF"), "not a pdf");
        assert!(bytes.len() > 500, "suspiciously small: {}", bytes.len());
    }
}
