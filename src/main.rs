// dada_license_hider — hide the "LICENSED BY ..." text in Dada Life /
// Tailored Noise VST plugins that use the VST3Bridge + encrypted WAVE-VM
// script layout (verified: Endless Smile 1.3.1, Sausage Fattener 1.4.1).
//
// Usage:
//   dada_license_hider <path> [--apply] [--line N] [--restore]
//
//   <path>      a .vst3 bundle dir, a directory to scan for *.dat/*.dll, or a
//               single PE file.
//   --apply     write the patch (default: dry run)
//   --line N    force the script line number to patch (as listed in dry run)
//   --restore   restore every <file>.bak created by a previous --apply
//
// How it works:
//   1. Every PE is scanned for RT_RCDATA resources; the resource that
//      decrypts (MSVC rand() LCG keystream, seed 0) into a
//      `md5hex(name, ...)` script is the plugin's GUI/parameter script.
//   2. The license text is drawn by a "dynamic text" script line, located by:
//        a) a line containing "LICENSED" (inline text)  -> blank the text
//        b) the known draw-call hash c6299f5f10d1735af9684a93f124eb23
//      It is neutralized by zeroing its alpha argument (same length) and,
//      when possible, moving its y1 rectangle beyond the GUI height.
//   3. Re-encryption is ct' = ct ^ pt ^ pt', so only the changed bytes
//     differ; script length never changes.

use std::env;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const KNOWN_HASH: &[u8; 32] = b"c6299f5f10d1735af9684a93f124eb23";
const SIZE_HASH: &[u8; 32] = b"a3472ee7df0fdfb970ede47c577de9a8";

#[derive(Clone, Copy)]
struct RcData {
    id: u32,
    offset: usize,
    size: usize,
}

// ------------------------------------------------------------- little-endian

fn g16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn g32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let mut s = 0;
    let mut e = b.len();
    while s < e && b[s].is_ascii_whitespace() {
        s += 1;
    }
    while e > s && b[e - 1].is_ascii_whitespace() {
        e -= 1;
    }
    &b[s..e]
}

// ------------------------------------------------------------- PE parsing

fn rva_to_off(sections: &[(usize, usize, usize)], rva: usize) -> Option<usize> {
    // sections: (virtual_address, span, pointer_to_raw_data)
    for &(va, span, raw) in sections {
        if va <= rva && rva < va + span.max(1) {
            return Some(rva - va + raw);
        }
    }
    None
}

fn pe_rcdata_bytes(data: &[u8]) -> Vec<RcData> {
    let mut out = Vec::new();
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return out;
    }
    let e = match g32(data, 0x3C) {
        Some(v) => v as usize,
        None => return out,
    };
    if e + 4 > data.len() || &data[e..e + 4] != b"PE\x00\x00" {
        return out;
    }
    let coff = e + 4;
    let nsec = match g16(data, coff + 2) {
        Some(v) => v as usize,
        None => return out,
    };
    let opt_size = match g16(data, coff + 16) {
        Some(v) => v as usize,
        None => return out,
    };
    let opt = coff + 20;
    let magic = match g16(data, opt) {
        Some(v) => v,
        None => return out,
    };
    let dd_off = opt + if magic == 0x10b { 96 } else { 112 };
    let res_rva = match g32(data, dd_off + 2 * 8) {
        Some(v) => v as usize,
        None => return out,
    };
    if res_rva == 0 {
        return out;
    }
    let sec_tab = opt + opt_size;
    let mut sections = Vec::new();
    for i in 0..nsec {
        let o = sec_tab + i * 40;
        let vsz = g32(data, o + 8).unwrap_or(0) as usize;
        let va = g32(data, o + 12).unwrap_or(0) as usize;
        let rsz = g32(data, o + 16).unwrap_or(0) as usize;
        let raw = g32(data, o + 20).unwrap_or(0) as usize;
        sections.push((va, vsz.max(rsz), raw));
    }
    let res_off = match rva_to_off(&sections, res_rva) {
        Some(o) => o,
        None => return out,
    };

    fn walk(
        data: &[u8],
        res_off: usize,
        sections: &[(usize, usize, usize)],
        off: usize,
        level: u32,
        t: u32,
        r: u32,
        out: &mut Vec<RcData>,
    ) {
        if off + 16 > data.len() {
            return;
        }
        let n_named = g16(data, off + 12).unwrap_or(0) as u32;
        let n_ids = g16(data, off + 14).unwrap_or(0) as u32;
        let mut pos = off + 16;
        for _ in 0..n_named + n_ids {
            if pos + 8 > data.len() {
                return;
            }
            let ent_id = g32(data, pos).unwrap_or(0);
            let ent_off = g32(data, pos + 4).unwrap_or(0);
            pos += 8;
            let t2 = if level == 1 { ent_id } else { t };
            let r2 = if level == 2 { ent_id } else { r };
            if ent_off & 0x8000_0000 != 0 {
                let sub = res_off + (ent_off & 0x7FFF_FFFF) as usize;
                walk(data, res_off, sections, sub, level + 1, t2, r2, out);
            } else {
                let de = res_off + (ent_off & 0x7FFF_FFFF) as usize;
                let dva = match g32(data, de) {
                    Some(v) => v,
                    None => continue,
                };
                let dsize = g32(data, de + 4).unwrap_or(0) as usize;
                if let Some(fo) = rva_to_off(sections, dva as usize) {
                    if t == 10 {
                        // RT_RCDATA
                        out.push(RcData {
                            id: r2,
                            offset: fo,
                            size: dsize,
                        });
                    }
                }
            }
        }
    }

    walk(data, res_off, &sections, res_off, 1, 0, 0, &mut out);
    out
}

// ------------------------------------------------------------- cipher

fn lcg_decrypt(ct: &[u8]) -> Vec<u8> {
    let mut s: u32 = 0;
    let mut out = Vec::with_capacity(ct.len());
    for &c in ct {
        s = s.wrapping_mul(0x343FD).wrapping_add(0x269EC3);
        out.push(c ^ (s >> 16) as u8);
    }
    out
}

fn is_hex_hash(b: &[u8]) -> bool {
    b.len() == 32
        && b.iter()
            .all(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn looks_like_script(pt: &[u8]) -> bool {
    if pt.len() < 34 || pt[32] != b'(' || !is_hex_hash(&pt[..32]) {
        return false;
    }
    if pt.split(|&b| b == b'\n').count() < 10 {
        return false;
    }
    let head = &pt[..pt.len().min(4096)];
    let printable = head
        .iter()
        .filter(|&&b| (32..127).contains(&b) || matches!(b, 0 | 10 | 13 | 9))
        .count();
    printable * 4 > head.len() * 3
}

// ------------------------------------------------------------- script utils

/// Split top-level comma-separated args of a call body; returns spans in `body`.
fn split_args(body: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut cur = 0usize;
    let mut i = 0usize;
    while i < body.len() {
        let c = body[i];
        if c == b'"' {
            in_str = !in_str;
        }
        if !in_str {
            if c == b'(' || c == b'{' {
                depth += 1;
            } else if c == b')' || c == b'}' {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            } else if c == b',' && depth == 0 {
                spans.push((cur, i));
                cur = i + 1;
            }
        }
        i += 1;
    }
    spans.push((cur, body.len()));
    spans
}

/// Parse `md5hex(args...)` line -> (abs start of args body, trimmed arg spans).
fn parse_line(line: &[u8]) -> Option<(usize, Vec<&[u8]>)> {
    let start = line.iter().position(|&c| c == b'(')? + 1;
    let end = line.iter().rposition(|&c| c == b')')?;
    if start > end {
        return None;
    }
    let body = &line[start..end];
    let args: Vec<&[u8]> = split_args(body)
        .iter()
        .map(|&(s, e)| trim_ascii(&body[s..e]))
        .collect();
    Some((start, args))
}

fn to_uint(b: &[u8]) -> Option<u64> {
    if b.is_empty() || !b.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    std::str::from_utf8(b).ok()?.parse().ok()
}

fn gui_height(lines: &[&[u8]]) -> Option<u32> {
    for ln in lines {
        if ln.len() > 32 && &ln[..32] == SIZE_HASH {
            if let Some((_, args)) = parse_line(ln) {
                if args.len() >= 2 {
                    if let Some(h) = to_uint(args[1]) {
                        return Some(h as u32);
                    }
                }
            }
        }
    }
    None
}

fn contains_licensed(line: &[u8]) -> bool {
    let pat = b"LICENSED";
    if line.len() < pat.len() {
        return false;
    }
    (0..=line.len() - pat.len()).any(|i| {
        line[i..i + pat.len()]
            .iter()
            .zip(pat)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

fn find_candidates(lines: &[&[u8]]) -> Vec<(usize, &'static str)> {
    let inline: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| contains_licensed(l))
        .map(|(i, _)| (i, "inline LICENSED"))
        .collect();
    if !inline.is_empty() {
        return inline;
    }
    lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.len() > 32 && &l[..32] == KNOWN_HASH)
        .map(|(i, _)| (i, "dynamic-text draw call"))
        .collect()
}

enum PatchOutcome {
    UnknownLayout,
    NoChange,
    Patched(Vec<u8>, Vec<String>),
}

/// Neutralize one draw line. Returns patched line + human-readable changes.
fn patch_line(line: &[u8], height: Option<u32>) -> PatchOutcome {
    let (start, args) = match parse_line(line) {
        Some(v) => v,
        None => return PatchOutcome::UnknownLayout,
    };
    if args.len() < 8 {
        return PatchOutcome::UnknownLayout;
    }
    let end = match line.iter().rposition(|&c| c == b')') {
        Some(e) => e,
        None => return PatchOutcome::UnknownLayout,
    };
    let body = &line[start..end];
    let spans = split_args(body);

    // abs spans of trimmed tokens
    let tok = |i: usize| -> (usize, usize, &[u8]) {
        let mut s = spans[i].0;
        let mut e = spans[i].1;
        while s < e && body[s].is_ascii_whitespace() {
            s += 1;
        }
        while e > s && body[e - 1].is_ascii_whitespace() {
            e -= 1;
        }
        (start + s, start + e, &body[s..e])
    };

    let mut repl: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    let mut changes: Vec<String> = Vec::new();

    // 1) alpha (arg index 7) -> zero, same length
    let (as_, ae, av) = tok(7);
    if !av.is_empty()
        && av.iter().all(|c| c.is_ascii_digit())
        && av.iter().any(|&c| c != b'0')
    {
        let zeros = vec![b'0'; av.len()];
        changes.push(format!(
            "alpha {}->{}",
            String::from_utf8_lossy(av),
            String::from_utf8_lossy(&zeros)
        ));
        repl.push((as_, ae, zeros));
    }

    // 2) y1 (arg index 1) -> beyond GUI height, same length
    if let Some(h) = height {
        let (ys, ye, yv) = tok(1);
        if !yv.is_empty() && yv.iter().all(|c| c.is_ascii_digit()) {
            let cand = vec![b'9'; yv.len()];
            let cand_val = to_uint(&cand).unwrap_or(0);
            let y1_val = to_uint(yv).unwrap_or(0);
            if yv != cand.as_slice() && y1_val <= h as u64 && cand_val > h as u64 {
                changes.push(format!(
                    "y1 {}->{}",
                    String::from_utf8_lossy(yv),
                    String::from_utf8_lossy(&cand)
                ));
                repl.push((ys, ye, cand));
            }
        }
    }

    if repl.is_empty() {
        return PatchOutcome::NoChange;
    }
    let mut out = line.to_vec();
    for (s, e, tok) in repl {
        out[s..e].copy_from_slice(&tok);
    }
    PatchOutcome::Patched(out, changes)
}

// ------------------------------------------------------------- file handling

fn walk_dir(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk_dir(&p, out);
            } else if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                if ext.eq_ignore_ascii_case("dat") || ext.eq_ignore_ascii_case("dll") {
                    out.push(p);
                }
            }
        }
    }
}

fn collect_pe_files(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    let mut out = Vec::new();
    walk_dir(root, &mut out);
    out.sort();
    out
}

fn process_pe(
    path: &Path,
    apply: bool,
    force_line: Option<usize>,
    results: &mut Vec<(PathBuf, bool)>,
) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            println!("  [!] {}: {}", path.display(), e);
            return;
        }
    };
    for rc in pe_rcdata_bytes(&data) {
        let ct = &data[rc.offset..rc.offset + rc.size];
        let pt = lcg_decrypt(ct);
        if !looks_like_script(&pt) {
            continue;
        }
        let lines: Vec<&[u8]> = pt.split(|&b| b == b'\n').collect();
        let height = gui_height(&lines);
        println!(
            "  script resource: id={} offset={:#x} size={:#x}, {} lines, gui_height={}",
            rc.id,
            rc.offset,
            rc.size,
            lines.len().saturating_sub(1),
            height.map(|h| h.to_string()).unwrap_or_else(|| "?".into())
        );
        let cands = match force_line {
            Some(l) => vec![(l, "forced by --line")],
            None => find_candidates(&lines),
        };
        if cands.is_empty() {
            println!("  [!] no license-draw candidate found. Script dump follows (--line N to force):");
            for (i, ln) in lines.iter().enumerate() {
                let t = String::from_utf8_lossy(trim_ascii(ln));
                if !t.is_empty() {
                    let t: String = t.chars().take(160).collect();
                    println!("      {:4} {}", i, t);
                }
            }
            results.push((path.to_path_buf(), false));
            return;
        }
        let (idx, why) = cands[0];
        let line = lines[idx];
        let shown: String = {
            let s = String::from_utf8_lossy(trim_ascii(line));
            s.chars().take(160).collect()
        };
        println!("  candidate line {} ({}): {}", idx, why, shown);
        let (new_line, changes) = match patch_line(line, height) {
            PatchOutcome::UnknownLayout => {
                println!("    -> unrecognized arg layout, skipped");
                results.push((path.to_path_buf(), false));
                return;
            }
            PatchOutcome::NoChange => {
                println!("    -> already patched (nothing to change)");
                results.push((path.to_path_buf(), false));
                return;
            }
            PatchOutcome::Patched(l, c) => (l, c),
        };
        if !apply {
            println!("    -> would change: {} (dry run; use --apply)", changes.join(", "));
            results.push((path.to_path_buf(), true));
            return;
        }

        // pt2 = pt with line idx replaced
        let mut pt2 = pt.clone();
        {
            let mut off = 0usize;
            for (i, ln) in lines.iter().enumerate() {
                if i == idx {
                    pt2[off..off + ln.len()].copy_from_slice(&new_line);
                    break;
                }
                off += ln.len() + 1;
            }
        }
        let ct2: Vec<u8> = ct
            .iter()
            .zip(pt.iter().zip(pt2.iter()))
            .map(|(c, (p, p2))| c ^ p ^ p2)
            .collect();
        let diff: Vec<String> = ct
            .iter()
            .zip(ct2.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, (a, b))| format!("{:#x}:{:02x}->{:02x}", rc.offset + i, a, b))
            .collect();

        let bak = PathBuf::from(format!("{}.bak", path.display()));
        if !bak.exists() {
            if let Err(e) = fs::copy(path, &bak) {
                println!("  [!] backup failed: {}", e);
            } else {
                println!("    backup written: {}", bak.display());
            }
        }
        match fs::OpenOptions::new().write(true).open(path) {
            Ok(mut f) => {
                if let Err(e) = f
                    .seek(SeekFrom::Start(rc.offset as u64))
                    .and_then(|_| f.write_all(&ct2))
                {
                    println!("  [!] write failed: {}. Re-run as administrator.", e);
                    results.push((path.to_path_buf(), false));
                    return;
                }
            }
            Err(e) => {
                println!("  [!] file locked or access denied: {}. Close the host DAW and re-run as administrator.", e);
                results.push((path.to_path_buf(), false));
                return;
            }
        }
        // verify
        let ok = match fs::read(path) {
            Ok(d2) => &d2[rc.offset..rc.offset + rc.size] == ct2.as_slice(),
            Err(_) => false,
        };
        println!(
            "    patched: {} -> {}  [{}]",
            changes.join(", "),
            diff.join(", "),
            if ok { "OK" } else { "VERIFY FAILED" }
        );
        results.push((path.to_path_buf(), true));
        return;
    }
}

fn main() {
    let mut path: Option<String> = None;
    let mut apply = false;
    let mut restore = false;
    let mut force_line: Option<usize> = None;
    let mut it = env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--apply" => apply = true,
            "--yes" => {} // kept for compatibility; first candidate is used
            "--restore" => restore = true,
            "--line" => match it.next().and_then(|v| v.parse::<usize>().ok()) {
                Some(v) => force_line = Some(v),
                None => {
                    eprintln!("--line needs a number");
                    std::process::exit(2);
                }
            },
            other => path = Some(other.to_string()),
        }
    }
    let root = match path {
        Some(p) => p,
        None => {
            eprintln!("usage: dada_license_hider <path> [--apply] [--line N] [--restore]");
            std::process::exit(2);
        }
    };
    let root = PathBuf::from(root);
    let files = collect_pe_files(&root);
    if files.is_empty() {
        println!("no PE files found under {}", root.display());
        std::process::exit(1);
    }

    if restore {
        let mut n = 0;
        for f in &files {
            let bak = PathBuf::from(format!("{}.bak", f.display()));
            if bak.exists() {
                match fs::copy(&bak, f) {
                    Ok(_) => {
                        println!("restored {} from {}", f.display(), bak.display());
                        n += 1;
                    }
                    Err(e) => println!("[!] restore failed for {}: {}", f.display(), e),
                }
            }
        }
        println!("{} file(s) restored.", n);
        return;
    }

    let mut results = Vec::new();
    for f in &files {
        process_pe(f, apply, force_line, &mut results);
    }
    let patched = results.iter().filter(|(_, p)| *p).count();
    println!(
        "\ndone: {} file(s) {} ({} patched).",
        results.len(),
        if apply { "processed" } else { "would patch (dry run)" },
        patched
    );
    if !apply {
        println!("re-run with --apply to write.");
    }
}
