// dada_license_hider — hide the "LICENSED BY ..." text in Dada Life /
// Tailored Noise VST plugins that use the VST3Bridge + encrypted WAVE-VM
// script layout (verified: Endless Smile 1.3.1, Sausage Fattener 1.4.1).
//
// How it works:
//   1. Every PE is scanned for RT_RCDATA resources; the resource that
//      decrypts (MSVC rand() LCG keystream, seed 0) into a
//      `md5hex(name, ...)` script is the plugin's GUI/parameter script.
//   2. The license text is drawn by a script line, located by:
//        a) a line containing "LICENSED" (inline text)
//        b) the known dynamic-text draw-call hash c6299f5f10d1735af9684a93f124eb23
//      It is neutralized by zeroing its alpha argument (same length) and,
//      when possible, moving its y1 rectangle beyond the GUI height.
//   3. Re-encryption is ct' = ct ^ pt ^ pt', so only the changed bytes
//      differ; script length never changes.
//   4. Before writing, <file>.bak is created. An existing .bak is reused only
//      if it is byte-identical to the file being patched, and --restore only
//      copies a .bak back if patching it reproduces the current file, so a
//      backup left over from an older plugin version is never applied.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

const KNOWN_HASH: &[u8; 32] = b"c6299f5f10d1735af9684a93f124eb23";
const SIZE_HASH: &[u8; 32] = b"a3472ee7df0fdfb970ede47c577de9a8";
const RT_RCDATA: u32 = 10;
const ARG_Y1: usize = 1;
const ARG_ALPHA: usize = 7;

/// Hide the "LICENSED BY ..." text in Dada Life / Tailored Noise VST plugins.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// A .vst3 bundle dir, a directory to scan for *.dat/*.dll, or a single PE file
    path: PathBuf,
    /// Write the patch (default: dry run)
    #[arg(long, conflicts_with = "restore")]
    apply: bool,
    /// Force the script line number to patch (as listed in dry run)
    #[arg(long, value_name = "N")]
    line: Option<usize>,
    /// Restore every <file>.bak created by a previous --apply
    #[arg(long)]
    restore: bool,
    /// Ignored; kept for compatibility (the first candidate is always used)
    #[arg(long, hide = true)]
    yes: bool,
}

// ------------------------------------------------------------- little-endian

fn g16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn g32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn trim_range(b: &[u8], mut r: Range<usize>) -> Range<usize> {
    while r.start < r.end && b[r.start].is_ascii_whitespace() {
        r.start += 1;
    }
    while r.end > r.start && b[r.end - 1].is_ascii_whitespace() {
        r.end -= 1;
    }
    r
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    &b[trim_range(b, 0..b.len())]
}

fn preview(b: &[u8]) -> String {
    String::from_utf8_lossy(trim_ascii(b))
        .chars()
        .take(160)
        .collect()
}

// ------------------------------------------------------------- PE parsing

#[derive(Clone, Copy)]
struct RcData {
    id: u32,
    offset: usize,
    size: usize,
}

impl RcData {
    fn range(&self) -> Range<usize> {
        self.offset..self.offset + self.size
    }
}

/// (`virtual_address`, span, `pointer_to_raw_data`)
type Section = (usize, usize, usize);

fn rva_to_off(sections: &[Section], rva: usize) -> Option<usize> {
    sections
        .iter()
        .find(|&&(va, span, _)| va <= rva && rva < va + span.max(1))
        .map(|&(va, _, raw)| rva - va + raw)
}

/// All `RT_RCDATA` resources whose data lies entirely inside the file.
fn pe_rcdata(data: &[u8]) -> Vec<RcData> {
    fn parse(data: &[u8]) -> Option<Vec<RcData>> {
        if data.get(0..2)? != b"MZ" {
            return None;
        }
        let e = g32(data, 0x3C)? as usize;
        if data.get(e..e.checked_add(4)?)? != b"PE\0\0" {
            return None;
        }
        let coff = e + 4;
        let nsec = g16(data, coff + 2)? as usize;
        let opt_size = g16(data, coff + 16)? as usize;
        let opt = coff + 20;
        let dd_off = opt + if g16(data, opt)? == 0x10b { 96 } else { 112 };
        let res_rva = g32(data, dd_off + 2 * 8)? as usize;
        if res_rva == 0 {
            return None;
        }
        let sec_tab = opt + opt_size;
        let sections: Vec<Section> = (0..nsec)
            .map(|i| {
                let o = sec_tab + i * 40;
                let field = |k| g32(data, o + k).unwrap_or(0) as usize;
                (field(12), field(8).max(field(16)), field(20))
            })
            .collect();
        let res_off = rva_to_off(&sections, res_rva)?;
        let mut out = Vec::new();
        walk(data, res_off, &sections, res_off, 1, (0, 0), &mut out);
        Some(out)
    }

    // Resource tree is exactly three levels (type / name / language); never
    // descend further, so a malformed self-referencing tree cannot recurse.
    fn walk(
        data: &[u8],
        res_off: usize,
        sections: &[Section],
        off: usize,
        level: u32,
        (ty, id): (u32, u32),
        out: &mut Vec<RcData>,
    ) {
        let (Some(n_named), Some(n_ids)) = (g16(data, off + 12), g16(data, off + 14)) else {
            return;
        };
        for k in 0..(n_named as usize + n_ids as usize) {
            let pos = off + 16 + k * 8;
            let (Some(ent_id), Some(ent_off)) = (g32(data, pos), g32(data, pos + 4)) else {
                return;
            };
            let target = res_off + (ent_off & 0x7FFF_FFFF) as usize;
            let ty = if level == 1 { ent_id } else { ty };
            let id = if level == 2 { ent_id } else { id };
            if ent_off & 0x8000_0000 != 0 {
                if level < 3 {
                    walk(data, res_off, sections, target, level + 1, (ty, id), out);
                }
                continue;
            }
            if ty != RT_RCDATA {
                continue;
            }
            let (Some(dva), Some(dsize)) = (g32(data, target), g32(data, target + 4)) else {
                continue;
            };
            let Some(offset) = rva_to_off(sections, dva as usize) else {
                continue;
            };
            let size = dsize as usize;
            if offset
                .checked_add(size)
                .is_some_and(|end| end <= data.len())
            {
                out.push(RcData { id, offset, size });
            }
        }
    }

    parse(data).unwrap_or_default()
}

// ------------------------------------------------------------- cipher

/// XOR with the MSVC `rand()` keystream (seed 0); encrypts and decrypts.
fn lcg_xor(input: &[u8]) -> Vec<u8> {
    let mut s: u32 = 0;
    input
        .iter()
        .map(|&c| {
            s = s.wrapping_mul(0x0003_43FD).wrapping_add(0x0026_9EC3);
            // key byte = (s >> 16) & 0xFF
            c ^ s.to_le_bytes()[2]
        })
        .collect()
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

struct Script {
    rc: RcData,
    pt: Vec<u8>,
    height: Option<u32>,
}

impl Script {
    /// (offset in pt, line bytes) for every '\n'-separated line.
    fn lines(&self) -> Vec<(usize, &[u8])> {
        let mut off = 0;
        self.pt
            .split(|&b| b == b'\n')
            .map(|l| {
                let start = off;
                off += l.len() + 1;
                (start, l)
            })
            .collect()
    }
}

fn find_script(data: &[u8]) -> Option<Script> {
    pe_rcdata(data).into_iter().find_map(|rc| {
        let pt = lcg_xor(&data[rc.range()]);
        looks_like_script(&pt).then(|| {
            let height = gui_height(&pt);
            Script { rc, pt, height }
        })
    })
}

/// A `md5hex(arg, arg, ...)` line with trimmed argument spans (indices into `line`).
struct Call<'a> {
    line: &'a [u8],
    args: Vec<Range<usize>>,
}

impl<'a> Call<'a> {
    fn parse(line: &'a [u8]) -> Option<Self> {
        let start = line.iter().position(|&c| c == b'(')? + 1;
        let end = line.iter().rposition(|&c| c == b')')?;
        if start > end {
            return None;
        }
        let mut args = Vec::new();
        let (mut depth, mut in_str, mut cur) = (0i32, false, start);
        let mut stop = end;
        for i in start..end {
            match line[i] {
                b'"' => in_str = !in_str,
                _ if in_str => {}
                b'(' | b'{' => depth += 1,
                b')' | b'}' if depth == 0 => {
                    stop = i;
                    break;
                }
                b')' | b'}' => depth -= 1,
                b',' if depth == 0 => {
                    args.push(trim_range(line, cur..i));
                    cur = i + 1;
                }
                _ => {}
            }
        }
        args.push(trim_range(line, cur..stop));
        Some(Call { line, args })
    }

    fn arg(&self, i: usize) -> &'a [u8] {
        &self.line[self.args[i].clone()]
    }
}

fn has_hash(line: &[u8], hash: &[u8; 32]) -> bool {
    line.len() > 32 && line.starts_with(hash)
}

fn to_uint(b: &[u8]) -> Option<u64> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(b).ok()?.parse().ok()
}

fn gui_height(pt: &[u8]) -> Option<u32> {
    pt.split(|&b| b == b'\n')
        .filter(|l| has_hash(l, SIZE_HASH))
        .filter_map(Call::parse)
        .find_map(|c| (c.args.len() >= 2).then(|| to_uint(c.arg(1))).flatten())
        .and_then(|h| u32::try_from(h).ok())
}

fn contains_licensed(line: &[u8]) -> bool {
    line.windows(8).any(|w| w.eq_ignore_ascii_case(b"LICENSED"))
}

/// Pick the line to patch: the forced one, else the first candidate.
fn select_line(
    lines: &[(usize, &[u8])],
    force_line: Option<usize>,
) -> Result<(usize, &'static str), String> {
    if let Some(n) = force_line {
        return if n < lines.len() {
            Ok((n, "forced by --line"))
        } else {
            Err(format!(
                "--line {} is out of range (0..={})",
                n,
                lines.len() - 1
            ))
        };
    }
    let find = |pred: &dyn Fn(&[u8]) -> bool| lines.iter().position(|(_, l)| pred(l));
    find(&contains_licensed)
        .map(|i| (i, "inline LICENSED"))
        .or_else(|| find(&|l| has_hash(l, KNOWN_HASH)).map(|i| (i, "dynamic-text draw call")))
        .ok_or_else(|| "no license-draw candidate found".to_string())
}

enum PatchOutcome {
    UnknownLayout,
    NoChange,
    Patched(Vec<u8>, Vec<String>),
}

/// Neutralize one draw line. Returns patched line + human-readable changes.
fn patch_line(line: &[u8], height: Option<u32>) -> PatchOutcome {
    let Some(call) = Call::parse(line).filter(|c| c.args.len() > ARG_ALPHA) else {
        return PatchOutcome::UnknownLayout;
    };
    let mut out = line.to_vec();
    let mut changes = Vec::new();
    let mut replace = |r: Range<usize>, what: &str, new: u8| {
        let old = String::from_utf8_lossy(&line[r.clone()]);
        out[r.clone()].fill(new);
        changes.push(format!(
            "{} {}->{}",
            what,
            old,
            String::from_utf8_lossy(&out[r])
        ));
    };

    // 1) alpha -> zero, same length
    let alpha = call.arg(ARG_ALPHA);
    if to_uint(alpha).is_some() && alpha.iter().any(|&c| c != b'0') {
        replace(call.args[ARG_ALPHA].clone(), "alpha", b'0');
    }

    // 2) y1 -> all nines (same length) if that lands beyond the GUI height
    if let Some(h) = height {
        let y1 = call.arg(ARG_Y1);
        let nines = vec![b'9'; y1.len()];
        if let (Some(y), Some(n)) = (to_uint(y1), to_uint(&nines)) {
            if y <= u64::from(h) && n > u64::from(h) {
                replace(call.args[ARG_Y1].clone(), "y1", b'9');
            }
        }
    }

    if changes.is_empty() {
        PatchOutcome::NoChange
    } else {
        PatchOutcome::Patched(out, changes)
    }
}

/// Whole file with one script line replaced, re-encrypted in place.
fn rebuild(data: &[u8], script: &Script, line_start: usize, new_line: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let base = script.rc.offset + line_start;
    for (i, &b) in new_line.iter().enumerate() {
        out[base + i] ^= script.pt[line_start + i] ^ b;
    }
    out
}

/// What `--apply` would turn `data` into, if anything.
fn patched_image(data: &[u8], force_line: Option<usize>) -> Option<Vec<u8>> {
    let script = find_script(data)?;
    let lines = script.lines();
    let (idx, _) = select_line(&lines, force_line).ok()?;
    let (start, line) = lines[idx];
    match patch_line(line, script.height) {
        PatchOutcome::Patched(new_line, _) => Some(rebuild(data, &script, start, &new_line)),
        _ => None,
    }
}

// ------------------------------------------------------------- file handling

#[derive(Clone, Copy, PartialEq)]
enum Outcome {
    /// Not a target (no script resource / no backup); not counted.
    Skipped,
    WouldPatch,
    Patched,
    AlreadyPatched,
    Restored,
    Failed,
}

fn backup_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}

fn collect_pe_files(root: &Path) -> Vec<PathBuf> {
    fn walk_dir(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for p in rd.flatten().map(|e| e.path()) {
            if p.is_dir() {
                walk_dir(&p, out);
            } else if p.extension().and_then(|s| s.to_str()).is_some_and(|ext| {
                ext.eq_ignore_ascii_case("dat") || ext.eq_ignore_ascii_case("dll")
            }) {
                out.push(p);
            }
        }
    }
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    let mut out = Vec::new();
    walk_dir(root, &mut out);
    out.sort();
    out
}

/// Make sure <path>.bak holds `original`. A pre-existing backup is accepted
/// only if identical; otherwise it likely belongs to another plugin version.
fn ensure_backup(path: &Path, original: &[u8]) -> Result<(), String> {
    let bak = backup_path(path);
    match fs::read(&bak) {
        Ok(existing) if existing == original => Ok(()),
        Ok(_) => Err(format!(
            "{} exists but differs from the current file (plugin updated?). Move it away and re-run.",
            bak.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::write(&bak, original).map_err(|e| format!("backup failed: {e}"))?;
            println!("    backup written: {}", bak.display());
            Ok(())
        }
        Err(e) => Err(format!("cannot read {}: {}", bak.display(), e)),
    }
}

fn write_range(path: &Path, image: &[u8], range: Range<usize>) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new().write(true).open(path)?;
    f.seek(SeekFrom::Start(range.start as u64))?;
    f.write_all(&image[range])
}

fn patch_file(path: &Path, apply: bool, force_line: Option<usize>) -> Outcome {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            println!("[!] {}: {}", path.display(), e);
            return Outcome::Failed;
        }
    };
    let Some(script) = find_script(&data) else {
        return Outcome::Skipped;
    };
    let rc = script.rc;
    let lines = script.lines();
    println!("{}", path.display());
    println!(
        "  script resource: id={} offset={:#x} size={:#x}, {} lines, gui_height={}",
        rc.id,
        rc.offset,
        rc.size,
        lines.len().saturating_sub(1),
        script.height.map_or_else(|| "?".into(), |h| h.to_string())
    );

    let (idx, why) = match select_line(&lines, force_line) {
        Ok(v) => v,
        Err(msg) if force_line.is_some() => {
            println!("  [!] {msg}");
            return Outcome::Failed;
        }
        Err(msg) => {
            println!("  [!] {msg}. Script dump follows (--line N to force):");
            for (i, (_, ln)) in lines.iter().enumerate() {
                if !trim_ascii(ln).is_empty() {
                    println!("      {:4} {}", i, preview(ln));
                }
            }
            return Outcome::Failed;
        }
    };
    let (start, line) = lines[idx];
    println!("  candidate line {} ({}): {}", idx, why, preview(line));
    let (new_line, changes) = match patch_line(line, script.height) {
        PatchOutcome::UnknownLayout => {
            println!("    [!] unrecognized arg layout, skipped");
            return Outcome::Failed;
        }
        PatchOutcome::NoChange => {
            println!("    -> already patched (nothing to change)");
            return Outcome::AlreadyPatched;
        }
        PatchOutcome::Patched(l, c) => (l, c),
    };
    let image = rebuild(&data, &script, start, &new_line);
    if !apply {
        println!(
            "    -> would change: {} (dry run; use --apply)",
            changes.join(", ")
        );
        return Outcome::WouldPatch;
    }

    if let Err(msg) = ensure_backup(path, &data) {
        println!("    [!] {msg}");
        return Outcome::Failed;
    }
    if let Err(e) = write_range(path, &image, rc.range()) {
        println!("    [!] write failed: {e}. Close the host DAW and re-run as administrator.");
        return Outcome::Failed;
    }
    let ok = fs::read(path).is_ok_and(|d| d == image);
    let diff: Vec<String> = rc
        .range()
        .filter(|&i| data[i] != image[i])
        .map(|i| format!("{:#x}:{:02x}->{:02x}", i, data[i], image[i]))
        .collect();
    println!(
        "    patched: {} -> {}  [{}]",
        changes.join(", "),
        diff.join(", "),
        if ok { "OK" } else { "VERIFY FAILED" }
    );
    if ok {
        Outcome::Patched
    } else {
        Outcome::Failed
    }
}

/// Copy <path>.bak back, but only if patching it reproduces the current file.
fn restore_file(path: &Path, force_line: Option<usize>) -> Outcome {
    let bak = backup_path(path);
    if !bak.exists() {
        return Outcome::Skipped;
    }
    let (backup, current) = match (fs::read(&bak), fs::read(path)) {
        (Ok(b), Ok(c)) => (b, c),
        (Err(e), _) | (_, Err(e)) => {
            println!("[!] {}: {}", path.display(), e);
            return Outcome::Failed;
        }
    };
    if backup == current {
        println!("{}: already identical to backup", path.display());
        return Outcome::AlreadyPatched;
    }
    if patched_image(&backup, force_line).as_deref() != Some(current.as_slice()) {
        println!(
            "[!] {}: backup is not the unpatched form of the current file (plugin updated?); not restored",
            path.display()
        );
        return Outcome::Failed;
    }
    match fs::write(path, &backup) {
        Ok(()) => {
            println!("restored {} from {}", path.display(), bak.display());
            Outcome::Restored
        }
        Err(e) => {
            println!("[!] restore failed for {}: {}", path.display(), e);
            Outcome::Failed
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let files = collect_pe_files(&cli.path);
    if files.is_empty() {
        println!("no PE files found under {}", cli.path.display());
        return ExitCode::FAILURE;
    }

    let results: Vec<Outcome> = files
        .iter()
        .map(|f| {
            if cli.restore {
                restore_file(f, cli.line)
            } else {
                patch_file(f, cli.apply, cli.line)
            }
        })
        .filter(|&o| o != Outcome::Skipped)
        .collect();
    let count = |o: Outcome| results.iter().filter(|&&r| r == o).count();
    let failed = count(Outcome::Failed);

    println!();
    if cli.restore {
        println!(
            "done: {} restored, {} already original, {} failed.",
            count(Outcome::Restored),
            count(Outcome::AlreadyPatched),
            failed
        );
    } else {
        let (n, verb) = if cli.apply {
            (count(Outcome::Patched), "patched")
        } else {
            (count(Outcome::WouldPatch), "would patch")
        };
        println!(
            "done: {} file(s) with a script: {} {}, {} already patched, {} failed.",
            results.len(),
            n,
            verb,
            count(Outcome::AlreadyPatched),
            failed
        );
        if !cli.apply && n > 0 {
            println!("re-run with --apply to write.");
        }
    }
    if failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
