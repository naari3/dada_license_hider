# dada_license_hider

Hides the "LICENSED BY ..." line drawn in the GUI of some Dada Life / Tailored Noise plugins.

Tested on:

- Endless Smile 1.3.1 (VST3, 32/64-bit)
- Sausage Fattener 1.4.1 (VST3, 64-bit)

Generic Rbass and NimbleKick don't have a matching script resource, so they are skipped.

## Build

```
cargo build --release
```

The binary ends up in `target/release/dada_license_hider.exe`.

## Usage

```
dada_license_hider <path> [--apply] [--line N]
dada_license_hider <path> --restore
```

`<path>` can be a `.vst3` bundle, a directory (scanned recursively for `*.dat` / `*.dll`), or a single file.

Without `--apply` it only prints what it would change:

```
dada_license_hider "C:\Program Files\Common Files\VST3\Endless Smile.vst3"
```

Then write it:

```
dada_license_hider "C:\Program Files\Common Files\VST3\Endless Smile.vst3" --apply
```

Close the DAW first. Under `Program Files` you probably need an elevated shell.

Each patched file gets a `<file>.bak` next to it. `--restore` copies those back.

If the tool picks the wrong line, the dry run prints the candidate line number; pass another one with `--line N`. When no candidate is found it dumps the whole script so you can pick one.

## How it works

The plugin GUI is a small script stored as an RT_RCDATA resource in `Loader 32.dat` / `Loader 64.dat` (which are PE files). It is XORed with the MSVC `rand()` keystream, seed 0.

Each script line looks like `<md5>(arg, arg, ...)`. The license text is drawn by the line containing `LICENSED`, or, if the text is filled in at runtime, by the line with hash `c6299f5f10d1735af9684a93f124eb23`. That line gets:

- alpha set to `0` (`90` -> `00`)
- y1 set to all nines (`870` -> `999`) if that is below the GUI height

Both edits keep the same length, so the resource size does not change and only a handful of bytes in the file differ.

## Backups and plugin updates

An existing `.bak` is only reused if it is identical to the file being patched. `--restore` only writes a `.bak` back if patching it gives exactly the current file. So if you update the plugin and an old `.bak` is still lying around, both commands stop with an error instead of mixing versions. Delete or move the old `.bak` and run again.
