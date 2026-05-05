# EdgeDump

Beacon Object File (BOF) for extracting Microsoft Edge saved credential artifacts from the main `msedge.exe` process during authorized testing.

## Overview

EdgeDump scans the primary Microsoft Edge process memory for saved credential patterns that may be present in plaintext while Edge is running.

It does not read browser files directly, access SQLite databases, or use DPAPI. The project is intended for lab validation, red-team assessments, and defensive exposure testing.

## Build

### BOF

```bash
make
```

or:

```bash
x86_64-w64-mingw32-gcc -c -DBOF -Wall -O2 edgedump.c -o edgedump.x64.o
```

### Standalone EXE

```bash
make exe
```

or:

```bash
x86_64-w64-mingw32-gcc -Wall -O2 edgedump.c -o edgedump.exe -lkernel32
```

## Usage

```
execute bof edgedump.x64.o
```

Example output:

<img width="803" height="237" alt="image" src="https://github.com/user-attachments/assets/7947a3b3-d938-4322-9707-dbe23ff56987" />

## Requirements

- Edge does **not** need to be an active process credentials are loaded into memory at startup and persist for the session, even for sites the user never visits.
- Same-user context is sufficient to read the current user's Edge process.
- Elevated (admin) context can read Edge processes across all logged-on and disconnected user sessions on the same host, particularly impactful on terminal servers, RDS, and VDI environments.
- Windows target with BOF-compatible execution support.

## How It Works

At a high level, EdgeDump:

1. Finds the main `msedge.exe` process.
2. Opens the process with memory-read permissions.
3. Scans readable memory regions for Edge credential patterns.
4. Deduplicates matching results.
5. Prints discovered URL, username, and password entries.

## Files

```
edgedump.c    - source code
beacon.h      - BOF API header
Makefile      - BOF and EXE build targets
```
BOF API Header courtesy of [Adaptix Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit)

## Limitations

- Results depend on what is present in process memory at runtime.
- This project targets Microsoft Edge only.
- Output may vary by Edge version, Windows version, and process state.
- Maximum result limits may apply depending on the build configuration.

## References

Thanks to the original author and research that inspired this project:

- Original discovery / C# PoC: [L1v1ng0ffTh3L4N - EdgeSavedPasswordsDumper](https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper)

## Disclaimer

This project is intended for authorized security testing, lab research, and defensive validation only. Do not use it against systems or users without explicit permission.
