# Project Overview

`hv` is a hardware-assisted hypervisor for Windows written in Rust. It provides a thin virtualization layer that runs on both AMD (SVM) and Intel (VT-x) processors. The project compiles as a Windows kernel driver (cdylib) that runs without the Rust standard library (`#![no_std]`).

## Key Characteristics

- **No-std Rust**: Uses `#![no_std]` and `#![no_main]` for kernel-mode operation
- **Kernel Driver**: Compiles to a Windows kernel driver (`.sys` compatible)
- **Dual Architecture Support**: Supports both AMD SVM and Intel VT-x (mutually exclusive features)
- **Type 2 Hypervisor**: Runs as a driver within the host Windows OS
- **Windows Version Support**: Windows 10 2004+ and Windows 11 (up to build 27774)

# Technology Stack

## Programming Language
- **Rust Edition**: 2024
- **Toolchain**: Nightly (see `rust-toolchain.toml`)
- **Target**: `x86_64-pc-windows-msvc`

## Key Dependencies
| Crate | Purpose |
|-------|---------|
| `x86` | x86/x64 CPU intrinsics and operations |
| `raw-cpuid` | CPU feature detection |
| `hashbrown` | Hash map implementation for no-std |
| `spin` | Synchronization primitives for no-std |
| `bitflags`, `bitreader` | Bit manipulation utilities |
| `lde` | Length-Disassembler Engine |
| `goldberg` | Code obfuscation |
| `obfstr` | String obfuscation (local path dependency) |
| `rsa` | Cryptographic operations |
| `static_assertions` | Compile-time assertions |
| `thiserror-no-std` | Error handling without std |
| `derive_more` | Derive macro utilities |
| `paste` | Token pasting macros |

## Build-Time Dependencies
| Crate | Purpose |
|-------|---------|
| `pdb` | PDB parsing for symbol extraction |
| `pelite` | PE file parsing |
| `reqwest` | Downloading PDB files from Microsoft Symbol Server |
| `toml`, `serde` | Configuration parsing |

# Project Structure

## Source Organization (`src/`)

```
src/
├── lib.rs              # Entry point, hypervisor initialization
├── prelude.rs          # Common imports used across modules
├── error.rs            # Error types and Result alias
├── panic.rs            # Panic handler (calls abort)
├── allocator.rs        # Global kernel memory allocator
├── wdk.rs              # Windows Driver Kit bindings and wrappers
├── hash.rs             # Hash utilities and simple RNG
├── hypervisor/         # Core hypervisor logic
│   ├── mod.rs          # Hypervisor struct, page tables, CPU virtualization
│   └── compatibility.rs# Platform detection (Intel vs AMD)
├── amd/                # AMD SVM implementation
│   ├── mod.rs
│   ├── vcpu.rs         # VCPU setup, VMCB, vmrun/vmenter, VM exit handling
│   ├── vmcb.rs         # VMCB structure definitions, VM exit codes
│   └── instructions.rs # SVM instructions (vmrun, vmload, vmsave, stgi)
├── intel/              # Intel VT-x implementation
│   ├── mod.rs
│   ├── vcpu.rs         # VMXON, VMCS setup, VM entry, VM exit handling
│   └── instructions.rs # VMX instructions (vmxon, vmclear, vmptrld, etc.)
└── offsets/            # Auto-generated offset files (by build.rs)
    ├── mod.rs
    ├── modules.rs      # Module base addresses
    └── *.rs            # Per-module offsets (ntoskrnl, win32k, etc.)
```

## Configuration Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Package manifest, profiles, features, dependencies |
| `.cargo/config.toml` | Cargo configuration: build-std, linker scripts, target |
| `rust-toolchain.toml` | Nightly toolchain specification |
| `rustfmt.toml` | Rustfmt configuration (Unix newlines) |
| `offsets.toml` | Pattern signatures for offset extraction from binaries |
| `modules.toml` | Base addresses for Windows kernel modules |

## Build Output Directories

| Directory | Purpose |
|-----------|---------|
| `winbin/` | Windows PE binaries (input for symbol extraction) |
| `pdb/` | Downloaded PDB symbol files (cached) |
| `target/` | Build artifacts (excluded from git) |
| `src/offsets/` | Auto-generated Rust offset modules (excluded from git) |

# Build Process

## Prerequisites

1. **Rust Nightly** with components:
   - `rustfmt`
   - `rustc-dev`

2. **Cross-compilation environment**:
   - `msvc-wine-rust` or equivalent for linking Windows drivers on Linux
   - Target: `x86_64-pc-windows-msvc`

3. **Windows binaries** in `winbin/`:
   - `ntoskrnl.exe`
   - `win32k.sys`, `win32kbase.sys`, `win32kfull.sys`
   - `nvlddmkm.sys`, `dxgkrnl.sys`
   - Other drivers defined in `modules.toml`

## Build Commands

```bash
# Standard build (AMD support by default)
cargo build

# Release build (optimized)
cargo build --release

# Intel support
cargo build --features intel --no-default-features

# AMD support (explicit)
cargo build --features amd
```

## Build Script (`build.rs`)

The build process is heavily customized via `build.rs`:

1. **Reads `offsets.toml`**: Parses pattern signatures for offset discovery
2. **Reads `modules.toml`**: Loads module base addresses
3. **Processes PE files**: From `winbin/` directory
4. **Downloads PDBs**: From Microsoft Symbol Server (msdl.microsoft.com)
5. **Extracts symbols**: Functions, exports, and global variables
6. **Pattern matching**: Searches for byte patterns in binary code
7. **Generates `src/offsets/`**: Rust modules with offset constants
8. **Windows version detection**: Sets `win10` or `win11` feature flags based on `NtBuildNumber`

### Environment Variables

- `WINBIN_INPUT`: Override path to Windows binaries (default: `winbin/`)
- `MODULES_INPUT`: Override path to modules.toml (default: `modules.toml`)

## Feature Flags

| Feature | Description |
|---------|-------------|
| `amd` | AMD SVM support (default) |
| `intel` | Intel VT-x support |
| `kvm` | Running inside KVM (adjusts TLB flush behavior) |
| `win10` | Windows 10 specific code paths (auto-set by build.rs) |
| `win11` | Windows 11 specific code paths (auto-set by build.rs) |

**Note**: `amd` and `intel` features are mutually exclusive. Build will fail if both are enabled.

# Architecture

## Hypervisor Flow

1. **Entry Point** (`entry` in `lib.rs`):
   - Initialize module system (`Module::init()`)
   - Detect platform (Intel/AMD)
   - Check hardware compatibility
   - Create hypervisor instance
   - Virtualize all CPUs

2. **CPU Virtualization** (`Hypervisor::virtualize_cpu`):
   - Allocate VCPU structure
   - Capture current context
   - Enable virtualization (SVM/VMX)
   - Setup VCPU
   - Enter guest mode

3. **VM Exits**:
   - AMD: `handle_vmexit` in `amd/vcpu.rs`
   - Intel: VM exits handled via VMCS
   - Currently minimal handling (mostly passes through)

## Memory Management

- **Page Allocator**: Uses Windows `MmAllocateIndependentPagesEx`
- **Global Allocator**: Kernel pool with randomized pool tag
- **Page Tables**: Built for both primary and shadow (AMD) / EPT (Intel)
- **Large Pages**: 2MB large page support for efficient memory mapping

## Key Data Structures

| Structure | Purpose |
|-----------|---------|
| `Hypervisor` | Central hypervisor state, page table management |
| `VCpu` | Virtual CPU state (architecture-specific) |
| `Vmcb` (AMD) | Virtual Machine Control Block |
| `Vmcs` (Intel) | Virtual Machine Control Structure |
| `GuestRegisters` | Saved guest register state |
| `KTrapFrame` | Windows KTRAP_FRAME for debugging |

# Development Conventions

## Code Style

- **Newline style**: Unix (`\n`) - enforced by rustfmt.toml
- **Formatting**: Use `cargo fmt` before committing
- **Imports**: Use `prelude.rs` for common imports
- **Safety**: Heavy use of `unsafe` for kernel operations; marked explicitly

## Naming Conventions

- Module offsets: `snake_case` (e.g., `NtBuildNumber`)
- Signatures: Patterns in `offsets.toml` use IDA-style hex (e.g., `48 8B 05 ? ? ? ?`)
- VMCB/VMCS fields: Follow hardware manual naming

## Unsafe Code Guidelines

- All hardware access is `unsafe`
- Raw pointer operations marked with `unsafe` blocks
- Transmute used for kernel function pointers
- Inline assembly for privileged operations

## Comments and Documentation

- Hardware structures reference Intel/AMD manual sections
- VMCB layout references "Table B-1" from AMD manual
- VMCS fields reference Intel SDM

# Testing and Debugging

## Testing Strategy

- **No unit tests**: This is a kernel driver with hardware dependencies
- **Manual testing**: Load driver in VM, verify virtualization
- **Compatibility**: Test on both Intel and AMD hardware

## Debugging

- **Debug prints**: Use `println!` or `dbg!` macros (output via `DbgPrintEx`)
- **Windbg**: KTrapFrame allows stack reconstruction
- **Serial output**: Can be configured for debugging

## Supported Platforms

| Platform | Minimum Version | Maximum Version |
|----------|----------------|-----------------|
| Windows 10 | 2004 (build 19041) | - |
| Windows 11 | 22000 | 27774 (25H2 Insider) |

# Security Considerations

## Obfuscation Features

- **String obfuscation**: `obfstr` crate for compile-time string encryption
- **Code obfuscation**: `goldberg` crate for control flow obfuscation
- **Randomized pool tags**: Allocation tag randomized per build
- **Control Flow Guard**: Disabled in release builds (`-Ccontrol-flow-guard=off`)

## Kernel Safety

- Runs in kernel mode (Ring 0)
- Modifies critical CPU state (CR0, CR4, EFER)
- Can cause system crashes if misconfigured
- Proper IRQL management required

## Build Security

- Downloads PDBs from Microsoft Symbol Server (HTTPS)
- Verifies PE checksums
- Validates Windows version at build time

# Deployment

## Output

- Release binary: `target/x86_64-pc-windows-msvc/release/hv.dll` (rename to `.sys`)
- Debug symbols: `.pdb` file generated

## Loading

The driver can be loaded using standard Windows driver loading mechanisms:
- `sc create` / `sc start`
- Manual driver loading tools
- Kernel exploit for unsigned driver loading (for testing)

## Runtime Requirements

- Windows 10 2004+ or Windows 11
- AMD processor with SVM support OR Intel processor with VT-x support
- Administrator privileges (for driver loading)
- Test signing mode or valid driver signature (for production)

# Important Notes

1. **Offset Files**: The `src/offsets/` directory is auto-generated by `build.rs`. Do not manually edit these files.

2. **Windows Binaries**: The `winbin/` directory must contain valid Windows PE files for the target Windows version.

3. **PDB Cache**: The `pdb/` directory caches downloaded symbols. Can be safely deleted to force re-download.

4. **Mutual Exclusivity**: `amd` and `intel` features are mutually exclusive. Build will fail if both are enabled.

5. **Cross-compilation**: This project is designed to be cross-compiled from Linux to Windows using msvc-wine.
