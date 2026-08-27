# hv
- This is a lightweight hardware-assisted bluepill type 2 hypervisor for Windows written in Rust, designed to be loaded particularly as a manual mapped kernel module after boot and system initializiation phase.
- Currently only has partial functionality on AMD (SVM), but Intel (VT-x) functionality is planned in the future.
- Tested to support Windows 10 2004+ and Windows 11 (up to build 27774)

## License
MIT [LICENSE](LICENSE)

## Details
- Uses no-std rust completely and minimal/constrained use of winkernel APIs to maximize contained operation
- Optimized handler layout to ensure efficient VMEXIT processing
- Compiles to kernel driver, making loading at runtime easy

## Usage and Installation
1. Download source code and open terminal in directory
2. Create winbin directory
3. Collect windows binaries listed in modules.toml from C:\Windows\System32\drivers and put into winbin folder
4. Compile in release mode using command: cargo build --release
5. Load driver using a driver manual mapper (can be found on github or internet)
