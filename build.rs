#![feature(map_try_insert)]

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::File;
// use std::io::Read;

use pdb::FallibleIterator;
use pelite::FileMap;
use pelite::pe64::debug::Entry;
use pelite::pe64::{Pe, PeFile};
use reqwest::blocking::Client;
use serde::Deserialize;
// use toml::Table;

fn get_pdb_info(pe: &PeFile) -> Result<(String, String), Box<dyn std::error::Error>> {
    // Get debug directory
    for entry in pe.debug()? {
        if let Ok(Entry::CodeView(cv)) = entry.entry()
            && let Some(debug_data) = entry.data()
        {
            // Extract GUID (16 bytes after "RSDS" signature)
            let guid_bytes = &debug_data[4..20];

            let l0 = u16::from_be_bytes(guid_bytes[10..12].try_into()?);
            let l1 = u16::from_be_bytes(guid_bytes[12..14].try_into()?);
            let l2 = u16::from_be_bytes(guid_bytes[14..16].try_into()?);
            let total_l = ((l0 as u64) << (4 * 8)) | ((l1 as u64) << (2 * 8)) | (l2 as u64);

            let guid = format!(
                "{:08X}{:04X}{:04X}{:04X}{:012X}",
                u32::from_le_bytes(guid_bytes[0..4].try_into()?),
                u16::from_le_bytes(guid_bytes[4..6].try_into()?),
                u16::from_le_bytes(guid_bytes[6..8].try_into()?),
                u16::from_be_bytes(guid_bytes[8..10].try_into()?),
                total_l,
            );

            // Extract PDB filename (null-terminated after GUID + age)
            let age = cv.age();
            let pdb_filename = cv.pdb_file_name();

            return Ok((
                guid.clone(),
                format!(
                    "https://msdl.microsoft.com/download/symbols/{pdb_filename}/{guid}{age:x}/{pdb_filename}"
                ),
            ));
        }
    }

    Err(format!("No PDB found on MSDL servers").into())
}

fn download_pdb(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(Client::new()
        .get(url)
        .header("User-Agent", "Microsoft-Symbol-Server/6.11.0001.402")
        .send()?
        .bytes()?
        .to_vec())
}

fn walk_symbols_with_offsets(
    pdb: &mut pdb::PDB<'_, File>,
    mut symbols: pdb::SymbolIter<'_>,
    differentiate_functions: bool,
) -> Option<Vec<(u32, String)>> {
    let mut result = Vec::new();
    while let Some(symbol) = symbols.next().ok()? {
        if let Some(value) = dump_symbol_with_offsets(pdb, &symbol, differentiate_functions) {
            result.push(value);
        }
    }

    Some(result)
}

pub fn extract_symbols_with_offset(
    pdb: &mut pdb::PDB<'_, File>,
    differentiate_functions: bool,
) -> Option<BTreeMap<u32, String>> {
    let mut symbols = Vec::new();

    // Global symbols
    let symbol_table = pdb.global_symbols().ok()?;
    symbols.append(&mut walk_symbols_with_offsets(
        pdb,
        symbol_table.iter(),
        differentiate_functions,
    )?);

    // Modules' private symbols
    let dbi = pdb.debug_information().ok()?;
    let mut modules = dbi.modules().ok()?;

    while let Some(module) = modules.next().ok()? {
        let info = match pdb.module_info(&module).ok()? {
            Some(info) => info,
            None => {
                continue;
            }
        };

        symbols.append(&mut walk_symbols_with_offsets(
            pdb,
            info.symbols().ok()?,
            differentiate_functions,
        )?);
    }

    // TODO: number the symbols with same name instead of this
    // remove duplicate symbols
    symbols.dedup_by(|a, b| a.1 == b.1);

    Some(symbols.into_iter().collect())
}

fn dump_symbol_with_offsets(
    pdb: &mut pdb::PDB<'_, File>,
    symbol: &pdb::Symbol<'_>,
    differentiate_functions: bool,
) -> Option<(u32, String)> {
    // println!("cargo:warning={:?}", pdb.sections());
    let addr_map = pdb.address_map().ok()?;

    match symbol.parse().ok()? {
        // Public symbols?
        pdb::SymbolData::Public(data) => Some(if data.function {
            (
                data.offset.to_rva(&addr_map).unwrap_or_default().0,
                // Add parenthese to distinguish functions from global variables
                if differentiate_functions {
                    format!("{}()", data.name)
                } else {
                    let name = data.name.to_string();
                    let name = name.trim_end_matches("()").to_owned();
                    let name = name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");

                    // if name.contains("ProcessMouseInputData") {
                    //     //     // pdb.sections().unwrap().iter().find(|x| x.)
                    //     let rva = data.offset.to_rva(&pdb.address_map().unwrap());
                    //     println!("cargo:warning={:X?}", rva);
                    //     //     println!(
                    //     //         "cargo:warning=a {name} {:X?}",
                    //     //         data.offset.to_rva(&addr_map)
                    //     //     );
                    // }

                    name
                },
            )
        } else {
            (data.offset.to_rva(&addr_map).unwrap_or_default().0, {
                let name = data.name.to_string();
                let name = name.trim_end_matches("()").to_owned();
                let name = name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");

                // if name.contains("ProcessMouseInputData") {
                //     println!("cargo:warning=b {name}");
                // }

                name
            })
        }),
        // Global variables
        pdb::SymbolData::Data(data) => {
            Some((data.offset.to_rva(&addr_map).unwrap_or_default().0, {
                let name = data.name.to_string();
                let name = name.trim_end_matches("()").to_owned();
                let name = name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");

                // if name.contains("ProcessMouseInputData") {
                //     println!("cargo:warning=c {name}");
                // }

                name
            }))
        }
        // Functions and methods
        pdb::SymbolData::Procedure(data) => Some((
            data.offset.to_rva(&addr_map).unwrap_or_default().0,
            // Add parenthese to distinguish functions from global variables
            if differentiate_functions {
                format!("{}()", data.name)
            } else {
                let name = data.name.to_string();
                let name = name.trim_end_matches("()").to_owned();
                let name = name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");

                // if name.contains("ProcessMouseInputData") {
                //     println!("cargo:warning=d {name}");
                // }

                name
            },
        )),
        _ => {
            // ignore everything else
            None
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Offset {
    pub start: Option<String>,
    pub patterns: Vec<String>,
    pub add: Option<isize>,
    pub extra: Option<isize>,
    pub read: Option<usize>,
    pub rip: Option<bool>,
}

fn ida_signature_to_vec(signature: &str) -> Vec<Option<u8>> {
    let signature_minified = signature.to_owned().replace("?", "??").replace(" ", "");

    signature_minified
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            if chunk.len() == 2 {
                if chunk[0] == b'?' && chunk[1] == b'?' {
                    None
                } else if chunk[0] == b'?' {
                    panic!("Signature `{signature}` doesnt match expected format");
                } else {
                    // println!("{:?}", &chunk);
                    Some(u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
                }
            } else {
                panic!("Signature `{signature}` doesnt match expected format");
            }
        })
        .collect()
}

fn find_pattern(bytes: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
    // Construct slice from range of addresses
    bytes
        // Divide the possible locations of the sig into subsections with len of pattern
        .windows(pattern.len())
        // Check if each subsection contains/is eq to the pattern
        .position(|window| {
            for i in 0..pattern.len() {
                // We have a wildcard -- Ignore this byte
                match pattern[i] {
                    Some(b) => {
                        if window[i] != b {
                            return false;
                        }
                    }
                    None => {}
                }
            }

            true
        })
}

// sig_offsets.push_str("pub mod sigs {\n");
// code_offsets.push_str("pub mod code {\n");
// export_offsets.push_str("pub mod exports {\n");
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=offsets.toml");

    let offsets_file = std::fs::read_to_string("offsets.toml")?;
    let t = toml::from_str::<HashMap<String, HashMap<String, Offset>>>(&offsets_file)?;

    // dbg!(&t);

    // let offsets = |module_name: &str| -> Option<&HashMap<String, Offset>> {
    //     t.iter()
    //         .find(|(cur_module_name, _)| module_name == *cur_module_name)
    //         .and_then(|m| Some(m.1))
    // };
    let offsets_for_symbol = |symbol: &str, module_name: &str| -> Option<Vec<(&String, &Offset)>> {
        t.iter().find_map(|(cur_module_name, items)| {
            if module_name == *cur_module_name {
                let mut offsets_for_symbol = items
                    .iter()
                    .filter(|x| x.1.start.as_ref().map_or(true, |x| symbol.starts_with(x)))
                    .collect::<Vec<_>>();

                if offsets_for_symbol.is_empty() {
                    None
                } else {
                    if let Some(s) = offsets_for_symbol.iter().find(|x| x.0 == symbol) {
                        offsets_for_symbol = vec![*s];
                    }

                    Some(offsets_for_symbol)
                }
            } else {
                None
            }
        })
    };

    // for (module, offsets) in t {
    //     for (name, offset) in offsets {
    //         println!("{module} {name} {offset:X?}");
    //     }
    // }

    // return Ok(());

    let _ = std::fs::create_dir("winbin/");
    let _ = std::fs::create_dir("pdb/");
    let _ = std::fs::create_dir("src/offsets/");

    let mut base_mod = String::new();
    let mut module_bases_mod = String::new();

    let winbin_path = env::var("WINBIN_INPUT").unwrap_or("winbin/".into());
    let modules_path = env::var("MODULES_INPUT").unwrap_or("modules.toml".into());

    println!("cargo:rerun-if-changed={winbin_path}");
    println!("cargo:rerun-if-changed={modules_path}");

    let modules_file = std::fs::read_to_string(modules_path).expect("Failed to read modules.toml");
    let modules_toml =
        toml::from_str::<toml::Value>(&modules_file).expect("Failed to parse modules.toml");
    let modules_table = modules_toml["modules"]
        .as_table()
        .expect("Failed to locate module table in offsets.toml");

    for (module_name, module_address) in modules_table {
        let module_address = u64::from_ne_bytes(module_address.as_integer().unwrap().to_ne_bytes());

        module_bases_mod.push_str(&format!(
            "pub const {}: usize = 0x{module_address:X};\n",
            module_name.to_uppercase()
        ));
    }

    if !module_bases_mod.is_empty() {
        base_mod.push_str(&format!("pub mod modules;\n"));
        let _ = std::fs::write("src/offsets/modules.rs", module_bases_mod)?;
    }

    // Parse PE file
    for entry in std::fs::read_dir(winbin_path)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let map = FileMap::open(&path)?;
        let file = PeFile::from_bytes(&map)?;
        let headers = file.headers();
        // let checksum = headers.pe().nt_headers().FileHeader.TimeDateStamp;
        let mut checksum = headers.pe().rich_structure().unwrap().checksum();
        let checksum_key = headers.pe().rich_structure().unwrap().xor_key();

        let base_name = path
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
            .to_lowercase();

        // if base_name.contains("nvlddmkm") {
        //     println!("cargo:warning={base_name} {checksum:X}");
        // }

        if checksum != checksum_key {
            checksum = headers.pe().nt_headers().FileHeader.TimeDateStamp;
            // dbg!(path);
            // panic!("PE header has been tampered {checksum:X}");
            // continue;
        }

        base_mod.push_str(&format!("pub mod {base_name};\n"));

        let mut symbols = if let Ok((_pdb_uuid, pdb_url)) = get_pdb_info(&file) {
            let _ = std::fs::create_dir(format!("pdb/{base_name}"));

            let pdb_path = format!("pdb/{base_name}/{checksum:X}");

            // download symbols if we dont have them already
            if !std::fs::exists(&pdb_path)? {
                let pdb_raw = download_pdb(&pdb_url)?;
                let _ = std::fs::write(&pdb_path, pdb_raw)?;
            }

            let pdb_file = std::fs::File::open(&pdb_path)?;
            if let Ok(mut pdb) = pdb::PDB::open(pdb_file) { 
                extract_symbols_with_offset(&mut pdb, false).unwrap()
            } else {
                BTreeMap::new()
            }
        } else {
            BTreeMap::new()
        };

        file.exception().unwrap().functions().for_each(|f| {
            // symbols
            let rva = f.image().BeginAddress;
            let _ = symbols.try_insert(
                rva,
                format!(
                    "sub_{:X}",
                    file.nt_headers().OptionalHeader.ImageBase as usize + rva as usize
                ),
            );
        });

        let mut code_offsets = String::new();
        let mut offsets = String::new();
        let mut sig_offsets = String::new();
        // let mut export_offsets = String::new();
        sig_offsets.push_str("pub mod sigs {\n");
        code_offsets.push_str("pub mod code {\n");
        // export_offsets.push_str("pub mod exports {\n");
        // export_offsets.push_str("}\n");
        let mut raw_export_offsets = Vec::new();

        // dump exports offsets
        if let Ok(exports) = file.exports() {
            exports
                .by()
                .unwrap()
                .iter_names()
                .for_each(|(name, export)| {
                    if let Ok(name) = name
                        && let Ok(export) = export
                        && let Some(rva) = export.symbol()
                    {
                        let simple_name = name.to_string().trim_end_matches("()").to_owned();
                        let simple_name =
                            simple_name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");

                        raw_export_offsets.push((rva, simple_name.clone()));
                        // export_offsets.push_str(&format!(
                        //     "    pub const {simple_name}: usize = 0x{rva:X};\n"
                        // ));
                    }
                });
        }

        // if let Some(symbols) = &mut symbols {
        // combine export offsets with symbols for search
        for (offset, name) in raw_export_offsets {
            let simple_name = name.trim_end_matches("()").to_owned();
            let simple_name = simple_name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");

            // insert only if symbol with same name doesnt yet exist
            // if !symbols.iter().any(|(_, s)| s == &simple_name) {
            let _ = symbols.try_insert(offset, simple_name);
            // }
        }

        // remove duplicate symbol names
        let mut created_offsets: HashMap<String, i32> = HashMap::new();
        // symbols.retain(|offset, name| symbols.iter().any(|s1| s1.1 == name));

        for (offset, name) in symbols {
            // if offset == 0 {
            //     offset = 0x1000;
            // }

            // let is_function = name.ends_with("()");
            let simple_name = name.trim_end_matches("()").to_owned();
            let simple_name = simple_name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
            let mut has_sig_offset = false;

            // if is_function {
            // we have an offset referencing this symbol. resolve it
            if let Some(offsets) = &offsets_for_symbol(&simple_name, &base_name) {
                // println!("{name} {offsets:?}");
                for (name, offset_info) in offsets {
                    for (i_pattern, pattern) in offset_info.patterns.iter().enumerate() {
                        // let pattern_s = pattern;
                        let pattern = ida_signature_to_vec(pattern);
                        let image_base = file.optional_header().ImageBase;
                        // println!("cargo:warning={image_base:X}");

                        // if simple_name.contains("ProcessMouseInputData") {
                        //     println!("cargo:warning={name:?} {simple_name:?}");
                        // }

                        // println!("cargo:warning={base_name} {simple_name} {name} {offset:X}");
                        let view = match file.read_bytes(image_base + offset as u64) {
                            Ok(x) => x,
                            Err(_) => continue,
                        };
                        let view = &view[..view.len().min(0x1000)];
                        // let view = &view[..view.len().min(350)];

                        let offset_from_view = match find_pattern(view, &pattern) {
                            Some(offset) => offset,
                            None => {
                                if i_pattern == offset_info.patterns.len() - 1
                                    && offset_info.start.as_ref().is_some()
                                {
                                    // println!(
                                    //     "cargo:warning={simple_name}, {base_name}, {offsets:#?}"
                                    // );

                                    // break;
                                    // panic!("Pattern not found for offset `{name}`: `{pattern_s}`");
                                    continue;
                                } else {
                                    continue;
                                }
                            }
                        };

                        let mut total_va = offset as usize + offset_from_view;

                        if let Some(add) = offset_info.add {
                            total_va = total_va.wrapping_add_signed(add);
                        }

                        if matches!(offset_info.rip, Some(true))
                            && let Ok(rip_offset) = file.read(image_base + total_va as u64, 4, 1)
                        {
                            let rip_offset =
                                i32::from_le_bytes(rip_offset[0..4].try_into().unwrap()) as isize;
                            total_va = total_va.wrapping_add_signed(rip_offset) + size_of::<i32>();
                        }

                        if let Some(read_bits_count) = offset_info.read {
                            let read_bytes_count = read_bits_count / 8;
                            let read_bytes = &file
                                .read_bytes(image_base + (total_va as u64))
                                .unwrap()[..read_bytes_count];

                            let extra = offset_info.extra.unwrap_or(0);

                            let read_s = match read_bits_count {
                                8 => format!(
                                    "u8 = 0x{:X}",
                                    u8::from_ne_bytes(read_bytes.try_into().unwrap())
                                        .wrapping_add_signed(extra as _)
                                ),
                                16 => format!(
                                    "u16 = 0x{:X}",
                                    u16::from_ne_bytes(read_bytes.try_into().unwrap())
                                        .wrapping_add_signed(extra as _)
                                ),
                                32 => {
                                    let value = u32::from_ne_bytes(read_bytes.try_into().unwrap())
                                        .wrapping_add_signed(extra as _);

                                    // set windows version according to global NtBuildNumber system value
                                    if *name == "NtBuildNumber" {
                                        // this was the creators update
                                        // where they added things like the advanced dwm composition,
                                        pub const WIN10_2004_BUILD_NUMBER: u32 = 19041;
                                        // w32k driver stack changed massively in win11
                                        pub const MIN_WIN11_BUILD_NUMBER: u32 = 22000;
                                        // pub const MAX_WIN11_BUILD_NUMBER: u32 = 26100;
                                        // win11 25H2 insider preview build no. 27774
                                        pub const MAX_WIN11_BUILD_NUMBER: u32 = 27774;

                                        let build_number = value & 0x00FFFFFF;

                                        if build_number > MAX_WIN11_BUILD_NUMBER {
                                            panic!(
                                                "Windows version is too new (unsupported {build_number})"
                                            );
                                        } else if build_number >= MIN_WIN11_BUILD_NUMBER {
                                            println!("cargo:rustc-cfg=feature=\"win11\"");
                                        }
                                        // minimum supported version
                                        else if build_number >= WIN10_2004_BUILD_NUMBER {
                                            println!("cargo:rustc-cfg=feature=\"win10\"");
                                        } else {
                                            panic!(
                                                "Windows version is too old (unsupported {build_number})"
                                            );
                                        }
                                    }

                                    format!("u32 = 0x{value:X}")
                                }
                                64 => format!(
                                    "u64 = 0x{:X}",
                                    u64::from_ne_bytes(read_bytes.try_into().unwrap())
                                        .wrapping_add_signed(extra as _)
                                ),
                                _ => panic!("Unknown read size for pattern {name}"),
                            };

                            if !sig_offsets.contains(&format!("pub const {name}:")) {
                                let name = if name.is_empty() {
                                    "unk"
                                }
                                else {
                                    &name
                                };

                                has_sig_offset = true;
                                sig_offsets.push_str(&format!("    pub const {name}: {read_s};\n"));
                            }
                        } else {
                            if let Some(extra) = offset_info.extra {
                                total_va = total_va.wrapping_add_signed(extra);
                            }

                            if !sig_offsets.contains(&format!("pub const {name}:")) {
                                let name = if name.is_empty() {
                                    "unk"
                                }
                                else {
                                    &name
                                };

                                has_sig_offset = true;
                                sig_offsets.push_str(&format!(
                                    "    pub const {name}: usize = 0x{total_va:X};\n"
                                ));
                            }
                        }
                    }
                }
            }
            // }

            // if is_function {
            //     code_offsets.push_str(&format!(
            //         "    pub const {simple_name}: usize = 0x{offset:X};\n"
            //     ));
            // } else {
            if !has_sig_offset && created_offsets.try_insert(simple_name.clone(), 0).is_ok() {
                let name = if simple_name.is_empty() {
                    "unk"
                }
                else {
                    &simple_name
                };

                offsets.push_str(&format!("pub const {name}: usize = 0x{offset:X};\n"));
            }
            // }
        }
        // }

        sig_offsets.push_str("}\n");
        code_offsets.push_str("}\n");

        // offsets.push_str("\n");
        // offsets.push_str(&code_offsets);
        offsets.push_str("\n");
        offsets.push_str(&sig_offsets);
        // offsets.push_str("\n");
        // offsets.push_str(&export_offsets);

        let _ = std::fs::write(format!("src/offsets/{base_name}.rs"), &offsets)?;
    }

    let _ = std::fs::write(format!("src/offsets/mod.rs"), &base_mod)?;

    // std::fs::write("db/", contents)
    // let _ = download_pdb(&pdb_url)?;

    // println!("Hello, world!");

    Ok(())
}

