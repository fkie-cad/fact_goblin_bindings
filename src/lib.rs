use anyhow::anyhow;
use derive_more::Display;
use goblin::{
    container::Endian,
    elf::{Elf, ProgramHeader, SectionHeader},
};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::collections::BTreeMap;

/// A parsing error.
#[derive(Debug, Display)]
struct ParsingError(anyhow::Error);

impl From<ParsingError> for PyErr {
    fn from(error: ParsingError) -> Self {
        PyRuntimeError::new_err(error.to_string())
    }
}

impl<T: Send + Sync + 'static + std::error::Error> From<T> for ParsingError {
    fn from(error: T) -> Self {
        ParsingError(anyhow::Error::from(error))
    }
}

/// Parsed headers and other information from an ELF file.
///
/// Usage:
/// ```
/// with open("/path/to/binary", "rb") as file:
///     binary = file.read()
/// elf_file = ElfFile(binary)
/// print(elf_file.header)
/// ```
///
/// Notes:
/// - The constructor expects the binary content as Python `bytes`.
/// - The lists of exported and imported functions are lexicographically sorted.
#[pyclass(frozen, get_all)]
struct ElfFile {
    /// The name as a shared object, if applicable.
    soname: Option<String>,
    /// The interpreter.
    interpreter: Option<String>,
    /// Libraries needed by the binary.
    libraries: Vec<String>,
    /// A list of runtime search paths for dynamic libraries used by the binary, if there are any.
    runpaths: Vec<String>,
    /// The ELF header.
    header: BTreeMap<&'static str, String>,
    /// The program headers of the ELF file.
    program_headers: Vec<BTreeMap<&'static str, String>>,
    /// The section headers of the ELF file.
    /// May not be present for stripped binaries.
    section_headers: Vec<BTreeMap<&'static str, String>>,
    /// dynamic symbols of the ELF file.
    dynamic_symbols: Vec<BTreeMap<&'static str, String>>,
    /// A lexicographically sorted list of all functions imported by the ELF file.
    imported_functions: Vec<String>,
    /// A lexicographically sorted list of all function exported by the ELF file.
    exported_functions: Vec<String>,
    /// The md5-sum over the list of imported functions.
    imphash: String,
}

/// The public methods accessible from Python.
#[pymethods]
impl ElfFile {
    /// Parse an ELF file. The constructor expects the file contents as a bytes-array as input.
    #[new]
    fn new(file_content: &[u8]) -> Result<Self, ParsingError> {
        // We catch panics here and transform them to `ParsingError`.
        // This way all regular errors and panics generated from this function
        // will generate the same type of exception on the Python side.
        match std::panic::catch_unwind(|| {
            let parsed_elf = Elf::parse(file_content)?;
            let mut elf_file = Self::new_unparsed();

            elf_file.parse_general_information(&parsed_elf);
            elf_file.parse_header(&parsed_elf);
            elf_file.parse_program_headers(&parsed_elf);
            elf_file.parse_section_headers(&parsed_elf);
            elf_file.parse_dyn_symbols(&parsed_elf);

            Ok(elf_file)
        }) {
            Ok(result) => result,
            Err(_err) => Err(ParsingError(anyhow!("Panic in fact_goblin_bindings."))),
        }
    }
}

/// Private methods only accessible in Rust
impl ElfFile {
    /// Create a new `ElfFile` object containing no information.
    fn new_unparsed() -> Self {
        ElfFile {
            soname: None,
            interpreter: None,
            libraries: Vec::new(),
            runpaths: Vec::new(),
            header: BTreeMap::new(),
            program_headers: Vec::new(),
            section_headers: Vec::new(),
            dynamic_symbols: Vec::new(),
            imported_functions: Vec::new(),
            exported_functions: Vec::new(),
            imphash: String::new(),
        }
    }

    /// Parse general information (like the `soname` if present) from the ELF file.
    fn parse_general_information(&mut self, elf: &Elf) {
        self.soname = elf.soname.map(|s| s.to_string());
        self.interpreter = elf.interpreter.map(|s| s.to_string());
        self.libraries = elf.libraries.iter().map(|s| s.to_string()).collect();
        self.runpaths = elf.runpaths.iter().map(|s| s.to_string()).collect();
    }

    /// Parse dynamic symbols from the ELF file.
    /// Additionally, generate lexicographically sorted lists of all imported and exported functions
    /// and compute a hash over all imported functions.
    fn parse_dyn_symbols(&mut self, elf: &Elf) {
        for symbol in elf.dynsyms.iter() {
            let sym = BTreeMap::from([
                ("Address", hex(symbol.st_value)),
                (
                    "Bind",
                    goblin::elf::sym::bind_to_str(symbol.st_bind()).to_string(),
                ),
                (
                    "Type",
                    goblin::elf::sym::type_to_str(symbol.st_type()).to_string(),
                ),
                (
                    "Visibility",
                    goblin::elf::sym::visibility_to_str(symbol.st_visibility()).to_string(),
                ),
                (
                    "Symbol",
                    get_symbol_name(elf, symbol.st_name).unwrap_or("".to_string()),
                ),
                ("Size", hex(symbol.st_size)),
                ("Other", hex(symbol.st_other)),
            ]);
            self.dynamic_symbols.push(sym);

            if symbol.is_function() {
                let symbol_name = if let Some(symbol_name) = get_symbol_name(elf, symbol.st_name) {
                    symbol_name
                } else {
                    continue;
                };
                if (symbol.st_bind() == goblin::elf::sym::STB_GLOBAL
                    || symbol.st_bind() == goblin::elf::sym::STB_WEAK)
                    && symbol.st_size == 0
                {
                    self.imported_functions.push(symbol_name);
                } else {
                    self.exported_functions.push(symbol_name);
                }
            }
        }
        self.imported_functions.sort();
        self.exported_functions.sort();
        let imported_functions_string = self.imported_functions.join(",");
        let imphash = md5::compute(imported_functions_string);
        self.imphash = format!("{imphash:x}");
    }

    /// Parse the ELF-header.
    fn parse_header(&mut self, elf: &Elf) {
        let endianness = match elf.header.endianness() {
            Ok(Endian::Little) => "little-endian",
            Ok(Endian::Big) => "big-endian",
            Err(_) => "",
        };

        self.header = BTreeMap::from([
            (
                "Class",
                goblin::elf::header::class_to_str(elf.header.e_ident[4]).to_string(),
            ),
            ("Endianness", endianness.to_string()),
            (
                "Type",
                goblin::elf::header::et_to_str(elf.header.e_type).to_string(),
            ),
            (
                "Machine",
                goblin::elf::header::machine_to_str(elf.header.e_machine).to_string(),
            ),
            ("Version", hex(elf.header.e_version)),
            ("Entry point address", hex(elf.header.e_entry)),
            ("Program header offset", hex(elf.header.e_phoff)),
            ("Section header offset", hex(elf.header.e_shoff)),
            ("Flags", hex(elf.header.e_flags)),
            ("Size of this header", hex(elf.header.e_ehsize)),
            ("Size of program headers", hex(elf.header.e_phentsize)),
            ("Number of program headers", hex(elf.header.e_phnum)),
            ("Size of section headers", hex(elf.header.e_shentsize)),
            ("Number of section headers", hex(elf.header.e_shnum)),
            (
                "Section header string table index",
                hex(elf.header.e_shstrndx),
            ),
        ]);
    }

    /// Parse program headers of the ELF file.
    fn parse_program_headers(&mut self, elf: &Elf) {
        for header in elf.program_headers.iter() {
            self.program_headers.push(parse_program_header(header));
        }
    }

    /// Parse section headers of the ELF file.
    fn parse_section_headers(&mut self, elf: &Elf) {
        for header in elf.section_headers.iter() {
            self.section_headers.push(parse_section_header(header, elf));
        }
    }
}

/// Parse a single program header.
fn parse_program_header(header: &ProgramHeader) -> BTreeMap<&'static str, String> {
    let mut flags = String::new();
    if header.is_read() {
        flags += "R";
    }
    if header.is_write() {
        flags += "W"
    }
    if header.is_executable() {
        flags += "X"
    }

    BTreeMap::from([
        (
            "Type",
            goblin::elf::program_header::pt_to_str(header.p_type).to_string(),
        ),
        ("Flags", flags),
        ("Offset", hex(header.p_offset)),
        ("Vaddr", hex(header.p_vaddr)),
        ("Paddr", hex(header.p_paddr)),
        ("Filesz", hex(header.p_filesz)),
        ("Memsz", hex(header.p_memsz)),
        ("Align", hex(header.p_align)),
    ])
}

/// Parse a single section header.
fn parse_section_header(header: &SectionHeader, elf: &Elf) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("sh_name", get_section_header_name(elf, header.sh_name)),
        (
            "Type",
            goblin::elf::section_header::sht_to_str(header.sh_type).to_string(),
        ),
        (
            "Flags",
            goblin::elf::section_header::shf_to_str(header.sh_flags as u32).to_string(),
        ),
        ("sh_addr", hex(header.sh_addr)),
        ("sh_offset", hex(header.sh_offset)),
        ("sh_size", hex(header.sh_size)),
        ("sh_link", hex(header.sh_link)),
        ("sh_info", hex(header.sh_info)),
        ("sh_addralign", hex(header.sh_addralign)),
        ("sh_entsize", hex(header.sh_entsize)),
    ])
}

/// Get the name of a symbol from the corresponding string table index.
fn get_symbol_name(parsed_elf: &Elf, index: usize) -> Option<String> {
    let symbol_name = parsed_elf.dynstrtab.get_at(index).map(|s| s.to_string());
    symbol_name
}

/// Get the name of a section from the corresponding string table index.
fn get_section_header_name(elf: &Elf, sh_name: usize) -> String {
    elf.shdr_strtab.get_at(sh_name).unwrap_or("").to_string()
}

/// Convenience function for converting numericals to a hex-string.
fn hex(num: impl Into<u64>) -> String {
    let num: u64 = num.into();
    format!("{num:#x}")
}

/// Goblin bindings for parsing ELF files.
///
/// Usage:
/// ```
/// from fact_goblin_bindings import ElfFile
///
/// with open("/path/to/binary", "rb") as file:
///     binary = file.read()
/// elf_file = ElfFile(binary)
/// print(elf_file.header)
/// ```
#[pymodule]
fn fact_goblin_bindings(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<ElfFile>()?;
    Ok(())
}
