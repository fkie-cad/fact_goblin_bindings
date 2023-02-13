# FACT-Goblin-Bindings

[Goblin](https://github.com/m4b/goblin) is a Rust library for parsing ELF files.
This package provides Python bindings for Goblin exposing most of the information available through the library.

## Installation

```sh
pip install fact_goblin_bindings
```

## Usage

```python
from fact_goblin_bindings use ElfFile

with open("/path/to/binary", "rb") as file:
    binary = file.read()
elf_file = ElfFile(binary)
print(elf_file.header)
```

Use the Python documentation available through `help(ElfFile)` to get more information about the data provided by the bindings.

## Development

- It is recommended to use a virtual environment for development.
- Make sure that you have [Rust](https://www.rust-lang.org/) installed.
- Install [Maturin](https://github.com/PyO3/maturin) with `pip install maturin`
- Then you can build the package locally with `maturin develop`