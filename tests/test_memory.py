import tempfile
from pathlib import Path

from puncover.memory import GnuMapFile, MemoryAnalyzer, MemorySection


def test_gnu_map_file_parses_regions_sections_and_object_owners():
    contents = """Memory Configuration

Name             Origin             Length             Attributes
FLASH            0x00010000         0x00040000         xr
RAM              0x20000000         0x00008000         xrw
*default*        0x00000000         0xffffffff

Linker script and memory map

.text           0x00010000       0x30
 .text.first    0x00010000       0x10 ./src/first.o
 .rodata.table
                0x00010010       0x20 ./src/table.o
.data           0x20000000       0x08 load address 0x00010030
 .data.value    0x20000000       0x08 ./src/value.o
"""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory, "sample.map")
        path.write_text(contents, encoding="utf-8")
        parsed = GnuMapFile(path)

    assert [region.name for region in parsed.regions] == ["FLASH", "RAM"]
    assert parsed.sections[".data"].load_address == 0x10030
    assert parsed.owner_for(".text", 0x10005) == "./src/first.o"
    assert parsed.owner_for(".text", 0x10020) == "./src/table.o"
    assert parsed.owner_for(".data", 0x20000004) == "./src/value.o"


def test_memory_summary_includes_initialized_data_stack_heap_and_padding():
    sections = {
        1: MemorySection(".text", 0x10000, 0x10000, 100, 4, 100, 0),
        2: MemorySection(".data", 0x20000000, 0x10064, 20, 4, 20, 20),
        3: MemorySection(".bss", 0x20000014, 0x10078, 30, 4, 0, 30),
        4: MemorySection(".stack", 0x20000034, 0x20000034, 40, 8, 0, 40),
        5: MemorySection(".heap", 0x20000060, 0x20000060, 50, 16, 0, 50),
    }
    analyzer = MemoryAnalyzer.__new__(MemoryAnalyzer)

    assert analyzer._summarize(sections) == {
        "flash": {
            "code_rodata": 100,
            "initialized_data": 20,
            "linker": 0,
            "padding": 0,
            "total": 120,
        },
        "ram": {
            "static": 50,
            "stack": 40,
            "heap": 50,
            "padding": 6,
            "total": 146,
        },
    }
