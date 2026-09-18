import re
from dataclasses import asdict, dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

SHF_WRITE = 0x1
SHF_ALLOC = 0x2


@dataclass(frozen=True)
class MemoryRegion:
    name: str
    address: int
    size: int
    attributes: str

    @property
    def writable(self):
        return "w" in self.attributes.lower()

    def contains(self, address):
        return self.address <= address < self.address + self.size


@dataclass(frozen=True)
class MapSection:
    name: str
    address: int
    size: int
    load_address: int | None = None


@dataclass(frozen=True)
class InputSection:
    name: str
    address: int
    size: int
    object_file: str
    output_section: str

    def contains(self, address):
        return self.address <= address < self.address + self.size


@dataclass(frozen=True)
class MemorySection:
    name: str
    address: int
    load_address: int
    size: int
    alignment: int
    flash_size: int
    ram_size: int


@dataclass(frozen=True)
class MemorySymbol:
    name: str
    address: int
    size: int
    symbol_type: str
    section: str
    flash_address: int | None
    flash_size: int
    ram_size: int
    object_file: str | None


@dataclass(frozen=True)
class MemoryAnalysis:
    regions: tuple[MemoryRegion, ...]
    sections: tuple[MemorySection, ...]
    symbols: tuple[MemorySymbol, ...]
    summary: dict

    def as_dict(self):
        return {
            "regions": [asdict(region) for region in self.regions],
            "sections": [asdict(section) for section in self.sections],
            "summary": self.summary,
        }


class GnuMapFile:
    region_re = re.compile(
        r"^(?P<name>\S+)\s+0x(?P<address>[0-9a-fA-F]+)\s+"
        r"0x(?P<size>[0-9a-fA-F]+)\s+(?P<attributes>\S+)\s*$"
    )
    output_section_re = re.compile(
        r"^(?P<name>\S+)\s+0x(?P<address>[0-9a-fA-F]+)\s+"
        r"0x(?P<size>[0-9a-fA-F]+)"
        r"(?:\s+load address 0x(?P<load_address>[0-9a-fA-F]+))?\s*$"
    )
    input_section_re = re.compile(
        r"^\s+(?P<name>\.\S+)\s+0x(?P<address>[0-9a-fA-F]+)\s+"
        r"0x(?P<size>[0-9a-fA-F]+)\s+(?P<object_file>.+?)\s*$"
    )
    input_name_re = re.compile(r"^\s+(?P<name>\.\S+)\s*$")
    input_value_re = re.compile(
        r"^\s+0x(?P<address>[0-9a-fA-F]+)\s+0x(?P<size>[0-9a-fA-F]+)\s+"
        r"(?P<object_file>.+?)\s*$"
    )

    def __init__(self, path):
        self.path = Path(path)
        text = self.path.read_text(encoding="utf-8", errors="replace")
        self.regions = tuple(self._parse_regions(text))
        self.sections, self.input_sections = self._parse_sections(text)

    def _parse_regions(self, text):
        in_regions = False
        for line in text.splitlines():
            if line.strip() == "Memory Configuration":
                in_regions = True
                continue
            if not in_regions:
                continue
            if line.strip() == "Linker script and memory map":
                return
            match = self.region_re.match(line)
            if match and match.group("name") != "*default*":
                yield MemoryRegion(
                    match.group("name"),
                    int(match.group("address"), 16),
                    int(match.group("size"), 16),
                    match.group("attributes"),
                )

    @staticmethod
    def _is_object_file(value):
        return bool(re.search(r"(?:\.o|\.obj)(?:\)|\s|$)|\.a\(", value, re.IGNORECASE))

    def _parse_sections(self, text):
        sections = {}
        inputs = []
        current_output = None
        pending_input = None
        in_map = False

        for line in text.splitlines():
            if line.strip() == "Linker script and memory map":
                in_map = True
                continue
            if not in_map:
                continue

            output_match = self.output_section_re.match(line)
            if output_match:
                current_output = output_match.group("name")
                load_address = output_match.group("load_address")
                sections[current_output] = MapSection(
                    current_output,
                    int(output_match.group("address"), 16),
                    int(output_match.group("size"), 16),
                    int(load_address, 16) if load_address else None,
                )
                pending_input = None
                continue

            if not current_output:
                continue

            input_match = self.input_section_re.match(line)
            if input_match and self._is_object_file(input_match.group("object_file")):
                inputs.append(
                    InputSection(
                        input_match.group("name"),
                        int(input_match.group("address"), 16),
                        int(input_match.group("size"), 16),
                        input_match.group("object_file"),
                        current_output,
                    )
                )
                pending_input = None
                continue

            name_match = self.input_name_re.match(line)
            if name_match:
                pending_input = name_match.group("name")
                continue

            value_match = self.input_value_re.match(line)
            if (
                pending_input
                and value_match
                and self._is_object_file(value_match.group("object_file"))
            ):
                inputs.append(
                    InputSection(
                        pending_input,
                        int(value_match.group("address"), 16),
                        int(value_match.group("size"), 16),
                        value_match.group("object_file"),
                        current_output,
                    )
                )
            pending_input = None

        return sections, tuple(inputs)

    def owner_for(self, output_section, address):
        candidates = [
            section
            for section in self.input_sections
            if section.output_section == output_section and section.contains(address)
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda section: section.size).object_file


class MemoryAnalyzer:
    """Derive symbol and total FLASH/RAM usage from an ELF image and GNU ld MAP file."""

    def __init__(self, elf_path, map_path):
        self.elf_path = Path(elf_path)
        self.map_file = GnuMapFile(map_path)

    def analyze(self):
        with self.elf_path.open("rb") as stream:
            elf = ELFFile(stream)
            sections = self._read_sections(elf)
            symbols = self._read_symbols(elf, sections)

        summary = self._summarize(sections)
        return MemoryAnalysis(
            self.map_file.regions,
            tuple(sections.values()),
            tuple(symbols),
            summary,
        )

    def _region_for(self, address):
        return next((region for region in self.map_file.regions if region.contains(address)), None)

    @staticmethod
    def _section_lma(elf, section):
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD" and segment.section_in_segment(section):
                return segment["p_paddr"] + section["sh_addr"] - segment["p_vaddr"]
        return section["sh_addr"]

    def _read_sections(self, elf):
        result = {}
        for index, section in enumerate(elf.iter_sections()):
            size = section["sh_size"]
            if not size:
                continue

            name = section.name
            flags = section["sh_flags"]
            allocated = bool(flags & SHF_ALLOC)
            is_heap = "heap" in name.lower()
            if not allocated and not is_heap:
                continue

            address = section["sh_addr"]
            load_address = self._section_lma(elf, section)
            vma_region = self._region_for(address)
            lma_region = self._region_for(load_address)
            is_nobits = section["sh_type"] == "SHT_NOBITS"
            ram_size = size if vma_region and vma_region.writable else 0
            flash_size = (
                size
                if not is_nobits and lma_region and not lma_region.writable and allocated
                else 0
            )

            if not flash_size and not ram_size:
                continue

            result[index] = MemorySection(
                name,
                address,
                load_address,
                size,
                max(section["sh_addralign"], 1),
                flash_size,
                ram_size,
            )
        return result

    def _read_symbols(self, elf, sections):
        is_arm = elf["e_machine"] == "EM_ARM"
        symbol_table = elf.get_section_by_name(".symtab")
        if not isinstance(symbol_table, SymbolTableSection):
            return []

        result = []
        for symbol in symbol_table.iter_symbols():
            symbol_type = symbol["st_info"]["type"]
            section_index = symbol["st_shndx"]
            size = symbol["st_size"]
            if symbol_type not in ("STT_FUNC", "STT_OBJECT") or not size:
                continue
            if not isinstance(section_index, int) or section_index not in sections:
                continue

            section = sections[section_index]
            address = symbol["st_value"]
            if is_arm and symbol_type == "STT_FUNC":
                address &= ~1
            if not section.address <= address < section.address + section.size:
                continue

            size = min(size, section.address + section.size - address)
            offset = address - section.address
            result.append(
                MemorySymbol(
                    symbol.name,
                    address,
                    size,
                    "function" if symbol_type == "STT_FUNC" else "variable",
                    section.name,
                    section.load_address + offset if section.flash_size else None,
                    size if section.flash_size else 0,
                    size if section.ram_size else 0,
                    self.map_file.owner_for(section.name, address),
                )
            )
        return result

    @staticmethod
    def _alignment_padding(sections, size_name, address_name):
        used = [section for section in sections if getattr(section, size_name)]
        used.sort(key=lambda section: getattr(section, address_name))
        padding = 0
        for previous, current in zip(used, used[1:]):
            previous_end = getattr(previous, address_name) + getattr(previous, size_name)
            gap = getattr(current, address_name) - previous_end
            if 0 < gap < current.alignment:
                padding += gap
        return padding

    def _summarize(self, sections_by_index):
        sections = list(sections_by_index.values())
        flash_padding = self._alignment_padding(sections, "flash_size", "load_address")
        ram_padding = self._alignment_padding(sections, "ram_size", "address")

        flash_code = sum(s.flash_size for s in sections if s.name == ".text")
        flash_data = sum(s.flash_size for s in sections if s.ram_size)
        flash_total = sum(s.flash_size for s in sections) + flash_padding

        stack = sum(s.ram_size for s in sections if "stack" in s.name.lower())
        heap = sum(s.ram_size for s in sections if "heap" in s.name.lower())
        ram_static = sum(s.ram_size for s in sections) - stack - heap
        ram_total = sum(s.ram_size for s in sections) + ram_padding

        return {
            "flash": {
                "code_rodata": flash_code,
                "initialized_data": flash_data,
                "linker": flash_total - flash_code - flash_data,
                "padding": flash_padding,
                "total": flash_total,
            },
            "ram": {
                "static": ram_static,
                "stack": stack,
                "heap": heap,
                "padding": ram_padding,
                "total": ram_total,
            },
        }
