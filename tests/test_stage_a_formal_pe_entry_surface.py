from tests.stage_a_relational_support import *


_PE_OFFSET = 0x80
_OPTIONAL_OFFSET = _PE_OFFSET + 24
_SECTION_TABLE_OFFSET = _OPTIONAL_OFFSET + 224
_TEXT_RAW = 0x200
_EDATA_RAW = 0x400
_EDATA_RVA = 0x2000
_EXPORT_DIRECTORY_SIZE = 0xC0


def _pe32_export_surface_image(
    entries: tuple[int, ...],
    *,
    dll: bool = True,
    include_export_directory: bool = True,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    section_raw_size = 0x200
    size_of_image = 0x3000
    eat_rva = _EDATA_RVA + 0x40
    forwarder_rva = _EDATA_RVA + 0x80
    dll_name_rva = _EDATA_RVA + 0xA0

    text = bytearray(section_raw_size)
    text[0] = 0xC3
    text[0x10] = 0xC3

    edata = bytearray(section_raw_size)
    struct.pack_into(
        "<IIHHIIIIIII",
        edata,
        0,
        0,
        0,
        0,
        0,
        dll_name_rva,
        1,
        len(entries),
        0,
        eat_rva if entries else 0,
        0,
        0,
    )
    for index, entry in enumerate(entries):
        struct.pack_into("<I", edata, 0x40 + index * 4, entry)
    edata[0x80 : 0x80 + len(b"KERNEL32.Sleep\0")] = b"KERNEL32.Sleep\0"
    edata[0xA0 : 0xA0 + len(b"entry-test.dll\0")] = b"entry-test.dll\0"

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, _PE_OFFSET)
    characteristics = 0x210F if dll else 0x010F
    coff = struct.pack(
        "<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, characteristics
    )
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        0,
        0,
        section_raw_size,
        section_raw_size,
        0,
        text_rva,
        text_rva,
        _EDATA_RVA,
        0x400000,
        section_alignment,
        file_alignment,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        size_of_image,
        headers_size,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    directories = bytearray(16 * 8)
    if include_export_directory:
        struct.pack_into(
            "<II", directories, 0, _EDATA_RVA, _EXPORT_DIRECTORY_SIZE
        )
    optional = optional_prefix + bytes(directories)
    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        0x20,
        text_rva,
        section_raw_size,
        _TEXT_RAW,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    edata_section = struct.pack(
        "<8sIIIIIIHHI",
        b".edata\0\0",
        section_raw_size,
        _EDATA_RVA,
        section_raw_size,
        _EDATA_RAW,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    headers = (
        bytes(dos)
        + b"PE\0\0"
        + coff
        + optional
        + text_section
        + edata_section
    ).ljust(headers_size, b"\0")
    assert len(headers) == headers_size
    return headers + bytes(text) + bytes(edata)


def _patched_u32(image: bytes, offset: int, value: int) -> bytes:
    patched = bytearray(image)
    struct.pack_into("<I", patched, offset, value)
    return bytes(patched)


class StageAFormalPEEntrySurfaceTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for PE parsing")
    def test_exact_pe32_export_entry_surface_is_checked_by_lean(self):
        forwarder_rva = _EDATA_RVA + 0x80
        dll_image = _pe32_export_surface_image(
            (0x1000, 0, forwarder_rva, _EDATA_RVA + 0xE0)
        )
        exe_image = _pe32_export_surface_image((0x1010,), dll=False)
        absent_image = _pe32_export_surface_image(
            (), dll=False, include_export_directory=False
        )
        empty_image = _pe32_export_surface_image((), dll=False)
        malformed_base = _pe32_export_surface_image(
            (0x1000, 0, forwarder_rva, _EDATA_RVA + 0xE0), dll=False
        )

        unmapped = _patched_u32(
            malformed_base, _EDATA_RAW + 0x40, 0x3000
        )

        unterminated = bytearray(malformed_base)
        struct.pack_into(
            "<I", unterminated, _EDATA_RAW + 0x40, _EDATA_RVA + 0xBC
        )
        unterminated[_EDATA_RAW + 0xBC : _EDATA_RAW + 0xC0] = b"ABCD"

        truncated_eat = bytearray(malformed_base)
        struct.pack_into("<I", truncated_eat, _EDATA_RAW + 20, 2)
        struct.pack_into(
            "<I", truncated_eat, _EDATA_RAW + 28, _EDATA_RVA + 0xBC
        )

        virtual_tail = bytearray(malformed_base)
        struct.pack_into(
            "<I", virtual_tail, _SECTION_TABLE_OFFSET + 8, 0x300
        )
        struct.pack_into("<I", virtual_tail, _EDATA_RAW + 0x40, 0x1250)

        short_directory = _patched_u32(
            malformed_base, _OPTIONAL_OFFSET + 100, 39
        )
        truncated_directory = malformed_base[: _EDATA_RAW + 0xB0]

        images = {
            "dllImage": dll_image,
            "exeImage": exe_image,
            "absentImage": absent_image,
            "emptyImage": empty_image,
            "unmappedImage": unmapped,
            "unterminatedImage": bytes(unterminated),
            "truncatedEatImage": bytes(truncated_eat),
            "virtualTailImage": bytes(virtual_tail),
            "shortDirectoryImage": short_directory,
            "truncatedDirectoryImage": truncated_directory,
        }

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src"
                / "spaghetti_extractor"
                / "lean"
                / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            image_definitions = "\n\n".join(
                f"def {name} : Bytes := {list(image)}"
                for name, image in images.items()
            )
            (stage_a / "FormalPEEntrySurface.lean").write_text(
                "import StageA.RelationalCertificates\n\n"
                "namespace StageA.FormalPEEntrySurfaceTests\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "set_option maxRecDepth 1000000\n"
                "set_option maxHeartbeats 0\n\n"
                + image_definitions
                + "\n\n"
                "def expectedExports : List PEExport := [\n"
                "  { rva := 0x1000, kind := .executableAddress, forwarder := none },\n"
                "  { rva := 0, kind := .null, forwarder := none },\n"
                "  { rva := 0x2080, kind := .forwarder,\n"
                "    forwarder := some [75, 69, 82, 78, 69, 76, 51, 50, 46, 83, 108, 101, 101, 112] },\n"
                "  { rva := 0x20e0, kind := .dataAddress, forwarder := none }\n"
                "]\n\n"
                "def consoleEntrySurfaceValid (bytes : Bytes) : Bool :=\n"
                "  match parsePE32 bytes with\n"
                "  | some pe => PE32ConsoleImageEntrySurfaceValid pe\n"
                "  | none => false\n\n"
                "example : (parsePE32 dllImage).map PE32.characteristics =\n"
                "    some 0x210f := by decide\n\n"
                "example : (parsePE32 dllImage).map PE32.isDll = some true := by decide\n\n"
                "example : (parsePE32 exeImage).map PE32.isDll = some false := by decide\n\n"
                "example : (parsePE32 dllImage).bind parseExports =\n"
                "    some expectedExports := by decide\n\n"
                "example : (parsePE32 exeImage).bind parseExports = some [\n"
                "    { rva := 0x1010, kind := .executableAddress, forwarder := none }\n"
                "  ] := by decide\n\n"
                "example : (parsePE32 absentImage).bind parseExports = some [] := by decide\n\n"
                "example : (parsePE32 emptyImage).bind parseExports = some [] := by decide\n\n"
                "example : (parsePE32 unmappedImage).bind parseExports = none := by decide\n\n"
                "example : (parsePE32 unterminatedImage).bind parseExports = none := by decide\n\n"
                "example : (parsePE32 truncatedEatImage).bind parseExports = none := by decide\n\n"
                "example : (parsePE32 virtualTailImage).bind parseExports = none := by decide\n\n"
                "example : (parsePE32 shortDirectoryImage).bind parseExports = none := by decide\n\n"
                "example : (parsePE32 truncatedDirectoryImage).bind parseExports = none := by decide\n\n"
                "theorem absentExeConsoleEntrySurfaceValid :\n"
                "    consoleEntrySurfaceValid absentImage = true := by decide\n\n"
                "theorem emptyExeConsoleEntrySurfaceValid :\n"
                "    consoleEntrySurfaceValid emptyImage = true := by decide\n\n"
                "theorem dllConsoleEntrySurfaceRejected :\n"
                "    consoleEntrySurfaceValid dllImage = false := by decide\n\n"
                "theorem nonemptyExeConsoleEntrySurfaceRejected :\n"
                "    consoleEntrySurfaceValid exeImage = false := by decide\n\n"
                "theorem malformedExeConsoleEntrySurfacesRejected :\n"
                "    [unmappedImage, unterminatedImage, truncatedEatImage,\n"
                "    virtualTailImage, shortDirectoryImage, truncatedDirectoryImage].all\n"
                "    (fun image => !consoleEntrySurfaceValid image) = true := by decide\n\n"
                "end StageA.FormalPEEntrySurfaceTests\n",
                encoding="utf-8",
            )

            lean = _run_lean_relational(
                lean_dir, bundle="FormalPEEntrySurface"
            )

        self.assertEqual(lean["status"], "checked", lean)


if __name__ == "__main__":
    unittest.main()
