import re
from pathlib import Path
from typing import Optional
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import SUSPICIOUS_APIS

# Flatten all suspicious API names into one set for quick lookup
ALL_SUSPICIOUS_APIS = set()
for api_list in SUSPICIOUS_APIS.values():
    ALL_SUSPICIOUS_APIS.update(api_list)


def parse_asm_file(asm_path: str) -> dict:
    """
    Parse a disassembly text file and split it into functions.

    Returns:
        {
          "functions": [{"name": "...", "instructions": [...], "calls": [...]}, ...],
          "total_functions": int,
          "suspicious_functions": [...]
        }
    """
    path = Path(asm_path)
    if not path.exists():
        return {"error": f"ASM file not found: {asm_path}", "functions": []}

    content = path.read_text(encoding='utf-8', errors='replace')
    functions = _split_into_functions(content)

    # Tag which functions make suspicious API calls
    suspicious = []
    for func in functions:
        func["suspicious_calls"] = _find_suspicious_calls(func["instructions"])
        if func["suspicious_calls"]:
            suspicious.append(func)

    return {
        "functions": functions,
        "total_functions": len(functions),
        "suspicious_functions": suspicious,
    }


def _split_into_functions(content: str) -> list[dict]:
    """
    Split the flat disassembly text into individual functions.

    WHY: Ghidra and objdump both mark function starts with lines like:
        ******** FUNCTION ********       (Ghidra)
        <FunctionName>:                  (objdump)
        ; =============== FUNCTION =     (IDA-style)

    We detect all these patterns.
    """
    # Common function-start patterns
    func_start_patterns = [
        re.compile(r'^\*+\s+FUNCTION\s+\*+', re.MULTILINE),  # Ghidra
        re.compile(r'^[0-9a-f]+ <([a-zA-Z_][a-zA-Z0-9_@?]*)>:', re.MULTILINE),  # objdump
        re.compile(r'^; ={10,}.*FUNCTION', re.MULTILINE),  # IDA
        re.compile(r'^FUNCTION\s+([a-zA-Z_][a-zA-Z0-9_]*)', re.MULTILINE),
    ]

    functions = []
    lines = content.split('\n')

    current_func_name = "unknown_func"
    current_instructions = []

    for line in lines:
        # Check if this line starts a new function
        new_func = None

        # Ghidra pattern: line after "*** FUNCTION ***" has the name
        if re.match(r'\*+\s+FUNCTION\s+\*+', line.strip()):
            if current_instructions:
                functions.append(_make_func(current_func_name, current_instructions))
            current_func_name = "unknown_func"
            current_instructions = []
            continue

        # objdump pattern: 00401000 <FunctionName>:
        m = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
        if m:
            if current_instructions:
                functions.append(_make_func(current_func_name, current_instructions))
            current_func_name = m.group(2)
            current_instructions = []
            continue

        # Ghidra function name line (after the *** line)
        m = re.match(r'^\s+([a-zA-Z_][a-zA-Z0-9_:@?<>~]*)\s*$', line)
        if m and current_func_name == "unknown_func":
            current_func_name = m.group(1)
            continue

        # Regular instruction line — keep it if it has an address
        if re.match(r'^\s*[0-9a-fA-F]{4,}', line):
            current_instructions.append(line.rstrip())

    # Don't forget the last function
    if current_instructions:
        functions.append(_make_func(current_func_name, current_instructions))

    return functions


def _make_func(name: str, instructions: list[str]) -> dict:
    """Package a function into a dict."""
    # Extract all CALL targets from instructions
    calls = []
    for instr in instructions:
        # Match: call  <name>  or  call  address
        m = re.search(r'\bcall\b.*?<([^>]+)>', instr, re.IGNORECASE)
        if m:
            calls.append(m.group(1))
        else:
            # plain: call 0x401234 or call VirtualAlloc
            m2 = re.search(r'\bcall\s+([a-zA-Z_][a-zA-Z0-9_@]*)', instr, re.IGNORECASE)
            if m2:
                calls.append(m2.group(1))

    return {
        "name": name,
        "instructions": instructions,
        "num_instrs": len(instructions),
        "calls": list(set(calls)),
    }


def _find_suspicious_calls(instructions: list[str]) -> list[str]:
    """Return list of suspicious API names called in this instruction list."""
    found = []
    full_text = " ".join(instructions).lower()
    for api in ALL_SUSPICIOUS_APIS:
        if api.lower() in full_text:
            found.append(api)
    return found


def get_suspicious_functions_text(parsed: dict, max_functions: int = 5) -> str:
    """
    Format the most suspicious functions for inclusion in the LLM prompt.

    WHY limit to 5?
        Each function can have 100+ instructions. 5 suspicious functions
        with 50 instructions each = 250 lines in the prompt. That's enough
        context for GPT-4 to make a good analysis without hitting token limits.
    """
    sus_funcs = parsed.get("suspicious_functions", [])

    if not sus_funcs:
        # Fallback: return first 3 functions regardless
        all_funcs = parsed.get("functions", [])
        if not all_funcs:
            return "No disassembly available."
        sus_funcs = all_funcs[:3]

    lines = []
    lines.append(f"Suspicious functions found: {len(sus_funcs)} "
                 f"(showing top {min(len(sus_funcs), max_functions)})\n")

    for func in sus_funcs[:max_functions]:
        lines.append(f"{'─' * 40}")
        lines.append(f"Function: {func['name']}")
        if func.get("suspicious_calls"):
            lines.append(f"Suspicious API calls: {', '.join(func['suspicious_calls'])}")
        lines.append("")
        # Show up to 40 instructions per function
        for instr in func["instructions"][:40]:
            lines.append(f"  {instr}")
        if len(func["instructions"]) > 40:
            lines.append(f"  ... ({len(func['instructions']) - 40} more instructions)")
        lines.append("")

    return "\n".join(lines)


def create_mock_disassembly(sample_type: str = "generic") -> str:
    """
    Generate realistic mock disassembly for testing WITHOUT needing a real .exe.

    WHY: During development and thesis demo, you might not have real malware samples.
         This lets you test the full pipeline with realistic-looking assembly.
         For the actual evaluation, you replace this with real Ghidra output.
    """
    mocks = {
        "dropper": """\
00401000 <main>:
  00401000: push   ebp
  00401001: mov    ebp, esp
  00401003: sub    esp, 0x28
  00401006: push   0x40                    ; PAGE_EXECUTE_READWRITE
  00401008: push   0x3000                  ; MEM_COMMIT|MEM_RESERVE
  0040100A: push   0x1000                  ; size
  0040100C: push   0                       ; NULL process = self
  0040100E: call   VirtualAllocEx          ; allocate memory in target process
  00401013: test   eax, eax
  00401015: jz     0x40105F                ; fail → exit
  00401017: push   offset payload_bytes
  0040101C: push   eax                     ; remote address
  0040101D: call   WriteProcessMemory      ; copy shellcode
  00401022: call   CreateRemoteThread      ; execute injected code
  00401027: test   eax, eax
  00401029: jz     0x40105F
  0040102B: push   0xFFFFFFFF
  0040102D: push   eax
  0040102E: call   WaitForSingleObject
  00401033: xor    eax, eax
  00401035: pop    ebp
  00401036: ret
""",
        "keylogger": """\
00401200 <InstallHook>:
  00401200: push   ebp
  00401201: mov    ebp, esp
  00401203: push   NULL                    ; hMod = current module
  00401205: push   offset KeyboardProc     ; callback function
  00401207: push   0xD                     ; WH_KEYBOARD_LL
  00401209: call   SetWindowsHookExA       ; install low-level keyboard hook
  0040120E: mov    [hHook], eax
  00401213: test   eax, eax
  00401215: jz     SHORT fail
  00401217: call   MessageBoxA             ; "Hook installed"
  0040121C: ret

00401300 <KeyboardProc>:
  00401300: push   ebp
  00401301: mov    ebp, esp
  00401303: call   GetAsyncKeyState        ; get currently pressed key
  00401308: movzx  eax, ax
  0040130B: test   al, 0x80
  0040130D: jz     SHORT pass
  0040130F: call   WriteFile               ; write key to log file
  00401314: ret
""",
        "ransomware": """\
00402000 <EncryptFiles>:
  00402000: push   ebp
  00402001: mov    ebp, esp
  00402003: call   CryptAcquireContextA    ; init crypto provider
  00402008: call   CryptGenKey             ; generate AES-256 key
  0040200D: lea    eax, [searchPath]       ; "C:\\Users\\*.*"
  00402013: push   eax
  00402015: call   FindFirstFileW          ; start file enumeration
  0040201A: test   eax, eax
  0040201C: jz     SHORT done
  0040201E: call   CreateFileW             ; open target file
  00402023: call   CryptEncrypt            ; encrypt file contents
  00402028: call   DeleteFileW             ; remove original
  0040202D: call   FindNextFileW           ; continue enumeration
  00402032: jmp    SHORT 0x40201A

00402100 <DropRansomNote>:
  00402100: push   offset note_text        ; "Your files have been encrypted..."
  00402105: push   offset note_path        ; "C:\\README_DECRYPT.txt"
  0040210A: call   CreateFileW
  0040210F: call   WriteFile
  00402114: call   ShellExecuteA           ; open note in notepad
  00402119: ret
""",
    }
    return mocks.get(sample_type, mocks["dropper"])
