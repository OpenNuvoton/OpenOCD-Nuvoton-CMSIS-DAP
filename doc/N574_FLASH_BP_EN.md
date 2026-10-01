# N574 Flash Software Breakpoints (Flash BP)

## 1. Overview

The N574 uses a Cortex-M0 core with a limited number of FPB (Flash Patch and Breakpoint) hardware comparators. This change preserves the existing hardware-breakpoint implementation and adds an optional NOR-flash software-breakpoint path for cases where all FPB comparators are already in use.

A Flash BP temporarily replaces the target Thumb instruction with `BKPT 0x11` (physical bytes `11 BE`). Removing the breakpoint restores the original instruction.

The feature is designed around the following safety rules:

- The existing `BKPT_HARD` set and unset paths remain unchanged.
- RAM software breakpoints continue to use the original target memory read/write path.
- Flash BP is disabled by default for every flash bank.
- GDB automatic fallback is disabled by default.
- The shared NuMicro Cortex-M0 target configuration explicitly keeps both features disabled.
- Flash rewriting occurs only after the containing NOR bank and GDB fallback have both been explicitly enabled.
- Fallback is attempted only when a hardware breakpoint returns `ERROR_TARGET_RESOURCE_NOT_AVAILABLE`.
- Hardware FPB breakpoints remain the first choice.

This feature does not replace FPB. It only provides additional breakpoint capacity when FPB resources are exhausted.

## 2. Features and Fixes

This change adds or fixes the following behavior:

- Per-bank, opt-in NOR-flash software breakpoints.
- Opt-in GDB fallback after hardware-breakpoint resource exhaustion.
- Full-sector erase, program, read-back verification, and rollback.
- Complete target working-area preservation and verification.
- Multiple Flash BPs in the same erase sector.
- Rejection of overlapping Flash BP definitions.
- Protection against restoring stale instructions over newer firmware.
- Restoration of active Flash BPs during target teardown.
- GDB memory-read overlay so disassembly displays original instructions.
- N574 LDROM reads through FMC ISP for backup and verification.
- Safe flash-bank address lookup that ignores zero-sized banks.

## 3. Flash-Sector Transaction

Setting or clearing a Flash BP performs the following transaction:

1. Locate the NOR flash bank and erase sector containing the address.
2. Verify that the target is halted and that the flash driver provides read, erase, and write operations.
3. Read the complete sector into host memory.
4. Modify only the bytes belonging to the target instruction.
5. Erase the complete sector.
6. Write the complete sector back.
7. Read the complete sector again and compare every byte.
8. If an operation fails, attempt to restore the complete pre-transaction sector and verify the rollback.

The implementation uses the sector size reported by the probed flash driver instead of hard-coding the N574 512-byte page size.

### 3.1 Working-Area Preservation

NuMicro flash algorithms use the target working area for algorithm code, data, and stack. Before rewriting a sector, Flash BP saves the entire configured working area, including gaps between allocator blocks and unused space at the end of the area.

After the flash operation, OpenOCD writes the saved working-area contents back and performs read-back verification. This is independent of the target's `-work-area-backup` setting.

- If the working area cannot be saved, the operation stops before flash is modified.
- If flash programming succeeds but RAM restoration fails, OpenOCD first attempts to roll the flash sector back, then retries RAM restoration and reports an error.

### 3.2 Multiple Breakpoints in One Sector

Each operation starts from the current complete sector image and modifies only one instruction. Multiple Flash BPs can therefore coexist in the same sector, and removing one does not remove the others.

Overlapping breakpoint address ranges are rejected. This prevents one record from saving another breakpoint's opcode as the supposed original instruction.

Each active Flash BP record stores:

- target and address;
- instruction length;
- breakpoint opcode;
- original instruction bytes.

If normal removal fails, the record is retained. Target teardown attempts to halt the target and restore all active Flash BPs before discarding the records.

### 3.3 Firmware-Conflict Protection

Before clearing a Flash BP, OpenOCD checks the current flash bytes:

- If they already match the saved original instruction, the breakpoint is treated as restored and its record is removed.
- If they match the expected `11 BE` opcode, the normal clear transaction proceeds.
- If they match neither value, OpenOCD reports `CLEAR conflict` and refuses to overwrite the data.

This prevents an old in-memory breakpoint record from overwriting firmware that was reprogrammed by another tool.

## 4. GDB Integration

### 4.1 Hardware-Breakpoint Fallback

The target continues to use:

```tcl
gdb_breakpoint_override hard
```

A GDB breakpoint therefore requests an FPB hardware breakpoint first. The fallback path is entered only when all of the following are true:

1. The request is for `BKPT_HARD`.
2. The original request returns `ERROR_TARGET_RESOURCE_NOT_AVAILABLE`.
3. `gdb_flash_breakpoint_fallback` is enabled.
4. The address belongs to a NOR flash bank.
5. Flash BP is enabled for that bank.

```text
GDB Z1 -> existing FPB setup
              |
              +-- success: use hardware FPB; do not modify flash
              |
              +-- FPB resource unavailable
                    |
                    +-- address is not in an enabled NOR bank:
                    |      return the original error
                    |
                    +-- address is in an enabled NOR bank:
                           retry as BKPT_SOFT and run a sector transaction
```

### 4.2 Disassembly Overlay

While a Flash BP is active, physical flash must contain `BKPT 0x11`. Returning those physical bytes to GDB would cause NUIDE or GDB to display `bkpt 0x0011` instead of the original instruction.

After a successful GDB `m` memory-read packet, OpenOCD overlays saved original instruction bytes into the reply buffer when:

- the requested range overlaps an active Flash BP; and
- the physical bytes still match the recorded breakpoint opcode.

The overlay supports multiple breakpoints, unaligned reads, and partial instruction reads. It modifies only the GDB reply buffer, not target flash.

GDB disassembly therefore displays the original AXF instruction. An OpenOCD monitor command such as the following still shows physical flash bytes:

```gdb
monitor mdb <address> 2
```

## 5. N574 LDROM Read Support

N574 LDROM is not reliably readable through the normal Cortex-M SWD memory map. The NuMicro DAP driver therefore adds `numicro_dap_read()`.

Only N574 LDROM uses FMC ISP reads. Other NuMicro devices and other flash banks continue to use `default_flash_read()`.

The N574 LDROM path:

- requires the target to be halted;
- unlocks the required registers;
- enables FMC ISP;
- reads aligned 32-bit words with the FMC ISP read command;
- supports unaligned starting addresses and partial words;
- checks timeout and ISP failure status.

This read path provides the sector backup, read-back verification, and rollback support required by LDROM Flash BP.

## 6. Zero-Sized Flash-Bank Fix

Flash-bank address lookup changes from an upper-bound expression based on `base + size - 1` to:

```c
if (c->size && addr >= c->base && addr - c->base < c->size)
```

This change:

- ignores zero-sized and not-yet-probed banks;
- prevents unsigned underflow when `size == 0`;
- avoids overflow in upper-bound address addition;
- prevents RAM or other high addresses from being incorrectly identified as flash.

## 7. Modified Files

The following seven source/configuration files form the complete runtime feature and must be committed together:

| File | Purpose |
|---|---|
| `src/flash/nor/core.c` | Flash BP records, sector transactions, verification, rollback, working-area preservation, read overlay, and safe address lookup |
| `src/flash/nor/core.h` | Per-bank enable state and public Flash BP APIs |
| `src/flash/nor/tcl.c` | `flash breakpoint` command registration |
| `src/flash/nor/numicro_dap.c` | N574 LDROM FMC ISP read support |
| `src/target/cortex_m.c` | Flash/RAM software-breakpoint dispatch and teardown restoration |
| `src/server/gdb_server.c` | GDB fallback command, fallback logic, and memory-read overlay |
| `tcl/target/numicroM0.cfg` | Safe disabled defaults for APROM, LDROM, and GDB fallback |

The following documentation and test files should be committed with the feature:

| File | Purpose |
|---|---|
| `doc/openocd.texi` | OpenOCD command reference |
| `doc/N574_FLASH_BP.md` | Traditional Chinese design and usage guide |
| `doc/N574_FLASH_BP_EN.md` | English design and usage guide |
| `testing/n574_flash_breakpoint_regression.py` | Host-side source-wiring and fault-injection regression |

## 8. Files Not Included in the Feature

The following files must not be included in the production feature commit:

- `src/target/flashbp_journal.c`
- `src/target/flashbp_journal.h`
- `src/openocd-flashbp-journal-fix.zip`
- `src/openocd-flashbp-step-fix.zip`
- `src/openocd.zip`
- local IDE settings;
- backup files;
- generated configure/Makefile files;
- object files and built executables.

The `flashbp_journal.c/.h` module is an unfinished host-persistent recovery experiment. It is not listed in `Makefile.am`, and no production source calls any `flashbp_journal_*()` API. It is therefore not compiled, linked, or used by the current OpenOCD binary.

The production implementation guarantees transaction rollback only while the OpenOCD process and target connection remain available. It does not guarantee automatic recovery after process termination, host failure, target power loss, or debug-probe disconnection.

Local build wrappers are unrelated to runtime behavior. They should be reviewed and committed separately only if the team wants to maintain them as an official build interface.

## 9. Compatibility and Behavior

| Existing behavior | Effect of this change |
|---|---|
| Cortex-M hardware breakpoints | The original `BKPT_HARD` set/unset branches are unchanged |
| FPB with available comparators | Continues to use hardware FPB and does not modify flash |
| RAM software breakpoints | Continue through the original target memory read/write path |
| Disabled flash banks | Never enter a sector rewrite transaction |
| GDB fallback | Disabled by default and requires explicit enablement |
| Other NuMicro flash reads | Continue to use `default_flash_read()` |
| GDB memory reads without active Flash BPs | Returned data is unchanged |
| OpenOCD monitor memory reads | Continue to show physical flash bytes |
| Target teardown without active Flash BPs | No additional action |

Important compatibility considerations:

1. `numicroM0.cfg` is shared by multiple devices, so it keeps APROM/LDROM Flash BP and GDB fallback disabled.
2. N574-specific tooling must explicitly enable the feature after identifying the target.
3. `gdb_flash_breakpoint_fallback` is process-global, but an actual flash rewrite still requires per-bank enablement.
4. `struct flash_bank` has a new field. The first build after applying this change must be a clean build.
5. N574 LDROM reads now require a halted target and access FMC ISP registers; board-level validation is required.

## 10. Building and Host-Side Regression

Use the project's standard clean build procedure. If the local build helper is available:

```powershell
python .\build_openocd.py --clean --jobs 2
```

Do not reuse old objects after changing `struct flash_bank`.

Run the host-side regression with:

```powershell
python .\testing\n574_flash_breakpoint_regression.py --openocd .\src\openocd.exe
```

The regression verifies:

- unchanged Cortex-M hardware-breakpoint branches;
- Flash BP and RAM BP dispatch;
- disabled shared-target defaults;
- resource-exhaustion-only GDB fallback;
- full-sector erase, write, read-back, verification, and rollback wiring;
- single and multiple breakpoints in one sector;
- erase, program, and verification failure rollback;
- complete working-area restoration;
- firmware-conflict protection;
- target teardown restoration;
- GDB overlay for multiple, partial, and unaligned reads;
- required Flash BP strings in the built OpenOCD executable.

The host-side model does not replace N574 board-level testing.

## 11. Enabling and Using Flash BP

Start OpenOCD normally. For example:

```powershell
.\src\openocd.exe -s .\tcl -f interface\cmsis-dap.cfg -f target\numicroM0.cfg -d3 -l n574-flash-bp.log
```

After confirming that the target is an N574, explicitly enable the permitted banks and GDB fallback:

```gdb
monitor flash breakpoint cortex_m.flash_aprom enable
monitor flash breakpoint cortex_m.flash_ldrom enable
monitor gdb_flash_breakpoint_fallback enable
```

If a custom `CHIPNAME` is used, replace `cortex_m` with the actual bank prefix. Use the following command to list bank names:

```gdb
monitor flash banks
```

Query the current state with:

```gdb
monitor flash breakpoint cortex_m.flash_aprom
monitor flash breakpoint cortex_m.flash_ldrom
monitor gdb_flash_breakpoint_fallback
```

Disable the feature with:

```gdb
monitor gdb_flash_breakpoint_fallback disable
monitor flash breakpoint cortex_m.flash_aprom disable
monitor flash breakpoint cortex_m.flash_ldrom disable
```

Remove active breakpoints and confirm `CLEAR complete` before disabling the feature or terminating OpenOCD.

To force all GDB breakpoints to use software breakpoints instead of waiting for FPB exhaustion, issue the following only after the target configuration has loaded:

```text
gdb_breakpoint_override soft
```

## 12. Board-Level Validation

A recommended validation procedure is:

1. Connect GDB and program the original AXF image.
2. Reset and halt the target.
3. Enable APROM/LDROM Flash BP and GDB fallback.
4. Add hardware breakpoints until the FPB comparators are exhausted.
5. Add another breakpoint in enabled APROM.
6. Confirm `[FLASH-BP] FALLBACK`, `SET begin`, and `SET complete` in the log.
7. Read the physical breakpoint address with `monitor mdb <address> 2` and confirm `11 be`.
8. Continue execution and confirm the target stops at the Flash BP.
9. Delete the breakpoint and confirm `CLEAR complete`.
10. Read the physical address again and confirm the original instruction bytes were restored.
11. Test two Flash BPs in the same 512-byte sector and remove them independently.
12. Reprogram and verify the original AXF image before final execution testing.

## 13. Log Messages

All new runtime messages use the `[FLASH-BP]` prefix.

| Message | Meaning | Required action |
|---|---|---|
| `FALLBACK ... hardware-resource-exhausted` | FPB is full and Flash BP fallback is being attempted | Confirm a later `SET complete` |
| `FALLBACK failed` | Flash BP creation failed | Review halt, erase, program, and verify errors |
| `SET begin` | The sector is backed up and Flash BP programming is starting | Wait for completion |
| `SET verify passed` | Complete-sector read-back verification passed | Normal |
| `SET complete` | The Flash BP is active and recorded | Debugging may continue |
| `CLEAR begin` | Original instruction restoration is starting | Wait for completion |
| `CLEAR complete` | Original instruction was restored and the record removed | Safe to finish |
| `ROLLBACK` | A transaction failed and the original sector is being restored | Do not reset or remove power |
| `rollback completed` | The original sector was restored and verified | The requested BP operation still failed |
| `ROLLBACK FAILED` | Both the transaction and rollback failed | Do not run; reprogram the original image |
| `CLEAR conflict` | Flash no longer contains the expected breakpoint or original bytes | Do not overwrite; verify and reprogram firmware |
| `WORKING AREA RESTORE FAILED` | Application RAM could not be restored | Do not resume; reset and reload firmware |
| `target teardown with ... active` | OpenOCD is attempting final restoration | Wait for the result |
| `teardown restore failed` | Final restoration failed | Reprogram firmware before execution |

When FPB is exhausted, the existing breakpoint manager may first report that no comparator is available. If `[FLASH-BP] FALLBACK` and `SET complete` follow, the fallback succeeded.

## 14. Limitations and Safety Requirements

1. **Flash endurance:** Each Flash BP set and clear operation erases a complete sector. Prefer FPB and avoid frequent Flash BP cycling.
2. **No reset or power loss during transactions:** Do not reset, terminate OpenOCD, disconnect the probe, or remove target power during erase, program, verification, or rollback.
3. **No crash-persistent recovery:** Active records exist only in OpenOCD process memory. After an abnormal termination or power loss, reprogram the original image before execution.
4. **No concurrent programming:** Do not allow another debugger or programmer to modify flash while active Flash BPs exist.
5. **Rollback failure requires reprogramming:** A failed rollback may leave a sector erased or partially programmed.
6. **The target must be halted:** The NuMicro flash driver and working-area protection require a halted target.
7. **Only enabled NOR banks are handled:** RAM, unmapped addresses, zero-sized banks, and disabled banks never enter the Flash BP transaction path.
8. **Shared M0 configuration remains disabled:** N574-specific tooling must opt in explicitly.

## 15. Suggested Commit Message

```text
target: add transactional flash breakpoints for N574

Add an opt-in NOR flash software-breakpoint path for N574 when Cortex-M
FPB resources are exhausted.

- preserve the existing hardware and RAM breakpoint paths
- add per-bank Flash BP enable/disable commands
- rewrite, verify, and roll back complete flash sectors
- preserve and verify the complete target working area
- support multiple breakpoints in one sector and reject overlaps
- prevent stale breakpoint records from overwriting newer firmware
- restore active Flash BPs during target teardown
- fall back from GDB hardware breakpoints only on resource exhaustion
- return original instructions in GDB memory reads for disassembly
- read N574 LDROM through FMC ISP for backup and verification
- ignore zero-sized flash banks during address lookup

Flash BP remains disabled by default in the NOR core and the shared
NuMicro M0 target configuration. N574-specific tooling must explicitly
enable the APROM/LDROM banks and GDB fallback. Hardware FPB breakpoints
remain the first choice.
```
