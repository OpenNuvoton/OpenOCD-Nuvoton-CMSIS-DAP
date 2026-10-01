# N574 Flash 軟體斷點（Flash BP）

## 0. 變更摘要

本功能解決 N574 Cortex-M0 的 FPB（Flash Patch and Breakpoint）硬體斷點數量有限問題。既有硬體斷點仍具有最高優先權；只有 GDB 要求硬體斷點、FPB 資源已耗盡，而且目標地址位於明確啟用 Flash BP 的 NOR Flash bank 時，OpenOCD 才會把該次要求降級為 Flash 軟體斷點。

主要新增與修正如下：

- 新增 per-bank、預設關閉的 NOR Flash software breakpoint 功能。
- 新增 FPB 資源耗盡後的 opt-in GDB fallback。
- 以完整 sector transaction 設定及清除 Flash BP，包含 erase、program、read-back verify 與失敗 rollback。
- 保存並驗證還原完整 target working area，避免 Flash algorithm 破壞應用程式 RAM。
- 支援同一 sector 內多個 Flash BP，並拒絕互相重疊的 breakpoint。
- 清除前檢查實體 Flash，避免用舊 record 覆蓋已更新的 firmware。
- GDB memory read 回覆原始指令，避免 NUIDE／GDB 反組譯顯示暫存的 `BKPT 0x11`。
- 新增 N574 LDROM FMC ISP read，支援 LDROM 的 sector 備份、verify 與 rollback。
- 修正零容量或尚未 probe 的 Flash bank 可能錯誤匹配地址的問題。
- target teardown 時嘗試還原仍存在的 active Flash BP。

此功能**不取代 FPB**，而是 FPB 用完後的補充機制。由於 Flash BP 的 set 與 clear 都會擦除並重寫完整 sector，必須注意 Flash 壽命、操作期間供電，以及 OpenOCD 異常終止後的復原限制。

## 1. 目的與範圍

N574 為 Cortex-M0，FPB（Flash Patch and Breakpoint）硬體比較器數量有限。本修改保留原有 FPB 實作；當 GDB 要加入硬體斷點但 FPB 已用完時，才把該次要求降級為 Flash 軟體斷點。

Flash BP 會把目標指令暫時改成 Thumb `BKPT 0x11`（bytes `11 BE`），移除斷點時再還原原指令。

安全範圍如下：

- 原有 `BKPT_HARD` 設定與移除分支未修改。
- RAM 軟體斷點仍走原本的 memory read/write 路徑。
- 每個 Flash bank 的 Flash BP 預設關閉，只有明確執行 `flash breakpoint <bank_id> enable` 才會重寫該 bank。
- GDB 自動 fallback 也預設關閉；共用 Cortex-M0 target 設定保持兩個功能關閉，必須由 N574 專用設定、NUIDE 或使用者明確開啟。
- fallback 只在硬體斷點回傳 `ERROR_TARGET_RESOURCE_NOT_AVAILABLE`，而且地址位於已啟用 Flash BP 的 NOR Flash bank 時發生。

## 2. 實作內容

### 2.1 Flash sector transaction

設定或移除 Flash BP 時會執行完整 transaction：

1. 由地址找出 NOR Flash bank 與 sector。
2. 確認 target 已 halt，且 driver 提供 erase、write、read。
3. 讀取完整 sector 至 host RAM。
4. 只修改指定指令的 bytes。
5. 擦除完整 sector。
6. 寫回完整 sector。
7. 讀回完整 sector並逐 byte verify。
8. 任一步驟失敗時，嘗試用交易前的完整 sector 內容 rollback，並再次 verify。

N574 APROM 的 sector/page 為 512 bytes；實作不寫死 512，而是使用 Flash driver probe 後提供的 sector size。

Flash driver 會把演算法、資料及演算法 stack 放進 target 的 configured working area。Flash BP 在每次 sector transaction 前會先保存**完整 working area**，最後寫回並 read-back verify；此範圍包含 allocator 已分配區塊之間或尾端的 gap，因此即使 target cfg 使用 `-work-area-backup 0`，應用程式的 `.data`、`.bss` 與 stack 也不會被 Flash BP 留下的演算法內容覆蓋。若 working-area 備份無法讀取，Flash 尚未修改即中止；若 Flash 寫入成功但 RAM 還原失敗，會先把 Flash rollback，再重試 RAM 還原並回報錯誤。

### 2.2 多個斷點位於同一 sector

每次操作都先讀取「目前」完整 sector，再只改動該斷點的 2 bytes。因此同一 sector 可同時存在多個 Flash BP；移除其中一個時，其餘 Flash BP 會保留。

地址範圍互相重疊的 Flash BP 會被拒絕，避免其中一筆 record 保存到另一個 breakpoint 的 opcode，導致日後以錯誤內容還原。

每個 active Flash BP 另有 host-side record，保存：

- target 與地址；
- 指令長度；
- BKPT opcode；
- 原始指令 bytes。

正常移除失敗時，record 不會消失；OpenOCD target teardown 會嘗試 halt target 並再次還原所有 active Flash BP。

### 2.3 避免覆蓋新版 firmware

移除 Flash BP 前，會確認目前 Flash 內容仍是預期的 `11 BE`：

- 若已等於保存的原指令，視為已還原並清除 record。
- 若既不是 BKPT 也不是原指令，回報 `CLEAR conflict`，拒絕覆寫。

此檢查可避免 firmware 已被其他工具重燒後，OpenOCD 又把舊指令寫回去。

### 2.4 GDB／NUIDE 反組譯顯示

Flash BP 生效期間，目標 Flash 必須保留 Thumb `BKPT 0x11` 才能在執行時停住；但若把這兩個實體 bytes 原樣回覆給 GDB，NUIDE 的反組譯視窗會把原指令錯誤顯示成 `bkpt 0x0011`。

現在 GDB `m` memory-read packet 成功讀取目標後，OpenOCD 會用 active Flash BP record 修正**回覆 buffer**：

- read range 與 Flash BP 地址重疊時，以 record 保存的原始指令 bytes 覆蓋回覆內容；
- 支援一次讀取多個 breakpoint、未對齊及只讀到部分指令的情況；
- 只有實際讀回的 bytes 仍符合已記錄的 BKPT opcode 才覆蓋，避免 stale record 隱藏外部重燒的新內容；
- 不改動目標 Flash，因此 breakpoint 執行功能不受影響。

NUIDE／GDB 反組譯應看到 AXF 的原始組語；`monitor mdb <address> 2` 直接走 OpenOCD monitor 讀取，仍可用來確認目標 Flash 中的實體 `11 be`。

### 2.5 GDB fallback

N574 Cortex-M0 設定保留：

```tcl
gdb_breakpoint_override hard
```

因此 GDB breakpoint 仍先要求硬體斷點。共用 `numicroM0.cfg` 明確保持 Flash BP 關閉：

```tcl
flash breakpoint $_CHIPNAME.flash_aprom disable
flash breakpoint $_CHIPNAME.flash_ldrom disable
gdb_flash_breakpoint_fallback disable
```

確認 target 是 N574 且允許改寫 Flash 後，必須由 N574 專用 board/target cfg、NUIDE 或 GDB monitor 將 APROM／LDROM bank 與 GDB fallback 明確設為 `enable`。

N574 device table 的 SPROM size 為 0，因此不啟用 SPROM Flash BP；NOR core 的地址查找也會忽略零長度 bank，避免 RAM 等高位址被誤判成 Flash。

流程為：

```text
GDB Z1 → 原有 FPB 設定
              │
              ├─ 成功：使用硬體斷點，不寫 Flash
              │
              └─ FPB 資源不足
                    │
                    ├─ 地址不在已啟用的 NOR bank：維持原錯誤
                    │
                    └─ 地址在已啟用的 NOR bank：以 BKPT_SOFT 重試並執行 sector transaction
```

## 3. 修改位置

- `src/flash/nor/core.c`、`src/flash/nor/core.h`
  - 在 `struct flash_bank` 新增 per-bank `breakpoints_enabled` 狀態，預設為關閉。
  - 新增 Flash BP 地址與 sector 定位、完整 sector transaction、read-back verify、rollback、active records、GDB read overlay 與 target teardown restore API。
  - 保存、還原並 verify target 完整 configured working area。
  - 將 Flash bank 地址判斷由 `addr <= base + size - 1` 改為 `size && addr >= base && addr - base < size`，避免 `size == 0` 時 unsigned underflow，也避免地址上限加法 overflow。
- `src/flash/nor/tcl.c`
  - `flash breakpoint bank_id enable|disable` 命令。
- `src/flash/nor/numicro_dap.c`
  - 新增 `numicro_dap_read()`。
  - 只有 N574 LDROM 改用 FMC ISP command 逐字讀取；其他 NuMicro device 與其他 bank 仍回到 `default_flash_read()`。
  - 讓 N574 LDROM 可以執行 Flash BP 所需的 sector backup、read-back verify 與 rollback。
- `src/target/cortex_m.c`
  - 只在 `BKPT_SOFT` 路徑辨識 NOR Flash；非 Flash 地址回到原 RAM 路徑。
  - 原有 `BKPT_HARD` set/unset 分支保持不變。
  - Thumb 地址改用 `address & ~(target_addr_t)1` 對齊，避免固定 32-bit mask 截斷較寬的 target address。
  - target teardown 時嘗試還原 active Flash BP。
- `src/server/gdb_server.c`
  - `gdb_flash_breakpoint_fallback enable|disable` 命令。
  - FPB 資源不足後的 opt-in fallback。
  - GDB memory-read 回覆送出前套用 Flash BP 原始指令，讓反組譯不顯示暫存的 BKPT。
- `tcl/target/numicroM0.cfg`
  - APROM、LDROM Flash BP 與 GDB fallback 明確保持關閉，維持所有共用 M0 target 的原始行為。
  - N574 由專用 board/target cfg、NUIDE 或使用者明確啟用後，才採用「FPB 優先、用完才 Flash BP」。
- `doc/openocd.texi`
  - 新增 `flash breakpoint` 與 `gdb_flash_breakpoint_fallback` 使用說明。
- `doc/N574_FLASH_BP.md`
  - 本設計、使用、限制、測試及 GitHub 變更說明文件。
- `testing/n574_flash_breakpoint_regression.py`
  - 全新 host-side source wiring 與 fault-injection regression。

### 3.1 GitHub 正式功能檔案

以下七個 source/config 檔案是一組完整功能，應在同一個 commit 中上傳，不可只挑部分檔案：

| 檔案 | 必要原因 |
|---|---|
| `src/flash/nor/core.c` | Flash BP transaction、record、verify、rollback、working-area 保護與地址判斷修正 |
| `src/flash/nor/core.h` | `struct flash_bank` enable 欄位與 Flash BP public API |
| `src/flash/nor/tcl.c` | 註冊 `flash breakpoint` 命令 |
| `src/flash/nor/numicro_dap.c` | N574 LDROM FMC ISP read |
| `src/target/cortex_m.c` | Cortex-M software breakpoint 與 Flash/RAM 分流，以及 teardown restore |
| `src/server/gdb_server.c` | GDB fallback、控制命令與 disassembly read overlay |
| `tcl/target/numicroM0.cfg` | APROM／LDROM 與 GDB fallback 的安全預設關閉設定 |

建議同一 commit 一併上傳：

| 檔案 | 用途 |
|---|---|
| `doc/openocd.texi` | OpenOCD command reference |
| `doc/N574_FLASH_BP.md` | 功能設計、操作與風險說明 |
| `doc/N574_FLASH_BP_EN.md` | English design, usage, risk, and validation guide |
| `testing/n574_flash_breakpoint_regression.py` | 不需硬體的 source wiring 與 fault-injection regression |

### 3.2 不納入正式功能 commit

下列檔案不是目前已接線的 runtime 功能，不應納入本次正式 commit：

- `src/target/flashbp_journal.c`
- `src/target/flashbp_journal.h`
- `src/openocd-flashbp-journal-fix.zip`
- `src/openocd-flashbp-step-fix.zip`
- `src/openocd.zip`
- `.vscode/`、`.codebase-memory/`
- `*.bak`、編譯產物、generated Makefile/config 檔案

`flashbp_journal.c/.h` 是規劃中的 host persistent journal，但目前沒有加入 `Makefile.am`，也沒有任何 production source 呼叫其 API，因此不會被編譯或執行。現行正式功能只保證 OpenOCD process 存活期間的 transaction rollback；強制結束 OpenOCD、PC 當機或板端斷電後，不能依靠這兩個未接線檔案自動復原。

`make_openocd.bat`、`build_openocd.py` 等本機 build helper 不影響 OpenOCD runtime；只有團隊決定把它們作為共同建置入口時，才應另行 review 並提交。

### 3.3 對既有基本功能的影響

| 既有功能 | 影響 |
|---|---|
| Cortex-M hardware breakpoint | 原有 `BKPT_HARD` set/unset 分支不變；FPB 有空間時不寫 Flash |
| RAM software breakpoint | 保留原本 `target_read_memory()`／`target_write_memory()` 路徑；非已啟用 NOR bank 會回到原路徑 |
| 其他 NuMicro Flash read | `numicro_dap_read()` 只特別處理 N574 LDROM；其他 device/bank 使用 `default_flash_read()` |
| 未啟用的 Flash bank | 不執行 sector transaction |
| GDB fallback | 預設關閉；只有設定檔或使用者明確 enable 後才生效 |
| GDB memory read | 無 active Flash BP 時內容不變；有 active record 時只把仍符合 BKPT opcode 的重疊 bytes 換回原指令 |
| OpenOCD monitor `mdb` | 不套用 GDB overlay，可讀到實體 `11 be` |
| target teardown | 沒有 active Flash BP 時無額外動作；有 active record 時會嘗試 halt、還原並視原狀態 resume |

需要特別注意：

1. `numicroM0.cfg` 是共用設定，因此保持 APROM／LDROM Flash BP 與全域 GDB fallback 關閉；N574 必須在辨識裝置後明確啟用。
2. `gdb_flash_breakpoint_fallback` 是 OpenOCD process 的全域開關；真正寫入 Flash 前仍會檢查 containing bank 的 per-bank enable 狀態。
3. `struct flash_bank` layout 已變更，合併後第一次必須 clean rebuild，不能混用舊 object。
4. N574 LDROM read 現在要求 target halted，並操作 FMC ISP registers；這項行為應以 N574 實機驗證。

## 4. 編譯與 host-side regression

在 repository 根目錄使用專案既有的標準流程執行 clean build。例如已保留本專案 build helper 時：

```powershell
python .\build_openocd.py --clean --jobs 2
```

若未提交該 helper，請改用 repository 原有的 bootstrap/configure/make 流程並先執行 clean。本次在 `struct flash_bank` 新增 per-bank enable 欄位；既有 build tree 第一次編譯必須清除舊 object，避免新舊結構 layout 不一致。之後未再切換 source 版本時才可使用增量編譯。

執行不需要硬體的 regression：

```powershell
python .\testing\n574_flash_breakpoint_regression.py --openocd .\src\openocd.exe
```

regression 會檢查：

- Cortex-M 硬體斷點 set/unset 分支與 Git HEAD 完全相同。
- Flash BP 與 RAM BP 分流仍存在。
- GDB fallback 只受資源不足、硬體類型、兩個 enable 開關及 NOR bank 限制。
- 完整 sector 的 erase/write/read-back/verify/rollback wiring。
- 單一與同 sector 多個 breakpoint 的 set/clear。
- erase、program、verify failure 的 rollback。
- Flash 演算法即使覆寫完整 4 KiB working area，正常完成、rollback 與反覆 set/clear 後 RAM 都會還原。
- firmware content conflict 時拒絕覆寫。
- target teardown 還原 wiring。
- GDB read-buffer 對多個、部分及未對齊 Flash BP 的原始指令 overlay。

此 regression 使用 fault-injection NOR model，不取代真實 N574 板端測試。

## 5. 啟動 OpenOCD

範例：

```powershell
.\src\openocd.exe -s .\tcl -f interface\cmsis-dap.cfg -f target\numicroM0.cfg -d3 -l n574-flash-bp.log
```

- `-d3` 顯示 sector erase/program/verify 的 debug log。
- `-l n574-flash-bp.log` 將完整 log 留給問題分析。
- 共用 `numicroM0.cfg` 預設關閉此功能。確認 target 是 N574 後，必須對允許改寫的 bank 執行 `flash breakpoint <bank_id> enable`，並執行 `gdb_flash_breakpoint_fallback enable`。

可從 GDB 明確啟用：

```gdb
monitor flash breakpoint cortex_m.flash_aprom enable
monitor flash breakpoint cortex_m.flash_ldrom enable
monitor gdb_flash_breakpoint_fallback enable
```

若前端要讓所有 GDB breakpoint 直接使用軟體斷點，而非等待 FPB 耗盡，可在載入 target cfg **之後**覆寫：

```text
gdb_breakpoint_override soft
```

尚未 probe 或 probe 後容量為 0 的 bank 不會匹配任何 Flash BP 地址。target 已 examine 後執行 `flash breakpoint <bank_id> enable` 時會先確認 probe 結果；probe 失敗或容量仍為 0 會明確拒絕並關閉該 bank 的 pending enable 狀態。不要對 `flash list` 顯示 `size 0x0` 的 bank 設定斷點。

可由 GDB 查詢目前狀態：

```gdb
monitor flash breakpoint cortex_m.flash_aprom
monitor gdb_flash_breakpoint_fallback
```

若有設定自訂 `CHIPNAME`，請把 `cortex_m` 換成實際 bank 名稱；可用 `monitor flash banks` 查詢。

暫時關閉：

```gdb
monitor gdb_flash_breakpoint_fallback disable
monitor flash breakpoint cortex_m.flash_aprom disable
monitor flash breakpoint cortex_m.flash_ldrom disable
```

若已有 active Flash BP，應先刪除斷點，確認 `CLEAR complete` 後再關閉或結束 OpenOCD。

## 6. 使用 Template.axf 驗證

本次提供的 image：

- `<path-to-image>\Template.axf`
- 對應 source：`<path-to-source>\main.c`

目前 AXF 的關鍵 Thumb 地址如下；若重新編譯 AXF，地址可能改變，應重新用 `arm-none-eabi-nm` / `arm-none-eabi-objdump` 確認。

| 位置 | 地址 |
|---|---:|
| `Op_Add` | `0x000003E8` |
| `Op_Mul` | `0x000003F8` |
| `Op_Sub` | `0x00000408` |
| `WatchTest` | `0x000005FC` |
| `main` | `0x0000071C` |
| `WatchTest()` 呼叫後的指令 | `0x00000752` |

連線及重新燒錄：

```gdb
arm-none-eabi-gdb <path-to-image>\Template.axf
(gdb) target extended-remote :3333
(gdb) monitor reset halt
(gdb) load
(gdb) monitor reset halt
```

依序加入多個硬體斷點，直到超過 FPB 數量：

```gdb
(gdb) hbreak *0x000003e8
(gdb) hbreak *0x000003f8
(gdb) hbreak *0x00000408
(gdb) hbreak *0x000005fc
(gdb) hbreak *0x0000071c
(gdb) hbreak *0x00000752
(gdb) info breakpoints
```

前面的斷點使用原有 FPB；第一個超過 FPB 容量且位於 APROM 的地址會出現 `[FLASH-BP] FALLBACK`，接著出現 `SET begin` 與 `SET complete`。

實際 Flash bytes 可透過 OpenOCD monitor 讀取：

```gdb
(gdb) monitor mdb 0x00000752 2
```

若該地址是 fallback 的 Flash BP，應看到 `11 be`。刪除對應 breakpoint 後：

```gdb
(gdb) delete <breakpoint-number>
(gdb) monitor mdb 0x00000752 2
```

`0x00000752` 的原始指令為 Thumb `E7FF`，little-endian bytes 應還原為 `ff e7`。

也可從 OpenOCD telnet/monitor 手動建立 Flash 軟體斷點；`bp` 未加 `hw` 即為 software breakpoint：

```text
bp 0x00000752 2
rbp 0x00000752
```

## 7. Log 判讀

所有新增的 runtime log 都有 `[FLASH-BP]` prefix。

| Log 關鍵字 | 意義 | 建議處理 |
|---|---|---|
| `FALLBACK ... hardware-resource-exhausted` | FPB 已用完，開始嘗試 Flash BP | 預期行為；確認後續有 `SET complete` |
| `FALLBACK failed` | 已進入 fallback，但 Flash BP 設定失敗 | 依同一段 log 的 target halt、erase/program/verify 訊息排除問題 |
| `SET begin` | 已保存 sector，準備寫入 BKPT | 等待 erase/program/verify |
| `SET erase` / `SET program` | 正在重寫完整 sector | debug level 3 才會顯示 |
| `SET verify passed` | 完整 sector read-back 一致 | 正常 |
| `saved working area` | 已保存 Flash 演算法可能使用的完整 RAM 工作區 | debug level 3 才會顯示 |
| `working-area restore passed` | 工作區已寫回並完整 read-back verify | debug level 3 才會顯示 |
| `WORKING AREA RESTORE FAILED` | 工作區重試還原仍失敗，應用程式 RAM 可能已損壞 | 不可 resume；reset 並重新下載 firmware |
| `SET complete` | Flash BP 已生效且 record 已建立 | 可繼續 debug |
| `CLEAR begin` | 準備還原原指令 | 等待 verify |
| `CLEAR complete` | 原指令已還原且 record 已移除 | 可安全結束 |
| `ROLLBACK` | 原交易失敗，正在還原交易前完整 sector | 不要 reset、斷電或拔除 probe |
| `rollback completed` | rollback 已 verify 成功 | 該次 breakpoint 操作仍失敗，但原 sector 已恢復 |
| `ROLLBACK FAILED` | 原交易與 rollback 都失敗 | 不可執行程式；立即重燒原始 AXF/firmware |
| `CLEAR conflict` | Flash 不再是預期 BKPT，可能已被重燒或外部修改 | 不覆寫；確認 image 後完整重燒 |
| `target must be halted` | target 正在執行 | halt 後重試 |
| `target teardown with ... active` | 關閉 target 時仍有 Flash BP | OpenOCD 正在做最後還原嘗試 |
| `teardown restore failed` | 結束前仍無法還原 | 重新燒錄 firmware 後才可執行 |

FPB 耗盡時，既有 breakpoint manager 可能先輸出：

```text
Can not find free FPB Comparator!
can't add breakpoint: resource not available
```

若緊接著看到 `[FLASH-BP] FALLBACK` 與 `SET complete`，表示 fallback 成功，前兩行是第一次硬體斷點嘗試的診斷，不代表最終設定失敗。

`SET verify passed`、`saved working area` 與 `working-area restore passed` 使用 debug level 3；以 `-d2` 啟動時不會顯示，但完整 sector 與 working-area read-back verify 仍會執行。

## 8. 重要限制與安全注意事項

1. **Flash 壽命**：每次 Flash BP set/clear 都會各擦除一次完整 sector。頻繁單步、反覆 enable/disable 會消耗 erase cycles；優先使用 FPB，Flash BP 只作為容量不足時的補充。
2. **操作期間不可斷電**：erase/program/rollback 進行時不可 reset、關閉 OpenOCD、拔除 probe 或讓板子失去電源。
3. **程序 crash 無法保證復原**：active record 位於 OpenOCD host memory。若 OpenOCD process 被強制終止、PC 當機或板子斷電，record 會遺失；再次執行程式前必須重燒原始 image。
4. **不要同時燒錄**：active Flash BP 存在時，不要由另一個 debugger/programmer 修改 Flash。要重新下載 firmware，先刪除全部 breakpoint並確認 `CLEAR complete`。
5. **rollback failed 必須重燒**：完整 sector 可能已部分擦除或寫壞，不可直接 resume。
6. **target 必須 halt**：N574 Flash driver 需要 halted target及 RAM working area；預設 `numicroM0.cfg` 提供 4 KiB working area。Flash BP 會保存並驗證還原完整 4 KiB，不依賴 cfg 的 `-work-area-backup` 值。
7. **只處理已設定的 NOR bank**：RAM、未映射區域及非 NOR 地址不會進入 Flash transaction。

## 9. 建議的板端驗收條件

- FPB 容量內的所有斷點均無 `[FLASH-BP] SET`，且既有硬體 breakpoint 行為正常。
- 超過 FPB 容量的第一個 APROM breakpoint 有 `FALLBACK`、`SET complete`，實體 bytes 為 `11 be`。
- 刪除該 breakpoint 後有 `CLEAR complete`，實體 bytes 回到 AXF 內容。
- 同一 512-byte sector 設兩個 Flash BP，個別刪除其中一個不影響另一個。
- `continue` 可停在 Flash BP；正常 GDB step/remove 流程後原指令仍正確。
- 關閉 GDB/OpenOCD 前沒有 active Flash BP，或 teardown log 顯示全部還原成功。
- 最後重新燒錄並 verify `Template.axf`，確認裝置可正常執行。

## 10. 建議 GitHub commit message

建議使用以下英文 commit message：

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

若希望 commit title 明確標示 NuMicro，也可使用：

```text
target/numicro: add N574 flash breakpoint fallback
```

建議不要在此 commit 混入 KM1M driver、M23/M33/M55 target cfg、GitHub Actions、build archive 或尚未接線的 persistent journal 修改，讓功能範圍與 regression 容易 review 及回溯。
