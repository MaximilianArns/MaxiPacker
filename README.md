# MaxiPacker
**Advanced Evasion & Offensive Packer Development**

This repository is based on the *Packer Development Workshop* authored by [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t) and [eversinc33](https://github.com/eversinc33) ([rtecCyberSec/Packer_Development](https://github.com/rtecCyberSec/Packer_Development/tree/master)). Using the C-logic from that framework as a foundation, I followed their roadmap and implemented custom features to create my own specialized version: **MaxiPacker**.

My primary contributions and custom implementations include **Hardware Breakpoints**, **Module Stomping**, and **API Hashing**. Additionally, I expanded upon the existing techniques in the source code, for instance by extending the number of native syscalls that can be invoked indirectly, completely bypassing the standard Windows API execution path.

---

## Key Implementations & Evasion Techniques

### 1. Hardware Breakpoints
Instead of modifying security-critical functions like `AmsiScanBuffer()` through traditional memory patching (which is highly visible to modern EDRs), MaxiPacker leverages the CPU's debug registers (`DR0`-`DR7`). By setting Hardware Breakpoints at the target function addresses, we can intercept the execution flow and manipulate the CPU state to spoof a "clean" scan result. This technique completely avoids modifying the function's bytes on disk or in memory, leaving a minimal footprint. Check out the `src/evasion/hwbp_amsi_etw.h` file.

**PoC:** `AmsiScanBuffer` targeted via `DR0` with `DR7` activation:
<img width="1711" height="911" alt="amsidllhwbpPoC" src="https://github.com/user-attachments/assets/89bb8e58-f571-45be-88ec-3664e46fffaa" />

### 2. Module Stomping
To avoid behavioral indicators associated with allocating fresh, untrusted memory pages for a payload, MaxiPacker implements Module Stomping. This technique loads a legitimate, digitally signed Windows DLL (such as `xpsprint.dll`) into the process memory and overwrites its legitimate code section with our payload. Because security products expect executable code to run from these verified modules, the payload blends seamlessly into normal process behavior. Check out the `src/auxiliary/stomping.h` file.

**PoC:** Executing a custom `calc.exe` payload generated via `msfvenom`:
<img width="1708" height="913" alt="DLL_StompingPoC" src="https://github.com/user-attachments/assets/793f77f6-b5d3-4d00-981b-461a1dcf9d37" />

### 3. API Hashing
To eliminate static string signatures of Windows APIs and DLL names within the binary, I implemented a custom API Hashing mechanism utilizing a unique salt. This required rewriting the memory lookup logic to dynamically resolve exports by comparing hashes rather than plaintext strings, significantly lowering the loader's static detection rate. Check out the new memory lookup logic here `src/auxiliary/helpers.h`.

---

## Academic Background & Documentation
This project served as my final graduation project for the Penetration Tester program at **IT-Högskolan**.

For an in-depth technical breakdown, architectural overviews and detailed explanations of my contributions, please refer to the full project documentation:
👉 [Read the Full Project Report (Google Docs)](https://docs.google.com/document/d/1VYUU8XZ0R326FmLdFww7yr4So18_P6aPLo_TzmZgN4w/edit?tab=t.0#heading=h.wml1h12dox33)

## Future Roadmap
MaxiPacker is an ongoing research project designed to test and understand defensive boundaries. As I continuously experiment with new bypasses, the code may evolve dynamically and may not always look complete.

**Next Milestone:** Implement remote payload staging. Staging the encrypted payload over the network (rather than embedding it within the loader) will further lower file entropy and eliminate the probability of static on-disk detection prior to execution.
