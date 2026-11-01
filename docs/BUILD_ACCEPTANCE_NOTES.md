# Native build and lifecycle acceptance notes

The fixed source is TOS `def735f3ad9c57a4b8fc8de43537075baec2271a` in a clean
detached worktree. The final native build uses Apple Clang and the installed
macOS SDK. CMake cache and executable/library hashes are recorded in the native
report. No TOS tracked source changes were needed.

The initial environment preferred Homebrew LLVM/binutils. The recorded attempts
found missing SDK headers, an LLVM/libc++ `INFINITY` mismatch, a compiler-change
CMake cache reset to Debug (which exposed the baseline dsymutil link rule), and
GNU archive indexes rejected by Apple's linker. A reindex attempt was insufficient
and led to empty/invalid dependency archives. These attempts are failures, not
validation passes.

The successful correction was explicit Apple C/C++ compilers, Release configuration,
SDKROOT, and rebuilding the copied OpenSSL/sodium/secp256k1 dependency trees with
Apple `ar`/`ranlib` (including regenerating autoconf/libtool settings for sodium and
secp256k1). Build output stayed outside the source checkout. The SDK emitted
deployment-target warnings for some dependency objects; cross-version macOS
qualification and hermetic dependency reproducibility are not claimed.

The final targets built were `func`, `fift`, `tol`, `emulator`, `tos-proof-verify`
and `test-proof-verify-embedded`. Use a clean source worktree and operator-controlled
compiler/SDK/archive tools; do not rely on the original machine's default PATH.

An initial frozen-account probe used the original deployment StateInit hash and
failed native transaction serialization. The corrected lifecycle fixture freezes
the executed wallet state, which contains replay history and differs from its
original initialization. Final frozen/absent/uninitialized probes and explicit
StateInit activation pass. Reinitialization can reset the chain replay bitmap;
the local journal never auto-resets.

An initial proof mutation flipped the last byte of a TL answer and was accepted.
That transport mutation was not established to alter authenticated content and
was not counted as a protection control. The final control corrupts the TL
constructor and requires native refusal; authenticated root/file/code/account
substitutions are independently tested. No security claim assumes every transport
byte is a signed consensus field.

`evidence/setup-attempts.json` retains transcript hashes and bounded diagnostic
extracts. Complete logs remain in the temporary build/test directories on the
validation machine. Successful source/binary behavior is recorded by actual
runner output, separately from this historical setup ledger.
