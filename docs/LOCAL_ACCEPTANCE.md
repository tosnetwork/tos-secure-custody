# Local software acceptance and firmware-porting inputs

This increment adds optional **Pure ML-DSA-44 verification** using OpenSSL 3.5+,
native wallet/Vault tests and portable parser fixtures. The inspection APIs retain
their existing semantics. Separate verification reports mark cryptographic validity
against supplied keys while keeping state authentication, freshness, replay and signing
authorization false. No signer command or production approval path is added.

## Diagnostic verification

Configure an absolute path to an independently installed OpenSSL executable. No
request chooses its backend. Unsupported versions/providers, invalid signatures and
backend failures reject the request. Verification has a 15-second per-signature timeout;
multisig has at most 12 signatures. Public temporary inputs are removed after each call.

```sh
PYTHONPATH=src python3 -m tos_custody verify-highload submission.boc \
  --public-key public-key.raw --openssl /absolute/path/to/openssl
PYTHONPATH=src python3 -m tos_custody verify-multisig submission.boc \
  --context context.json --state account-data.boc --openssl /absolute/path/to/openssl
python3 scripts/check_crypto_vectors.py --openssl /absolute/path/to/openssl
```

Both commands also accept `--form relay`. Highload takes exactly 1312 public-key
bytes. Multisig verifies each signature against the corresponding key in supplied
account data, after the inspector checks exact OLD quorum, membership and seqno.
An attacker can supply their own account data and valid signatures: this does not
establish control of a deployed wallet. Neither output is a custody authorization.

The public signature fixtures use the pinned TOS **TEST ONLY** deterministic signer
keys 0, 21 and 22. No private key is exported; their seeds are public upstream.
Never fund these keys. The checker exercises real highload and multisig signatures,
tampered signature/message/key, cross-wallet context, zero signatures and altered
multisig context. Unit tests separately cover backend failure, timeout and API bounds.
The backend uses the standard ML-DSA-44 SPKI OID and Pure ML-DSA context encoding:
[OpenSSL ML-DSA documentation](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/).

## Native execution

Obtain a clean TOS checkout at `def735f3ad9c57a4b8fc8de43537075baec2271a`.
Keep build output outside that checkout. The runner checks HEAD and tracked changes
before importing its test code; the checkout and build are explicit operator inputs.

```sh
cmake -S /path/to/pinned-tos/test/pq-contracts -B /path/to/test-signer-build \
  -DCMAKE_BUILD_TYPE=Release
cmake --build /path/to/test-signer-build -j4
python3 scripts/check_native_custody.py --tos /path/to/pinned-tos --require-pinned-build \
  --build /path/to/tos-build --signer /path/to/test-signer-build/test-pq-contracts-sign \
  --openssl /absolute/path/to/openssl --report /path/to/native-report.json
```

The build must contain `crypto/func`, `crypto/fift` and an emulator shared library.
The runner first executes 44 upstream Vault scenarios (including actual Token wallets)
and all 21 upstream PQ wallet/cold Vault scenarios unchanged.
It then repeats seven supported integration scenarios with custody parser hooks
and three lifecycle/real-PQ-pauser scenarios: 21 highload request/preimage/signature
comparisons and seven multisig submission comparisons in the recorded run.
Signatures are independently verified with OpenSSL;
the native suites also check PQ opcode execution, emitted messages, role separation,
wrong-key rejection, old quorum, replay, delayed governance and payout state.

`evidence/native-conformance.json` records exact source digest and binary hashes.
The current local emulator/compiler binaries were built from the pinned checkout,
and their configured source path and CMake cache digest are recorded. Dependencies
and the host SDK/toolchain are not hermetically locked. Native execution is currently a separate local acceptance command;
the ordinary GitHub job does not silently count it as executed.

## Firmware-porting contract

`fixtures/portable-parser-corpus.json` contains exact BOC input, wallet form,
untrusted context where applicable, and the complete expected JSON interpretation.
It currently includes seven positive and six malformed-input cases. Run:

```sh
python3 scripts/check_portable_vectors.py
```

The corpus is language-neutral. A C/Rust/embedded implementation should reproduce
the same signing message, domains, addresses, amounts, action order and rejection
behavior. It supplements the larger Python adversarial suite; passing thirteen
vectors alone does not qualify a port. Changes to expected outputs require review.
The Python files do not become firmware automatically. A concrete device, memory
budget, display/buttons, boot/update boundary and protected signing API are still needed.

## Remaining local and external dependencies

RFC 0005 adds native finality/account proof integration, code/data binding and
durable conservative reservations. S1 stays open pending fresh custody-deployment
proof acceptance from an independently provisioned anchor, settlement/recovery
acceptance and non-author review. No arbitrary RPC JSON is accepted as a verdict.

The real HSM, protected PQ key generation/signing, device firmware, trusted display,
physical approval, hardware attestation, firmware reproducibility and physical attack
assessment require their corresponding devices/designs and evidence. Production
authorization stays blocked. The new macOS CI job verifies public signatures with
Homebrew OpenSSL; Homebrew/toolchain closure is not a hermetic release build.
