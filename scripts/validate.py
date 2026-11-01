"""Run actual unit tests; record counts and explicit unexecuted hardware gates."""
import datetime
import io
import json
import platform
import sys
import unittest
import cryptography
from source_bundle import ROOT, source_digest


def main():
    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(ROOT / "tests"))
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    text = stream.getvalue()
    print(text, end="")
    report = {"schema": "tos.custody.validation.v1", "source_digest": source_digest(ROOT),
              "recorded_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "python": platform.python_version(), "cryptography": cryptography.__version__,
              "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skips": len(result.skipped), "successful": result.wasSuccessful(),
              "evidence_level": "local software tests; synthetic fixtures and mocked HSM transport",
              "not_run": ["physical HSM", "offline device firmware", "ML-DSA hardware signing",
                          "TPM/DICE evidence verification", "native TVM end-to-end integration",
                          "firmware reproducibility", "independent security audit", "GitHub Actions CI"]}
    (ROOT / "evidence").mkdir(exist_ok=True)
    (ROOT / "evidence/unit-tests.txt").write_text(text)
    (ROOT / "evidence/validation.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return 0 if result.wasSuccessful() and not result.skipped else 1

if __name__ == "__main__":
    raise SystemExit(main())
