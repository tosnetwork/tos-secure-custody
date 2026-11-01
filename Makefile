.PHONY: test inspect repro status

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

inspect:
	PYTHONPATH=src python3 -m tos_custody inspect-bundle examples/native-payment.offline.json

status:
	PYTHONPATH=src python3 -m tos_custody status

repro:
	python3 scripts/check_reproducible.py
