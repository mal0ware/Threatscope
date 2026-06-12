.PHONY: dev test demo desktop build seed setup

setup:
	python -m venv venv && . venv/bin/activate && pip install -r requirements.txt
	cd frontend && npm install

dev:
	python -m api.main & cd frontend && npm run dev

test:
	pytest

demo:
	python -m api.main --demo

desktop:
	cd frontend && npm run tauri dev

build:
	cd frontend && npm run tauri build

seed:
	python scripts/generate_demo_data.py
