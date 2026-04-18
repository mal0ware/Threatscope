.PHONY: dev test demo desktop build seed setup

setup:
	python -m venv venv && . venv/bin/activate && pip install -r requirements.txt
	cd frontend && npm install

dev:
	python api/main.py & cd frontend && npm run dev

test:
	pytest && cd frontend && npm run test

demo:
	python api/main.py --demo

desktop:
	cd frontend && npm run tauri dev

build:
	cd frontend && npm run tauri build

seed:
	python scripts/generate_demo_data.py
