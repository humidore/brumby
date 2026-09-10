ifeq ($(OS),Windows_NT)
    ACTIVATE:=.venv/Scripts/activate
else
    ACTIVATE:=.venv/bin/activate
endif

UV:=$(shell uv --version)
ifdef UV
	VENV:=uv venv
	PIP:=uv pip
	RUN:=uv run --extra dev --extra test
else
	VENV:=python -m venv
	PIP:=python -m pip
	RUN:=
endif

PY_FILES:=$(shell git ls-files '*.py')

.venv:
	$(VENV) .venv

.PHONY: setup
setup: .venv
	. $(ACTIVATE) && $(PIP) install -Ue .[dev,test]

.PHONY: test
test:
	$(RUN) python -m coverage run -m pytest $(TESTOPTS)
	$(RUN) python -m coverage report

.PHONY: format
format:
	$(RUN) ruff format $(PY_FILES)
	$(RUN) ruff check --fix $(PY_FILES)

.PHONY: lint
lint:
	$(RUN) ruff check $(PY_FILES)
	$(RUN) python -m checkdeps --allow-names brumby brumby
	$(RUN) mypy brumby
