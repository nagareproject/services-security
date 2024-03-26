.PHONY: doc tests

clean:
	@rm -rf build dist
	@rm -rf src/*.egg-info
	@find src \( -name '*.py[co]' -o -name '__pycache__' \) -delete
	@rm -rf doc/_build/*

upgrade-precommit:
	python -m pre_commit autoupdate

install: clean
	python -m pip install -e '.[dev']
	git init
	python -m pre_commit install

tests:
	python -m pytest

qa:
	python -m ruff check src
	python -m ruff format --check src

qa-fix:
	python -m ruff check --fix src
	python -m ruff format src

doc:
	python -m sphinx.cmd.build -b html doc doc/_build

wheel:
	python -m pip wheel -w dist --no-deps .
