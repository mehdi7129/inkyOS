PYTHON ?= python3

.PHONY: help test fetch vm-start vm-stop inspect prototype

help:
	@echo 'make test     : tests locaux, sans image ni VM'
	@echo 'make fetch    : télécharger et vérifier la base officielle figée'
	@echo 'make vm-start : démarrer la VM Linux isolée inkyos-build'
	@echo 'make inspect  : vérifier le builder et inspecter la base en lecture seule'
	@echo 'make prototype: assembler une image système expérimentale sans app ni flash'
	@echo 'make vm-stop  : arrêter la VM de travail'

test:
	$(PYTHON) -m unittest discover -s tests -v
	@for script in scripts/*.sh; do bash -n "$$script" || exit; done

fetch:
	$(PYTHON) scripts/fetch-base.py --extract build/base.img

vm-start:
	limactl validate infra/lima.yaml
	@if [ "$$(limactl list --quiet inkyos-build)" = inkyos-build ]; then \
		limactl start --tty=false inkyos-build; \
	else \
		limactl start --tty=false --name=inkyos-build infra/lima.yaml; \
	fi

vm-stop:
	limactl stop --tty=false inkyos-build

inspect: vm-start
	bash scripts/inspect-base.sh

prototype: test vm-start
	bash scripts/build-prototype.sh
