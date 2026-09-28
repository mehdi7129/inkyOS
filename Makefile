PYTHON ?= python3

.PHONY: help test test-linux bootstrap-probe fetch vm-start vm-stop inspect prototype application-prototype

help:
	@echo 'make test     : tests locaux, sans image ni VM'
	@echo 'make test-linux: mêmes fixtures dans Linux ARM64, avec preuves et entrées hashées'
	@echo 'make bootstrap-probe: vrais UID/reçu root dans la VM dédiée, heure et radio simulées'
	@echo 'make fetch    : télécharger et vérifier la base officielle figée'
	@echo 'make vm-start : démarrer la VM Linux isolée inkyos-build'
	@echo 'make inspect  : vérifier le builder et inspecter la base en lecture seule'
	@echo 'make prototype: assembler une image système expérimentale sans app ni flash'
	@echo 'make application-prototype: intégrer APPLICATION_MANIFEST, APPLICATION_SHA256, APPLICATION_ASSETS ; démarrage app masqué'
	@echo 'make vm-stop  : arrêter la VM de travail'

test:
	$(PYTHON) -m unittest discover -s tests -v
	@for script in scripts/*.sh; do bash -n "$$script" || exit; done

test-linux: vm-start
	bash scripts/test-linux.sh

bootstrap-probe: vm-start
	bash scripts/probe-bootstrap.sh

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

prototype: test test-linux
	bash scripts/build-prototype.sh

application-prototype: test test-linux
	bash scripts/build-prototype.sh --application-manifest "$(APPLICATION_MANIFEST)" \
	  --application-sha256 "$(APPLICATION_SHA256)" --assets-dir "$(APPLICATION_ASSETS)"
