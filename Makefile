PYTHON ?= python3

.PHONY: help test test-linux bootstrap-probe test-ssh-probe fetch vm-start vm-stop inspect prototype application-prototype sd-diagnostic test-lan-prepared

help:
	@echo 'make test     : tests locaux, sans image ni VM'
	@echo 'make test-linux: mêmes fixtures dans Linux ARM64, avec preuves et entrées hashées'
	@echo 'make bootstrap-probe: vrais UID/reçu root dans la VM dédiée, heure et radio simulées'
	@echo 'make test-ssh-probe: vrai SSH/PAM sur copie jetable de PARENT_EXPORT, runner d activation inerte'
	@echo 'make fetch    : télécharger et vérifier la base officielle figée'
	@echo 'make vm-start : démarrer la VM Linux isolée inkyos-build'
	@echo 'make inspect  : vérifier le builder et inspecter la base en lecture seule'
	@echo 'make prototype: assembler une image système expérimentale sans app ni flash'
	@echo 'make application-prototype: intégrer APPLICATION_MANIFEST, APPLICATION_SHA256, APPLICATION_ASSETS ; démarrage app masqué'
	@echo 'make sd-diagnostic: dériver PARENT_EXPORT en image de diagnostic SD avec rapport et arrêt automatique ; aucun flash'
	@echo 'make test-lan-prepared: dériver PARENT_EXPORT en variante TEST LAN inerte avec preflight ; aucun flash/activation'
	@echo 'make vm-stop  : arrêter la VM de travail'

test:
	$(PYTHON) -m unittest discover -s tests -v
	@for script in scripts/*.sh; do bash -n "$$script" || exit; done

test-linux: vm-start
	bash scripts/test-linux.sh

bootstrap-probe: vm-start
	bash scripts/probe-bootstrap.sh

test-ssh-probe: vm-start
	PYTHON="$(PYTHON)" bash scripts/probe-test-ssh.sh "$(PARENT_EXPORT)"

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

sd-diagnostic: test test-linux
	PYTHON="$(PYTHON)" bash scripts/build-sd-diagnostic.sh "$(PARENT_EXPORT)"

test-lan-prepared: test test-linux
	PYTHON="$(PYTHON)" bash scripts/build-test-lan.sh "$(PARENT_EXPORT)"
