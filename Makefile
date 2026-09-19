.PHONY: lint test vendor clean e2e_mock e2e_pester

export GO111MODULE=on

# Binary/mock suite (Traefik binary + mock LAPI). CI job "e2e (binary + mock LAPI)".
# Real-stack Pester suite (Docker Traefik + Crowdsec): make e2e_pester / tests/e2e/real/Test-Integration.ps1
E2E_MOCK_SCENARIOS := $(notdir $(wildcard tests/e2e/mock/scenarios/*))

default: lint test

lint:
	golangci-lint run

test:
	go test -v -cover ./...

yaegi_test:
	yaegi test -v .

e2e_mock: $(addprefix e2e_mock_,$(E2E_MOCK_SCENARIOS))

e2e_mock_%:
	bash ./tests/e2e/mock/scenarios/$*/run.sh

e2e_pester:
	pwsh -File ./tests/e2e/real/Test-Integration.ps1

vendor:
	go mod vendor

clean:
	rm -rf ./vendor

run_dev:
	docker compose -f docker-compose.dev.yml up -d --remove-orphans

run_local:
	docker compose -f docker-compose.local.yml up -d --remove-orphans

run_behindproxy:
	docker compose -f examples/behind-proxy/docker-compose.yml up -d --remove-orphans

run_cacheredis:
	docker compose -f examples/redis-cache/docker-compose.yml up -d --remove-orphans

run_trustedips:
	docker compose -f examples/trusted-ips/docker-compose.yml up -d --remove-orphans

run_binaryvm:
	cd examples/binary-vm/ && sudo vagrant up

run_tlsauth:
	docker compose -f examples/tls-auth/docker-compose.yml up  -d --remove-orphans

run_appsec:
	docker compose -f examples/appsec-enabled/docker-compose.yml up -d --remove-orphans

run_custom_captcha:
	docker compose -f examples/custom-captcha/docker-compose.yml up -d --remove-orphans

run_captcha:
	docker compose -f examples/captcha/docker-compose.yml up -d --remove-orphans

run_custom_ban_page:
	docker compose -f examples/custom-ban-page/docker-compose.yml up -d --remove-orphans

GEOBLOCK_TAG := v1.2.0
GEOBLOCK_DIR := examples/geoenrich-decisions/geoblock

run_geoenrich:
	@if [ ! -f "$(GEOBLOCK_DIR)/plugin.go" ]; then \
		git clone --depth 1 --branch $(GEOBLOCK_TAG) https://github.com/david-garcia-garcia/traefik-geoblock.git $(GEOBLOCK_DIR); \
	fi
	docker compose -f examples/geoenrich-decisions/docker-compose.yml up -d --remove-orphans

run:
	docker compose -f docker-compose.yml up -d --remove-orphans

restart_dev:
	docker compose -f docker-compose.dev.yml restart

restart_local:
	docker compose -f docker-compose.local.yml restart

restart:
	docker compose -f docker-compose.yml restart

restart_behindproxy:
	docker compose -f examples/behind-proxy/docker-compose.yml restart

restart_cacheredis:
	docker compose -f examples/redis-cache/docker-compose.yml restart

restart_trustedips:
	docker compose -f examples/trusted-ips/docker-compose.yml restart

restart_tlsauth:
	docker compose -f examples/tls-auth/docker-compose.yml

restart_appsec:
	docker compose -f examples/tls-auth/docker-compose.yml

restart_captcha:
	docker compose -f examples/captcha/docker-compose.yml

restart_custombanpage:
	docker compose -f examples/custom-ban-page/docker-compose.yml

restart_geoenrich:
	docker compose -f examples/geoenrich-decisions/docker-compose.yml

show_logs:
	docker compose -f docker-compose.yml restart

show_local_logs:
	docker compose -f docker-compose.local.yml logs -f

show_dev_logs:
	docker compose -f docker-compose.dev.yml logs -f

clean_all_docker:
	docker compose -f examples/behind-proxy/docker-compose.yml down --remove-orphans
	docker compose -f examples/redis-cache/docker-compose.yml down --remove-orphans
	docker compose -f examples/trusted-ips/docker-compose.yml down --remove-orphans
	docker compose -f examples/tls-auth/docker-compose.yml down --remove-orphans
	docker compose -f examples/appsec-enabled/docker-compose.yml down --remove-orphans
	docker compose -f examples/captcha/docker-compose.yml down --remove-orphans
	docker compose -f examples/custom-captcha/docker-compose.yml down --remove-orphans
	docker compose -f examples/custom-ban-page/docker-compose.yml down --remove-orphans
	docker compose -f examples/geoenrich-decisions/docker-compose.yml down --remove-orphans
	docker compose -f docker-compose.local.yml down --remove-orphans
	docker compose -f docker-compose.yml down --remove-orphans

clean_vagrant:
	cd examples/binary-vm/ && sudo vagrant destroy -f


show_metrics:
	docker exec crowdsec cscli metrics

show_decisions:
	docker exec crowdsec cscli decisions list
