.PHONY: up down restart logs build clean sync-now

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

build:
	docker compose build --no-cache

logs:
	docker compose logs -f

sync-now:
	docker exec tib-collector python /app/collector.py --once

clean:
	docker compose down -v
	docker rmi tib-collector 2>/dev/null || true
