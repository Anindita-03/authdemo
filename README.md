# authdemo

A small auth API in Go: **Gin** (HTTP), **Ent** (ORM), **Atlas** (migrations), **PostgreSQL**.

| Endpoint | Auth | What it does |
|---|---|---|
| `POST /register` | – | create a user (password stored as a bcrypt hash) |
| `POST /login` | – | verify the password, return a session token |
| `GET /me` | Bearer token | return the logged-in user |
| `POST /logout` | Bearer token | revoke the session; the token stops working |
| `GET /health` | – | server + database check |

The token is random; only its SHA-256 hash is stored in `sessions`. Logout sets `revoked_at`.

## Run it

Prerequisites: Go, Docker, the [Atlas CLI](https://atlasgo.io/getting-started).

```bash
# 1. database (host port 5433 to avoid clashing with a local Postgres)
docker run --name authdemo-pg -e POSTGRES_PASSWORD=postgres -p 5433:5432 -d postgres:16
docker exec -it authdemo-pg psql -U postgres -c "CREATE DATABASE authdemo;"

# 2. create the tables from the committed migration
atlas migrate apply --dir "file://migrations" --url "postgres://postgres:postgres@localhost:5433/authdemo?sslmode=disable"

# 3. start the API (http://localhost:8080)
go run .
```

Optional env vars: `DATABASE_URL`, `PORT`.

Try it with `requests.http` (VS Code "REST Client" extension): register → login → paste the token → me → logout → me (now 401).

## Layout

```
main.go                    wiring + routes
internal/auth/handlers.go  register, login, me, logout
internal/auth/middleware.go RequireAuth (Bearer token -> session lookup)
ent/schema/                data model (User, Session) — edit, then `go generate ./ent`
ent/                       generated typed client (do not edit)
migrations/                Atlas SQL migrations
```

## Changing the schema

```bash
go generate ./ent
atlas migrate diff <name> --dir "file://migrations" --to "ent://ent/schema" --dev-url "docker://postgres/16/dev?search_path=public"
atlas migrate apply --dir "file://migrations" --url "postgres://postgres:postgres@localhost:5433/authdemo?sslmode=disable"
```
