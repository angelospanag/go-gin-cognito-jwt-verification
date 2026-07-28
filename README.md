# go-gin-cognito-jwt-verification

A Go/Gin application demonstrating Cognito JWT verification middleware. Incoming requests to protected routes must carry a valid `Authorization: Bearer <token>` header. The middleware verifies the JWT against Cognito's public JWKS endpoint.

## Getting Started

[mise](https://mise.jdx.dev/) manages the pinned toolchain (Go 1.26, golangci-lint).

```bash
# macOS / Linux
curl https://mise.run | sh

# Windows
winget install jdx.mise
```

Activate mise in your shell (`~/.zshrc`):

```zsh
eval "$(mise activate zsh)"
```

Then, in the repo:

```bash
mise trust    # one-time
mise install  # downloads Go and golangci-lint
```

Create a `.env` file at the root of the project:

```dotenv
AWS_DEFAULT_REGION=us-east-1
COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
COGNITO_APP_CLIENT_ID=XXXXXXXXXXXXXXXXXXXXXXXXXX
```

Start the server:

```bash
mise run dev
```

## Routes

| Method | Path                            | Auth required |
|--------|---------------------------------|---------------|
| GET    | `/healthcheck`                  | No            |
| GET    | `/protected-with-id-token`      | Cognito ID token |
| GET    | `/protected-with-access-token`  | Cognito access token |

## Development

| Command          | Description                                 |
|------------------|---------------------------------------------|
| `mise run dev`   | Run without building a binary               |
| `mise run build` | Build the Go binary                         |
| `mise run test`  | Run tests                                   |
| `mise run fmt`   | Format code via `golangci-lint fmt`         |
| `mise run lint`  | Lint via `golangci-lint run`                |
| `mise run vuln`  | Scan dependencies for known vulnerabilities |
| `mise run deps`  | Update and tidy dependencies                |
| `mise run clean` | Remove build artifacts                      |
