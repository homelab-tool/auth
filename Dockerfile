FROM node:22-alpine AS js-builder
RUN npm install -g pnpm@10.33.0
WORKDIR /app

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml rolldown.config.mjs ./
RUN pnpm install --ignore-scripts

COPY internal/server/pages/ internal/server/pages/
RUN pnpm build
RUN cp node_modules/htmx.org/dist/htmx.min.js internal/server/pages/static/dist/htmx.min.js

FROM golang:1.26-alpine AS go-builder
RUN apk add --no-cache gcc musl-dev sqlite-dev
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go tool templ generate
COPY --from=js-builder /app/internal/server/pages/static/dist internal/server/pages/static/dist

ENV GOCACHE=/root/.cache/go-build
RUN --mount=type=cache,target="/root/.cache/go-build" CGO_ENABLED=1 go build -o /app/auth ./cmd/auth/...

FROM alpine:3.21
RUN apk add --no-cache ca-certificates sqlite-libs
WORKDIR /app
COPY --from=go-builder /app/auth .
EXPOSE 1337
CMD ["./auth"]
