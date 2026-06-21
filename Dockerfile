FROM docker.io/library/node:24-alpine@sha256:156b55f92e98ccd5ef49578a8cea0df4679826564bad1c9d4ef04462b9f0ded6 AS js-builder
RUN apk add --no-cache make
RUN npm install -g pnpm@10.33.0
WORKDIR /app

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml rolldown.config.mjs Makefile ./
RUN pnpm install --ignore-scripts

COPY internal/server/pages/ internal/server/pages/
RUN make js-build
RUN make copy-htmx

FROM docker.io/library/golang:1.26-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS go-builder
RUN apk add --no-cache gcc musl-dev sqlite-dev
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go tool templ generate
COPY --from=js-builder /app/internal/server/pages/static/dist internal/server/pages/static/dist

ENV GOCACHE=/root/.cache/go-build
RUN --mount=type=cache,target="/root/.cache/go-build" CGO_ENABLED=1 go build -o /app/auth ./cmd/auth/...

FROM docker.io/library/alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache ca-certificates sqlite-libs
WORKDIR /app
COPY --from=go-builder /app/auth .
EXPOSE 1337
CMD ["./auth"]
