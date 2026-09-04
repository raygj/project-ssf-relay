FROM golang:1.26.6-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /ssf-relay ./cmd/ssf-relay

FROM alpine:3.20
RUN addgroup -S relay && adduser -S relay -G relay
COPY --from=builder /ssf-relay /usr/local/bin/ssf-relay
USER relay
ENTRYPOINT ["ssf-relay", "/etc/ssf-relay/config.yaml"]
