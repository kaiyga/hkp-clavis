FROM golang:1.25-alpine AS builder
WORKDIR /app

RUN apk add --no-cache make

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN make build-static \
  && cp build/clavis /clavis \ 
  && chmod +x /clavis

FROM alpine:latest AS production
WORKDIR /app

COPY --from=builder /clavis /app/clavis

RUN apk update --no-cache && apk add --no-cache ca-certificates

ENV	LISTEN_ADDRESS=0.0.0.0 \ 
    LISTEN_PORT=3000  \ 
    POSTGRES_USER=root \
    POSTGRES_PASSWORD=Ch@nG!E.ME!!\ 
    POSTGRES_ADDRESS=postgresql \ 
    POSTGRES_PORT=5432 \
    POSTGRES_DATABASE="clavis" \
    VERIFY_DEFAULT=true

CMD ["/app/clavis"]
