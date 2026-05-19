FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY *.go ./
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o gateway .

FROM alpine:3.20

RUN adduser -D appuser
WORKDIR /app
COPY --from=builder /app/gateway /app/gateway

USER appuser
EXPOSE 8080
ENV PORT=8080

CMD ["/app/gateway"]
