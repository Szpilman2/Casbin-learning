# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install git (required by Go modules) and gcc for any dependencies
RUN apk add --no-cache git gcc musl-dev

COPY ../go.mod ../go.sum ./
RUN go mod download

COPY . .

RUN go build -o app main.go

# Final stage
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/app .
COPY rbac_model.conf .
COPY policy.csv .

# Expose any ports if your app runs a server (optional)
EXPOSE 8080

CMD ["./app"]
