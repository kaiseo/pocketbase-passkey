# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o pocketbase-passkey main.go passkey.go

# Final stage
FROM alpine:latest

WORKDIR /app

# Install certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Copy the binary from builder
COPY --from=builder /app/pocketbase-passkey .
# Copy static files (demo)
COPY pb_public ./pb_public

# Create a directory for data persistence
RUN mkdir -p /app/pb_data

EXPOSE 8090

# Command to run
ENTRYPOINT ["./pocketbase-passkey", "serve", "--http=0.0.0.0:8090", "--dir=/app/pb_data"]
