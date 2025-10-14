# Build stage
FROM golang:1.24.6-alpine AS builder

# Install build tools for CGO
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the binary with CGO enabled
# -ldflags="-w -s" strips debug information and symbols, reducing the binary size
RUN go build -ldflags="-w -s" -o /certauth .

# Final stage
FROM alpine/curl:latest

WORKDIR /
COPY --from=builder /certauth /certauth
RUN chmod +x /certauth
COPY --from=builder /app/internal/certauth/views /internal/certauth/views
COPY --from=builder /app/internal/onboard/views /internal/onboard/views

# Expose the port the server runs on
EXPOSE 8090
EXPOSE 8091
EXPOSE 8092

# Run the binary
ENTRYPOINT ["/certauth"]