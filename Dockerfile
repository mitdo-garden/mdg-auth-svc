# syntax=docker/dockerfile:1
FROM golang:1.24-bookworm AS build
WORKDIR /src
ENV GOTOOLCHAIN=auto
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mdg-auth-svc ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/mdg-auth-svc /app/mdg-auth-svc
COPY configs /app/configs
ENV APP_ENV=test
EXPOSE 5001
USER nonroot:nonroot
ENTRYPOINT ["/app/mdg-auth-svc"]
