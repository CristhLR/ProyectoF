# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN go build -o /app/api ./cmd/api
RUN go build -o /app/worker ./cmd/worker
RUN go build -o /app/seed ./cmd/seed

FROM alpine:3.19
WORKDIR /app

COPY --from=build /app/api ./api
COPY --from=build /app/worker ./worker
COPY --from=build /app/seed ./seed

EXPOSE 8080
ENV PORT=8080

CMD ["./api"]
