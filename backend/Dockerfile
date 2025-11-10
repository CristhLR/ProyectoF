# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /app/api ./cmd/api

FROM alpine:3.19
WORKDIR /app
COPY --from=build /app/api /app/api
EXPOSE 8080
CMD ["/app/api"]
