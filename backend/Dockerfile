# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS build
WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY cmd ./cmd
RUN go build -o /app/api ./cmd/api \
 && go build -o /app/worker ./cmd/worker

FROM alpine:3.19
WORKDIR /app

COPY --from=build /app/api ./api
COPY --from=build /app/worker ./worker

EXPOSE 8080
ENV PORT=8080

CMD ["./api"]
