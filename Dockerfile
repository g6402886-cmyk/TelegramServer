FROM golang:1.23-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go build -o /out/telegramserver ./cmd/telegramserver

FROM alpine:3.20

RUN adduser -D -H -u 10001 telegram
WORKDIR /app
COPY --from=build /out/telegramserver /usr/local/bin/telegramserver
RUN mkdir -p /data && chown -R telegram:telegram /data
USER telegram

EXPOSE 10443

ENTRYPOINT ["telegramserver"]
CMD ["-addr", ":10443", "-rsa-key", "/data/server_rsa_private.pem", "-rsa-public-key", "/data/server_rsa_public.pem"]
