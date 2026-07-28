FROM golang:1-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

RUN apk add --no-cache build-base libpcap-dev
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY cmd ./cmd
COPY internal ./internal
COPY monitor ./monitor
COPY sample ./sample
COPY swucb ./swucb
COPY watch ./watch

RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/netbraid .

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

RUN apk add --no-cache ca-certificates libpcap
COPY --from=build /out/netbraid /usr/local/bin/netbraid

ENTRYPOINT ["/usr/local/bin/netbraid"]
