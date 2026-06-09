FROM golang:1-alpine
RUN apk add -u --no-cache build-base libpcap-dev && apk info -v
WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o main .
ENTRYPOINT ["./main"]
