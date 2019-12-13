FROM golang:1.12-buster as builder

ENV GOPROXY https://goproxy.io
ENV GO111MODULE on

WORKDIR /go/cache
COPY [ "go.mod","go.sum","./"]
RUN go mod download

WORKDIR /go/release
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o image-bouncer .

FROM alpine:3.10
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
WORKDIR /
COPY --from=builder /go/release/image-bouncer .
ENTRYPOINT ["/image-bouncer"]