FROM golang:alpine

WORKDIR /go/src/app

COPY . .

RUN go build

ENTRYPOINT [ "./duckcoin" ]

