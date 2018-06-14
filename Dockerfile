FROM golang as builder

WORKDIR /go/src/github.com/kelseyhightower/certificate-init-container
COPY . /go/src/github.com/kelseyhightower/certificate-init-container/
RUN go get -d -v
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo .

FROM scratch
COPY --from=builder /go/src/github.com/kelseyhightower/certificate-init-container/certificate-init-container /certificate-init-container
ENTRYPOINT ["/certificate-init-container"]
