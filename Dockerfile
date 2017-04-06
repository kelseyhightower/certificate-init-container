FROM alpine
ADD gopath/bin/certificate-init-container /certificate-init-container
ENTRYPOINT ["/certificate-init-container"]
