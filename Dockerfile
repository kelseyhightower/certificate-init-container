FROM docker-registry.booking.com/hshabbir/centos:latest
ADD certificate-init-container /certificate-init-container
ENTRYPOINT ["/certificate-init-container"]
