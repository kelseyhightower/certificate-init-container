#! /usr/bin/env sh

DST=$(echo "${@}" | grep -oE '\-cert-dir=[^ ]*'| cut -d'=' -f2)
cp /var/run/secrets/kubernetes.io/serviceaccount/ca.crt "${DST}/"
/certificate-init-container "${@}"
