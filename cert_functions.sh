HASH=sha256
ENC=aes256
BITS=4096

function create_cert_pair() {
	# create_cert_pair <name> <pass> <CN> [days - for self-signed only]
	[ -z "${3}" ] && return 1
	openssl genrsa -${ENC} -passout "pass:${2}" -out "${1}_key.pem" ${BITS} &&
	if [ -z "${4}" ]; then
		# csr
		openssl req -new -${HASH} -key "${1}_key.pem" -passin "pass:${2}" -out "${1}_csr.pem" -subj "${3}"
	else
		# self-signed
		openssl req -new -x509 -days "${4}" -${HASH} -key "${1}_key.pem" -passin "pass:${2}" -out "${1}_crt.pem" -subj "${3}"
	fi
}

function sign_cert() {
	# sign_cert <csr> <ca> <days> <ca-pass> [ extfile:extensions ]
	[ -z "${4}" ] && return 1
	if [ -z "${5}" ]; then
		# no extensions
		openssl x509 -req -${HASH} -in "${1}_csr.pem" -CA "${2}_crt.pem" -CAkey "${2}_key.pem" -passin "pass:${4}" -CAcreateserial -out "${1}_crt.pem" -days "${3}"
	else
		EXTFILE="-extfile ${5%%:*}"
		EXTENSIONS="${5##*:}"
		[ -n "${EXTENSIONS}" ] && EXTENSIONS="-extensions ${EXTENSIONS}"
		openssl x509 -req -${HASH} -in "${1}_csr.pem" -CA "${2}_crt.pem" -CAkey "${2}_key.pem" -passin "pass:${4}" -CAcreateserial -out "${1}_crt.pem" -days "${3}" ${EXTFILE} ${EXTENSIONS}
	fi
}

function create_signed_cert() {
	# create_signed_cert <name> <pass> <CN> <ca> <ca-pass> <days> [ extfile:extensions ]
	if ! diff -q \
		<( openssl rsa -in "${4}_key.pem" -passin "pass:${5}" -pubout 2> /dev/null ) \
		<( openssl x509 -in "${4}_crt.pem" -noout -pubkey ) 2> /dev/null; then
		echo "CA key doesn't match cert: ${4}" >&2
		return 1
	fi

	create_cert_pair "${1}" "${2}" "${3}" &&
	sign_cert "${1}" "${4}" "${6}" "${5}" "${@:7}"
}

function chain_PEM_to_JKS() {
	# PEMtoJKS <pem> <pass> <jks> <jks-pass> [chain pems ...]
	openssl pkcs12 -export -in "${1}_crt.pem" -inkey "${1}_key.pem" -passin "pass:${2}" -out "${1}.p12" -passout "pass:${2}" -name "${1}" -chain -CAfile <( for f in "${@:3}"; do echo "${f}_crt.pem"; done | xargs cat ) &&
	keytool -importkeystore -srckeystore "${1}.p12" -srcstoretype PKCS12 -srcstorepass "${2}" -destkeystore "${3}.jks" -deststoretype JKS -deststorepass "${4}" -noprompt
}

function add_PEM_to_JKS() {
	# add_pem_to_jks <pem> <jks> <jks-pass> [alias]
	keytool -import -trustcacerts -file "${1}_crt.pem" -alias "${4:-$1}" -keystore "${2}.jks" -storepass "${3}" -noprompt
}
