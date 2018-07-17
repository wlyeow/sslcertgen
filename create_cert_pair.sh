#!/usr/bin/env bash

function usage() {
	exec >&2
	echo "Usage: $(basename $0) -n CN -f FILE [-h HASH:=sha256] [-b BITS:=4096] [-p PASSWORD [ -e ENC:=aes128 ]] [-r ROOT_DAYS]"
	exit 1
}

if [ $# -eq 0 ]; then
	usage
fi

while getopts "f:p:n:r:h:b:e:" OPT; do
	case $OPT in
		f)
			F_PREFIX=${OPTARG}
			;;
		p)
			PASSW=${OPTARG}
			;;
		n)
			CNAME=${OPTARG}
			;;
		r)
			RDAYS=${OPTARG}
			;;
		h)
			HASH=${OPTARG}
			;;
		b)
			BITS=${OPTARG}
			;;
		e)
			ENC=${OPTARG}
			;;
	esac
done

if [ -z "${F_PREFIX}" ] || [ -z "${CNAME}" ]; then
	usage
fi

source cert_functions.sh

_create_cert_pair "${F_PREFIX}" "${CNAME}" "${PASSW}" "${RDAYS}"
