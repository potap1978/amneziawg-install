#!/bin/bash

AMNEZIAWG_DIR="/etc/amnezia/amneziawg"

function getHomeDirForClient() {
    local CLIENT_NAME=$1
    if [ -z "${CLIENT_NAME}" ]; then
	echo "Error: getHomeDirForClient() requires a client name as argument"
	exit 1
    fi

    if [ -e "/home/${CLIENT_NAME}" ]; then
	HOME_DIR="/home/${CLIENT_NAME}"
    elif [ "${SUDO_USER}" ]; then
	if [ "${SUDO_USER}" == "root" ]; then
	    HOME_DIR="/root"
	else
	    HOME_DIR="/home/${SUDO_USER}"
	fi
    else
	HOME_DIR="/root"
    fi
    echo "$HOME_DIR"
}

function loadParams() {
    source "${AMNEZIAWG_DIR}/params"
    SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"
}

function newClient() {
    # IPv6 → в квадратные скобки
    if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
	if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
	    SERVER_PUB_IP="[${SERVER_PUB_IP}]"
	fi
    fi
    ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

    echo ""
    echo "Client configuration"
    echo ""

    until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
	read -rp "Client name: " -e CLIENT_NAME
	CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "${SERVER_AWG_CONF}")
	if [[ ${CLIENT_EXISTS} != 0 ]]; then
	    echo "A client with this name already exists, please choose another."
	fi
    done

    for DOT_IP in {2..254}; do
	DOT_EXISTS=$(grep -c "${SERVER_AWG_IPV4::-1}${DOT_IP}" "${SERVER_AWG_CONF}")
	if [[ ${DOT_EXISTS} == '0' ]]; then
	    break
	fi
    done

    CLIENT_AWG_IPV4="$(echo "$SERVER_AWG_IPV4" | awk -F '.' '{print $1"."$2"."$3}').${DOT_IP}"
    CLIENT_AWG_IPV6="$(echo "$SERVER_AWG_IPV6" | awk -F '::' '{print $1}')::${DOT_IP}"

    CLIENT_PRIV_KEY=$(awg genkey)
    CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)
    CLIENT_PRE_SHARED_KEY=$(awg genpsk)

    HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

    cat >"${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_AWG_IPV4}/32,${CLIENT_AWG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}
EOF

    if [[ ${KEEPALIVE} -ne 0 ]]; then
	echo "PersistentKeepalive = ${KEEPALIVE}" >>"${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
    fi

    echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_AWG_IPV4}/32,${CLIENT_AWG_IPV6}/128" >>"${SERVER_AWG_CONF}"

    awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")

    echo "Client config created: ${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
}

function revokeClient() {
    NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
	echo "You have no existing clients!"
	exit 1
    fi

    echo "Select the client to revoke:"
    grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
    read -rp "Select client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER

    CLIENT_NAME=$(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

    sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "${SERVER_AWG_CONF}"

    HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
    rm -f "${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

    awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")

    echo "Client ${CLIENT_NAME} revoked."
}

function showClientQR() {
    NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
	echo "No existing clients!"
	exit 1
    fi

    echo "Select client to show QR:"
    grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
    read -rp "Select client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER

    CLIENT_NAME=$(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
    HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
    qrencode -t ansiutf8 < "${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
}

function manageMenu() {
    echo ""
    echo "AmneziaWG client management - Potap RULEZZZZZZ :)"
    echo "  1) Add new client"
    echo "  2) Revoke existing client"
    echo "  3) Show client QR"
    echo "  4) Exit"
    read -rp "Select an option [1-4]: " MENU_OPTION
    case "${MENU_OPTION}" in
	1) newClient ;;
	2) revokeClient ;;
	3) showClientQR ;;
	4) exit 0 ;;
    esac
}

loadParams
manageMenu
