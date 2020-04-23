#!/bin/bash

DATA_DIR=/usr/local/waent/data
WWW_CONF=/etc/lighttpd/lighttpd.conf
CERT_DIR=${DATA_DIR}/certs/external
CERT_FILENAME=www.cert
CERT_CA_FILENAME=ca.pem
SERVERNAME_FILE=${CERT_DIR}/.servername
FPM_CONF_FILE=/etc/php/7.0/fpm/pool.d/www.conf

SED_CMDS=/tmp/sed.cmds

PROGNAME=$(basename "$0")
LOCKFILE_DIR=${DATA_DIR}
LOCK_FD=300

WHOAMI_FILE=/tmp/whoami.txt
HTTP_ROOT=/var/www/html
CERT_DIR_STAGING=/tmp
CERT_DIR_INSTALLED=/var/lib/whatsapp

function get_cert_file() {
  local file_path=${1}
  echo ${file_path}/${CERT_FILENAME}
}

function get_cert_ca_file() {
  local file_path=${1}
  echo ${file_path}/${CERT_CA_FILENAME}
}

function lock() {
    local lock_file=${LOCKFILE_DIR}/${PROGNAME}.lock

    while :
    do
        echo "Acquiring lock ..."

        # create lock file
        eval "exec ${LOCK_FD}>${lock_file}"
        flock -n ${LOCK_FD}

        result=$?
        if [ ${result} -eq 0 ]; then
            echo "Lock acquired"
            break
        else
            sleep 1s
        fi
    done
}

function unlock() {
    local lock_file=${LOCKFILE_DIR}/${PROGNAME}.lock
    # Technically, this is not required; just removing file is enough
    flock -u ${LOCK_FD}
    rm -fr ${lock_file}
    echo "Lock released"
}

# stop doesn't terminate the lighttpd process in docker
# using pkill as workaround; keeping init.d .. stop for cleanup
function restart_www() {
    /etc/init.d/lighttpd stop
    sleep 1
    pkill lighttpd
    /etc/init.d/lighttpd start
}

function create_rootCA() {
    openssl genrsa -out rootCA.key 2048
    if [ -f rootCA.key ]; then
        echo "Created root CA key"
    else
        echo -e "Unable to create root CA key"
        exit 1
    fi

    openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 365 \
        -out ${CERT_CA_FILENAME} << EOF
US
CA
Menlo Park
WhatsApp Inc
Enterprise Client - AutoGen CA
.
sudhagar@whatsapp.com
EOF
    if [ -f ${CERT_CA_FILENAME} ]; then
        echo -e "\nCreated root CA (autogen) certificate"
    else
        echo -e "\nUnable to create root CA (autogen) certificate"
        exit 1
    fi
}

# Blow the root CA private key as it's temporary. This also prevents new certs
# from being signed
function delete_rootCA_key() {
    rm -f rootCA.key rootCA.srl
    echo "Deleted root CA (autogen) key"
}

function create_device_cert() {
    common_name=${1}
    local cert_file=$(get_cert_file ${CERT_DIR_STAGING})
    openssl genrsa -out device.key 2048
    echo "Created device key for ${common_name}"
    openssl req -new -key device.key -out device.csr << EOF
.
.
.
.
.
${common_name}
.
.
.
EOF
    if [ ! -f device.csr ]; then
        echo -e "\nUnable to create device certificate signing request"
        exit 1
    fi

    echo -e "\nCreated device certificate signing request"
    openssl x509 -req -in device.csr -CA ${CERT_CA_FILENAME} -CAkey rootCA.key \
        -CAcreateserial -out device.crt -days 3650 -sha256

    if [ ! -f device.crt ]; then
        echo "Unable sign device certificate"
        exit 1
    fi

    echo "Signed device certificate"
    cat device.crt device.key > ${cert_file}
    rm -f device.crt device.key device.csr
}

function delete_device_cert() {
    rm -f ${CERT_DIR_STAGING}/*.cert
}

function create_cert() {
    local server_name=${1}
    local cert_file=$(get_cert_file ${CERT_DIR_STAGING})
    local dir=$(dirname ${cert_file})
    mkdir -p ${dir}
    cd ${dir}

    delete_device_cert
    create_rootCA
    create_device_cert ${server_name}
    delete_rootCA_key
}

function add_ca_config() {
    # if ssl ca config is not present, add it
    ca_cfg_present=$(grep ssl.ca-file ${WWW_CONF} | wc -l)
    if [ ${ca_cfg_present} -eq 0 ]; then
        cat << EOF >> ${WWW_CONF}
# ssl.ca-file = ""
EOF
    fi
}

function add_ssl_config() {
    # if ssl config is already present, don't create it
    ssl_cfg_present=$(grep ssl.engine ${WWW_CONF} | wc -l)
    if [ ${ssl_cfg_present} -eq 0 ]; then
        cat << EOF >> ${WWW_CONF}

ssl.engine = "disable"
# ssl.pemfile = ""
# ssl.ca-file = ""
EOF
        echo "Added SSL configuration"
    else
        echo "SSL configuration already present"
    fi

    # since we are adding ca-file config after ssl configuration is added
    # check and add explicitly
    add_ca_config
}

function enable_ssl() {
    local cert_file=$(get_cert_file ${CERT_DIR_INSTALLED})
    local cert_ca_file=$(get_cert_ca_file ${CERT_DIR_INSTALLED})

    echo '/^server.port/c server.port = 8443' > ${SED_CMDS}
    echo '/ssl.engine/c ssl.engine = "enable"' >> ${SED_CMDS}
    echo "/ssl.pemfile/c ssl.pemfile = \"${cert_file}\"" >> ${SED_CMDS}

    if [ -f ${cert_ca_file} ]; then
        echo "/ssl.ca-file/c ssl.ca-file = \"${cert_ca_file}\"" >> ${SED_CMDS}
    fi

    sed -i.bak -f ${SED_CMDS} ${WWW_CONF}
    rm -f ${SED_CMDS}

    harden_ssl_configuration

    echo "SSL enabled"
}

function harden_ssl_configuration() {
    # if ssl hardening is already present, don't do anything
    ssl_cfg_present=$(grep ssl.cipher-list ${WWW_CONF} | wc -l)
    if [ ${ssl_cfg_present} -eq 0 ]; then

    cat >> ${WWW_CONF} << EOF

# TLS Configuration
ssl.disable-client-renegotiation = "enable"
ssl.ec-curve = "secp384r1"
ssl.use-sslv2 = "disable"
ssl.honor-cipher-order = "enable"
EOF
    case ${WA_WEB_SECURITY_LEVEL^^} in
        OLD)
            cat >> ${WWW_CONF} << EOF

# old security configuration
ssl.use-sslv3 = "enable"
ssl.cipher-list = "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:HIGH:SEED:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!RSAPSK:!aDH:!aECDH:!EDH-DSS-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!SRP"
EOF
            ;;
        INTERMEDIATE)
            cat >> ${WWW_CONF} << EOF

# intermediate security configuration
ssl.use-sslv3 = "disable"
ssl.cipher-list = "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS"
EOF
            ;;
        MODERN|*)
            cat >> ${WWW_CONF} << EOF

# modern security configuration
ssl.use-sslv3 = "disable"
ssl.cipher-list = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256"
EOF
            ;;
    esac

        echo "SSL Hardened"
    else
        echo "SSL hardening already present"
    fi

}

function disable_ssl() {
    echo '/^server.port/c server.port = 8080' > ${SED_CMDS}
    echo '/ssl.engine/c ssl.engine = "disable"' >> ${SED_CMDS}
    echo '/ssl.pemfile/c #ssl.pemfile = ""' >> ${SED_CMDS}
    echo '/ssl.ca-file/c #ssl.ca-file = ""' >> ${SED_CMDS}
    sed -i.bak -f ${SED_CMDS} ${WWW_CONF}
    rm -f ${SED_CMDS}
    echo "SSL disabled"
}

function add_headers() {
  headrs_present=$(grep setenv.add-response-header ${WWW_CONF} | wc -l)
    if [ ${headrs_present} -eq 0 ]; then
    	echo '/"mod_rewrite",/c \\t"mod_setenv",' >> ${SED_CMDS}
    	sed -i.bak -f ${SED_CMDS} ${WWW_CONF}
    	rm -f ${SED_CMDS}
		  cat >> ${WWW_CONF} << EOF

		server.tag = "Server"
		\$HTTP["url"] !~ "/v1/" {
    		setenv.add-response-header  = (
            	"X-Content-Security-Policy" => "default-src 'self'; script-src 'self' 'unsafe-inline'; ",
            	"X-Frame-Options" => "DENY",
            	"X-XSS-Protection" => "1;",
            	"X-Content-Type-Options" => "nosniff",
            	"Strict-Transport-Security" => "max-age=31536000; includeSubDomains"
        		)
    		}

EOF
	fi
}

function setup_ssl() {
    local server_name=${1}
    local scripts_dir=${2}
    local create_certs=1
    local cert_file=$(get_cert_file ${CERT_DIR})
    local cert_ca_file=$(get_cert_ca_file ${CERT_DIR})

    add_ssl_config

    if [ -f ${cert_file} ]; then
        echo "Certificate ${cert_file} already exists!"
        # check if hostname has changed; if so, recreate it
        if [ -f ${SERVERNAME_FILE} ]; then
            current_server_name=$(cat ${SERVERNAME_FILE})
            echo "Current server name: ${current_server_name}"
            if [ "${current_server_name}" == "${server_name}" ]; then
                create_certs=0
            fi
        else
            create_certs=0
        fi
    fi

    if [ ${create_certs} -eq 1 ]; then
        echo "Creating self-signed certificate for server: ${server_name}"
        create_cert ${server_name}
    else
        echo "Copying existing certificate to the staging area ${CERT_DIR_STAGING}"
        mkdir -p ${CERT_DIR_STAGING}
        cp ${cert_file} ${CERT_DIR_STAGING}
        cp ${cert_ca_file} ${CERT_DIR_STAGING}
    fi

    echo "Provisioning certificates"
    /usr/bin/php ${scripts_dir}/ProvisionCertificate.php ${HTTP_ROOT} ${server_name} ${CERT_DIR_STAGING}
    exit_code=$?; if [[ $exit_code == 1 ]]; then
      echo "Failed to provision certificates"
      sleep 3600s
    else
      enable_ssl
      echo "Provisioned certificates successfully"
      rm -f ${CERT_DIR_STAGING}/*.*
      echo "Cleaned up staging area"
    fi
}

# Check all environment variables beginning with WA and export them
# as appropriate
function setup_env_vars() {
    # Cleanup all environment variables
    sed '/^env\[WA.*]/d' -i ${FPM_CONF_FILE}

    for e in `env | egrep ^WA | awk -F = '{print $1}'`; do
        # On AWS environment, remove linked containers' environment variable
        if [ ! -z "${WA_RUNNING_ENV}" -a "${WA_RUNNING_ENV}" = "AWS" ]; then
            if [[ ${e} =~ WA_COREAPP_ENV_ ]]; then
                echo "${e} is linked container env var, skip adding"
                continue
            fi
        fi

        if [ ! -z ${!e} ]; then
            # Add variable
            echo "env[${e}] = ${!e}" >> ${FPM_CONF_FILE}
        else
            echo "${e} is empty, skip adding to ${FPM_CONF_FILE}"
        fi
    done
}

function monitor_file() {
    local file=${1}
    local dir=$(dirname $file)
    local base=$(basename $file)

    inotifywait -m ${dir} -e create |
    while read path action filename; do
        echo "${filename} changed in ${path} via., ${action}"
        if [ ${filename} == ${base} ]; then
            echo "Certificate file changed; Restarting web server"
            restart_www
        fi
    done
}

function web_monitor() {
  monitor_file ${WHOAMI_FILE}
}
