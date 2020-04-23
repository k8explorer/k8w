#!/bin/bash
#
# December 16, 2016
#

HTTP_ROOT=/var/www/html
HTTPD_CONF=/etc/lighttpd/lighttpd.conf
MEDIA_ROOT=/usr/local/wamedia
DATA_DIR=/usr/local/waent/data
CFG_DIR=${DATA_DIR}/web
LOG_DIR=/var/log/whatsapp
TOOLS_DIR=/opt/whatsapp/tools
DB_CFG_DIR=/var/lib/whatsapp
SCRIPTS_DIR=${HTTP_ROOT}/src/WhatsApp/Scripts

# export version
export WA_VERSION=`cat /.version`
export WEBADMIN_VERSION=`cat /.webadmin_version`

# allow writes to the outgoing media mountpoint
mkdir -p ${MEDIA_ROOT}/outgoing ${MEDIA_ROOT}/shared
#chmod a+w ${MEDIA_ROOT}/outgoing ${MEDIA_ROOT}/shared

mkdir -p ${LOG_DIR} ${CFG_DIR} ${DB_CFG_DIR}
chown www-data:www-data ${LOG_DIR} ${CFG_DIR} ${DB_CFG_DIR}
chown -R www-data:www-data ${HTTP_ROOT}/admin_updates

# set initial ssl certificate, if no cert exists
if [ -z $WA_WEB_SERVERNAME ]; then
    WA_WEB_SERVERNAME=localhost
fi

# On AWS, password is stored as secure parameter
if [ ! -z "${WA_RUNNING_ENV}" -a "${WA_RUNNING_ENV}" = "AWS" ]; then
    echo "Running on AWS"
    passwd=$(/opt/whatsapp/bin/ssm.py ${AWS_REGION} ${AWS_STACK_NAME}-WA_DB_PASSWORD 2>>/dev/stderr)
    if [ ! -z "${passwd}" ]; then
        export WA_DB_PASSWORD=${passwd}
    else
        print "AWS: Unable to read DB password from secure store"
    fi
fi

# create web db and store db config database.yml in DB_CFG_DIR
/usr/bin/php ${SCRIPTS_DIR}/CreateWebDB.php ${HTTP_ROOT} ${DB_CFG_DIR}

# allow writes to sqlite web db
if [ -f ${CFG_DIR}/waweb.db ]; then
  chown www-data:www-data ${CFG_DIR}/waweb.db
fi

#source /opt/whatsapp/bin/web_setup.sh && setup_ssl $WA_WEB_SERVERNAME ${SCRIPTS_DIR}
source /opt/whatsapp/bin/web_setup.sh && disable_ssl
source /opt/whatsapp/bin/web_setup.sh && setup_env_vars
source /opt/whatsapp/bin/web_setup.sh && add_headers

/usr/sbin/php-fpm7.0
# dockers containers need tcp, so "true" is always correct here.
/usr/bin/php ${SCRIPTS_DIR}/BuildConfigJson.php true $WACORE_HOSTNAME $WACORE_BASEPORT

# start web server in background; this allows restart of web server
/etc/init.d/lighttpd start
echo "Web server started"

tail -F /var/log/lighttpd/error.log /var/log/whatsapp/web.log &

if [ "$WA_MODE_SANDBOX" = "1" ]; then
    echo "Sandbox mode: Starting webhooks proxy"
    cd ${HTTP_ROOT}/admin_updates && ln -sf ${WEBADMIN_VERSION}/sandbox admin
    /opt/whatsapp/bin/wh_proxy -cert /var/lib/whatsapp/server.cert -key /var/lib/whatsapp/www.cert &
else
    cd ${HTTP_ROOT}/admin_updates && ln -sf ${WEBADMIN_VERSION}/production admin
fi

if [ ! -z "${WA_API_KEY}" ]; then
    len=${#WA_API_KEY}
    if [ $len -lt 12 -o $len -gt 128 ]; then
        echo "Invalid API Key length. Should be in the range [12, 128]"
    fi
fi

# run web monitor in foreground; web monitor runs forever
echo "Starting web monitor loop ..."
source /opt/whatsapp/bin/web_setup.sh && web_monitor | tee /var/log/wa_monitor.log
