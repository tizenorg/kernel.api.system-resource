HEART_DEBUG=$1/heart
/bin/mkdir -p ${HEART_DEBUG}
/bin/cp -rf /opt/usr/dbspace/.resourced-logging-leveldb/ ${HEART_DEBUG}
/bin/cp -rf /opt/usr/dbspace/.resourced-logging.db ${HEART_DEBUG}
/bin/cp -rf /opt/usr/data/heart/ ${HEART_DEBUG}
