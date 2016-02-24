sqlite3 /opt/usr/dbspace/.resourced-datausage.db "
PRAGMA journal_mode=PERSIST;
DROP TABLE IF EXISTS fota;
ALTER TABLE restrictions RENAME to fota;
CREATE TABLE IF NOT EXISTS restrictions (
binpath TEXT,
rcv_limit BIGINT,
send_limit BIGINT,
iftype INT,
rst_state INT,
quota_id INT,
roaming INT,
reserved TEXT,
ifname TEXT,
PRIMARY KEY (binpath, iftype, ifname, quota_id)
);
INSERT INTO restrictions select * from fota;
DROP TABLE IF EXISTS fota;
"
