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
imsi TEXT,
PRIMARY KEY (binpath, iftype, ifname, quota_id, imsi)
);
INSERT INTO restrictions select * from fota;
DROP TABLE IF EXISTS fota;
ALTER TABLE quotas RENAME to fota;
CREATE TABLE IF NOT EXISTS quotas (
  binpath TEXT,
  sent_quota BIGINT,
  rcv_quota BIGINT,
  snd_warning_threshold INT,
  rcv_warning_threshold INT,
  time_period BIGINT,
  start_time BIGINT,
  iftype INT,
  roaming INT,
  reserved TEXT,
  imsi TEXT,
  ground INT,
  PRIMARY KEY(binpath, iftype, roaming, imsi, ground)
);
INSERT INTO quotas select * from fota;
DROP TABLE IF EXISTS fota;
"
