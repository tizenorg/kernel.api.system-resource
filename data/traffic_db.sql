PRAGMA journal_mode = PERSIST;

CREATE TABLE IF NOT EXISTS statistics (
  binpath TEXT,
  received BIGINT,
  sent BIGINT,
  time_stamp BIGINT,
  iftype INT,
  is_roaming INT,
  hw_net_protocol_type INT,
  ifname TEXT,
  reserved TEXT,
  imsi TEXT,
  ground INT,
  PRIMARY KEY (binpath, time_stamp, iftype, imsi)
);

CREATE INDEX IF NOT EXISTS binpath_st_idx ON statistics(binpath, iftype, imsi);

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

CREATE INDEX IF NOT EXISTS binpath_qt_idx ON quotas(binpath, iftype, imsi);

CREATE TABLE IF NOT EXISTS effective_quotas (
  binpath TEXT,
  sent_used_quota BIGINT,
  rcv_used_quota BIGINT,
  start_time BIGINT,
  finish_time BIGINT,
  iftype INT,
  roaming INT,
  state INT DEFAULT 0,
  reserved TEXT,
  imsi TEXT,
  PRIMARY KEY (binpath, iftype, start_time, finish_time, roaming, imsi)
);

CREATE INDEX IF NOT EXISTS binpath_effective_quotas_idx ON effective_quotas(binpath, iftype, imsi);

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

CREATE INDEX IF NOT EXISTS binpath_restrictions_idx ON restrictions(binpath, iftype, ifname);

CREATE TABLE IF NOT EXISTS iface_status (
  update_time BIGINT,
  iftype INT,
  ifstatus INT,
  reserved TEXT,
  ifname TEXT,
  PRIMARY KEY (update_time, iftype, ifstatus)
);

CREATE INDEX IF NOT EXISTS update_tm_if_idx ON iface_status(update_time, iftype, ifstatus);
