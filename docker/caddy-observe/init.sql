CREATE TABLE kafka_caddy_access_logs_consumer
(
    `message` String
)
ENGINE = Kafka
SETTINGS kafka_broker_list = 'kafka:9092', kafka_topic_list = 'caddy-access', kafka_group_name = 'github-clickhouse-tool', kafka_format = 'JSONAsString'
;

CREATE TABLE caddy_access_logs
(
    `ts` DateTime64(6) NOT NULL,
    `hostname` LowCardinality(String) NOT NULL,
    `client_ip` String NOT NULL,
    `remote_ip` String NOT NULL,
    `remote_port` String NOT NULL,
    `request_method` LowCardinality(String) NOT NULL,
    `request_uri` String NOT NULL,
    `http_version` LowCardinality(String) NOT NULL,
    `request_host` String NOT NULL,
    `user_agent` String NOT NULL,
    `request_size` UInt64 NOT NULL,
    `status` UInt16 NOT NULL,
    `response_size` UInt64 NOT NULL,
    `duration` Float64 NOT NULL
)
ENGINE = MergeTree
ORDER BY (ts, hostname)
;

CREATE MATERIALIZED VIEW caddy_access_logs_mv TO caddy_access_logs
AS SELECT
    toDateTime64(JSONExtractFloat(message, 'ts'), 6) AS ts,
    JSONExtractString(message, 'hostname') AS hostname,
    JSONExtractString(message, 'request', 'client_ip') AS client_ip,
    JSONExtractString(message, 'request', 'remote_ip') AS remote_ip,
    JSONExtractString(message, 'request', 'remote_port') AS remote_port,
    JSONExtractString(message, 'request', 'method') AS request_method,
    JSONExtractString(message, 'request', 'uri') AS request_uri,
    JSONExtractString(message, 'request', 'proto') AS http_version,
    JSONExtractString(message, 'request', 'host') AS request_host,
    JSONExtractString(message, 'request', 'headers', 'User-Agent', 1) AS user_agent,
    JSONExtractUInt(message, 'bytes_read') AS request_size,
    JSONExtractUInt(message, 'status') AS status,
    JSONExtractUInt(message, 'size') AS response_size,
    JSONExtractFloat(message, 'duration') AS duration
FROM kafka_caddy_access_logs_consumer
WHERE JSONExtractString(message, 'logger') = 'http.log.access'
;
