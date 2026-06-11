-- KeyPackage bundles: history per device, newest read back on fetch.
CREATE TABLE keypackages (
    device_id   TEXT    NOT NULL,
    received_at INTEGER NOT NULL,
    payload     BLOB    NOT NULL,
    signature   BLOB    NOT NULL,
    PRIMARY KEY (device_id, received_at)
);

-- Account device-list bundles: exactly one row per account; newer upserts
-- replace the existing row (compare-and-swap on the payload's lamport).
CREATE TABLE account_bundles (
    account_id TEXT    NOT NULL PRIMARY KEY,
    updated_at INTEGER NOT NULL,
    payload    BLOB    NOT NULL,
    signature  BLOB    NOT NULL
);
