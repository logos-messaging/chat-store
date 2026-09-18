-- Account logs (`/v1/account`): the latest log per account, as the account-log
-- crate's `signature || payload` artifact. A submitted log replaces the row only
-- when it strictly extends it (see `Store::put_account_log`). Keyed by the
-- hex-encoded account verifying key.
CREATE TABLE account_logs (
    account_pub TEXT    NOT NULL PRIMARY KEY,
    updated_at  INTEGER NOT NULL,
    signed_log  BLOB    NOT NULL
);
