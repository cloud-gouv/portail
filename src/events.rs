// Event type bitmap flags for SubscribeEvents.
pub mod event_type {
    // Generic proxy information
    pub const GENERAL_INFO: i64 = 0x01;
    // Generic proxy errors (TLS failures, upstream issues, etc.)
    pub const GENERAL_ERROR: i64 = 0x02;
    // ACL denied a connection.
    pub const ACL_REJECTION: i64 = 0x04;
}
