use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

//--------------------------------------------------------------------------------------------------
// Unix Timestamp handling
//--------------------------------------------------------------------------------------------------

#[derive(Serialize)]
pub struct Seconds(u32);

pub const ONE_HOUR: Seconds = Seconds(3600);

#[derive(Clone, Copy)]
pub struct UnixTimestamp(OffsetDateTime);

impl Serialize for UnixTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.unix_timestamp().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UnixTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let timestamp = i64::deserialize(deserializer)?;
        let datetime =
            OffsetDateTime::from_unix_timestamp(timestamp).map_err(serde::de::Error::custom)?;
        Ok(UnixTimestamp(datetime))
    }
}

impl From<UnixTimestamp> for OffsetDateTime {
    fn from(ts: UnixTimestamp) -> Self {
        ts.0
    }
}

impl UnixTimestamp {
    pub fn now() -> Self {
        UnixTimestamp(OffsetDateTime::now_utc())
    }

    pub fn add_one_hour(self) -> Self {
        UnixTimestamp(self.0 + Duration::seconds(ONE_HOUR.0 as i64))
    }
}

//--------------------------------------------------------------------------------------------------
