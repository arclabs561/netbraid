use serde::Serialize;
use sha2::{Digest, Sha256};

pub(crate) struct NormalizedRecordsDigest {
    hasher: Sha256,
}

impl NormalizedRecordsDigest {
    pub(crate) fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"netmon.normalized_records.v0\0");
        Self { hasher }
    }

    pub(crate) fn update<T: Serialize + ?Sized>(
        &mut self,
        kind: &str,
        index: u64,
        record: &T,
    ) -> Result<(), serde_json::Error> {
        let bytes = serde_json::to_vec(record)?;
        self.hasher.update(kind.as_bytes());
        self.hasher.update([0]);
        self.hasher.update(index.to_le_bytes());
        self.hasher
            .update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
        self.hasher.update(bytes);
        Ok(())
    }

    pub(crate) fn finish(self) -> String {
        format!("sha256:{:x}", self.hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_binds_family_index_length_and_bytes() {
        let mut baseline = NormalizedRecordsDigest::new();
        baseline.update("packet", 0, &"a").unwrap();
        let baseline = baseline.finish();

        for (kind, index, value) in [
            ("quarantine", 0, "a"),
            ("packet", 1, "a"),
            ("packet", 0, "aa"),
            ("packet", 0, "b"),
        ] {
            let mut changed = NormalizedRecordsDigest::new();
            changed.update(kind, index, &value).unwrap();
            assert_ne!(baseline, changed.finish());
        }
    }
}
