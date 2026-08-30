use std::{
    fs::File,
    io::{Cursor, Read},
    path::Path,
    sync::Arc,
};

use blake2::{Blake2b512, Digest};
use sapling_crypto::circuit::{OutputParameters, SpendParameters};

use crate::{ParameterKind, Result, ShieldedError};

pub const TRON_SPEND_SIZE: u64 = 48_013_340;
pub const TRON_OUTPUT_SIZE: u64 = 3_647_804;
pub const TRON_SPEND_BLAKE2B512: &str = "25fd9a0d1c1be0526c14662947ae95b758fe9f3d7fb7f55e9b4437830dcc6215a7ce3ea465914b157715b7a4d681389ea4aa84438190e185d5e4c93574d3a19a";
pub const TRON_OUTPUT_BLAKE2B512: &str = "a1cb23b93256adce5bce2cb09cefbc96a1d16572675ceb691e9a3626ec15b5b546926ff1c536cfe3a9df07d796b32fdfc3e5d99d65567257bf286cd2858d71a6";

pub struct TronParameters {
    pub spend: Arc<SpendParameters>,
    pub output: Arc<OutputParameters>,
}

impl Clone for TronParameters {
    fn clone(&self) -> Self {
        Self {
            spend: Arc::clone(&self.spend),
            output: Arc::clone(&self.output),
        }
    }
}
impl TronParameters {
    /// File-opening seam used to regression-test parameter snapshot races.
    #[doc(hidden)]
    pub fn load_with_opener(
        spend_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
        opener: impl FnMut(ParameterKind, &Path) -> std::io::Result<File>,
    ) -> Result<Arc<Self>> {
        load_tron_parameters_with_opener(spend_path, output_path, opener)
    }
}


pub fn load_tron_parameters(
    spend_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<Arc<TronParameters>> {
    load_tron_parameters_with_opener(spend_path, output_path, |_, path| File::open(path))
}

/// Test seam for proving authentication and parsing use one immutable byte snapshot.
#[doc(hidden)]
pub fn load_tron_parameters_with_opener(
    spend_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    mut opener: impl FnMut(ParameterKind, &Path) -> std::io::Result<File>,
) -> Result<Arc<TronParameters>> {
    let spend = authenticated_bytes(
        opener(ParameterKind::Spend, spend_path.as_ref())
            .map_err(|source| ShieldedError::ParameterIo { kind: ParameterKind::Spend, source })?,
        ParameterKind::Spend,
        TRON_SPEND_SIZE,
        TRON_SPEND_BLAKE2B512,
    )?;
    let output = authenticated_bytes(
        opener(ParameterKind::Output, output_path.as_ref())
            .map_err(|source| ShieldedError::ParameterIo { kind: ParameterKind::Output, source })?,
        ParameterKind::Output,
        TRON_OUTPUT_SIZE,
        TRON_OUTPUT_BLAKE2B512,
    )?;

    let spend = SpendParameters::read(Cursor::new(spend), false).map_err(|source| {
        ShieldedError::ParameterDeserialize { kind: ParameterKind::Spend, source }
    })?;
    let output = OutputParameters::read(Cursor::new(output), false).map_err(|source| {
        ShieldedError::ParameterDeserialize { kind: ParameterKind::Output, source }
    })?;
    Ok(Arc::new(TronParameters {
        spend: Arc::new(spend),
        output: Arc::new(output),
    }))
}

fn authenticated_bytes(
    mut file: File,
    kind: ParameterKind,
    expected_size: u64,
    expected_hash: &'static str,
) -> Result<Box<[u8]>> {
    let expected_len = usize::try_from(expected_size).map_err(|_| ShieldedError::ParameterSize {
        kind,
        expected: expected_size,
        actual: expected_size,
    })?;
    let mut bytes = vec![0_u8; expected_len].into_boxed_slice();
    let mut hasher = Blake2b512::new();
    let mut offset = 0;
    while offset < expected_len {
        let read = file
            .read(&mut bytes[offset..])
            .map_err(|source| ShieldedError::ParameterIo { kind, source })?;
        if read == 0 {
            return Err(ShieldedError::ParameterSize {
                kind,
                expected: expected_size,
                actual: offset as u64,
            });
        }
        hasher.update(&bytes[offset..offset + read]);
        offset += read;
    }

    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|source| ShieldedError::ParameterIo { kind, source })?
        != 0
    {
        return Err(ShieldedError::ParameterSize {
            kind,
            expected: expected_size,
            actual: expected_size + 1,
        });
    }

    let actual = hex::encode(hasher.finalize());
    if actual != expected_hash {
        return Err(ShieldedError::ParameterHash { kind, expected: expected_hash, actual });
    }
    Ok(bytes)
}
