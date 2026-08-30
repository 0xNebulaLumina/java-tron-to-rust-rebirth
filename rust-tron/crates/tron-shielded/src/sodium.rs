use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use blake2::{
    digest::{consts::U32, FixedOutput, Update},
    Blake2bMac, Blake2bMac512,
};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit,
};

use crate::{Result, ShieldedError};

pub const SUCCESS: i32 = 0;
pub const FAILURE: i32 = -1;
pub const AEAD_TAG_BYTES: usize = 16;
pub const DEFAULT_MAX_SODIUM_STATES: usize = 64;
// Historical libsodium permits roughly 256 GiB ChaCha20-Poly1305-IETF messages. The
// node boundary is intentionally much smaller: Java production payloads are at most
// 580 bytes (and its negative oracle uses 1,024 bytes), so 1 MiB leaves ample headroom.
pub const LIBSODIUM_AEAD_MESSAGE_BYTES_MAX: u64 = 274_877_906_880;
pub const MAX_SODIUM_MESSAGE_BYTES: usize = 1_048_576;
pub const MAX_SODIUM_AAD_BYTES: usize = 1_048_576;
pub const MAX_SODIUM_CIPHERTEXT_BYTES: usize = MAX_SODIUM_MESSAGE_BYTES + AEAD_TAG_BYTES;
pub const MAX_SODIUM_OUTPUT_BYTES: usize = MAX_SODIUM_CIPHERTEXT_BYTES;
const BLAKE2B_SALT_BYTES: usize = 16;

fn normalized_blake2b_salt(salt: &[u8]) -> Option<[u8; BLAKE2B_SALT_BYTES]> {
    if salt.is_empty() {
        return Some([0; BLAKE2B_SALT_BYTES]);
    }
    salt.try_into().ok()
}


struct BlakeState {
    state: Option<Blake2bMac512>,
}

pub struct SodiumCompat {
    next: AtomicU64,
    max_states: usize,
    states: Mutex<HashMap<u64, BlakeState>>,
}

impl SodiumCompat {
    pub fn new() -> Self {
        Self::with_max_states(DEFAULT_MAX_SODIUM_STATES)
            .expect("default sodium state bound is nonzero")
    }

    pub fn with_max_states(max_states: usize) -> Result<Self> {
        if max_states == 0 {
            return Err(ShieldedError::InvalidParameter(
                "max sodium states must be positive".into(),
            ));
        }
        Ok(Self {
            next: AtomicU64::new(1),
            max_states,
            states: Mutex::new(HashMap::new()),
        })
    }

    pub fn init_state(&self) -> Result<u64> {
        let mut states = self.states.lock().expect("state mutex poisoned");
        if states.len() >= self.max_states {
            return Err(ShieldedError::ContextLimit { max: self.max_states });
        }
        loop {
            let handle = self.next.fetch_add(1, Ordering::Relaxed);
            if handle == 0 {
                continue;
            }
            if let Entry::Vacant(entry) = states.entry(handle) {
                entry.insert(BlakeState { state: None });
                return Ok(handle);
            }
        }
    }

    pub fn free_state(&self, handle: u64) -> bool {
        self.states
            .lock()
            .expect("state mutex poisoned")
            .remove(&handle)
            .is_some()
    }

    pub fn state_count(&self) -> usize {
        self.states.lock().expect("state mutex poisoned").len()
    }

    pub fn blake2b_init(
        &self,
        handle: u64,
        key: &[u8],
        key_len: usize,
        out_len: usize,
        salt: &[u8],
        personal: &[u8],
    ) -> i32 {
        if out_len != 64
            || key_len != key.len()
            || key_len > 64
            || personal.len() != 16
        {
            return FAILURE;
        }
        let Some(salt) = normalized_blake2b_salt(salt) else {
            return FAILURE;
        };
        let key = if key_len == 0 { None } else { Some(key) };
        let Ok(state) = Blake2bMac512::new_with_salt_and_personal(key, &salt, personal) else {
            return FAILURE;
        };
        let mut states = self.states.lock().expect("state mutex poisoned");
        let Some(slot) = states.get_mut(&handle) else {
            return FAILURE;
        };
        slot.state = Some(state);
        SUCCESS
    }

    pub fn blake2b_update(&self, handle: u64, input: &[u8]) -> i32 {
        if !matches!(input.len(), 33 | 34) {
            return FAILURE;
        }
        let mut states = self.states.lock().expect("state mutex poisoned");
        let Some(state) = states.get_mut(&handle).and_then(|slot| slot.state.as_mut()) else {
            return FAILURE;
        };
        state.update(input);
        SUCCESS
    }

    pub fn blake2b_final(
        &self,
        handle: u64,
        out_len: usize,
    ) -> std::result::Result<Vec<u8>, i32> {
        if !matches!(out_len, 11 | 64) {
            return Err(FAILURE);
        }
        let mut states = self.states.lock().expect("state mutex poisoned");
        let Some(state) = states.get_mut(&handle).and_then(|slot| slot.state.take()) else {
            return Err(FAILURE);
        };
        let digest = state.finalize_fixed();
        Ok(digest[..out_len].to_vec())
    }
}

impl Default for SodiumCompat {
    fn default() -> Self {
        Self::new()
    }
}

pub fn blake2b_salt_personal(
    input: &[u8],
    key: &[u8],
    key_len: usize,
    salt: &[u8],
    personal: &[u8],
    out_len: usize,
) -> Result<Vec<u8>> {
    if input.len() > MAX_SODIUM_MESSAGE_BYTES
        || key_len != key.len()
        || key_len > 64
        || personal.len() != 16
        || out_len != 32
    {
        return Err(ShieldedError::InvalidParameter(
            "invalid BLAKE2b length".into(),
        ));
    }
    let salt = normalized_blake2b_salt(salt).ok_or_else(|| {
        ShieldedError::InvalidParameter("invalid BLAKE2b salt length".into())
    })?;
    let key = if key_len == 0 { None } else { Some(key) };
    let mut state = Blake2bMac::<U32>::new_with_salt_and_personal(key, &salt, personal).map_err(|_| {
        ShieldedError::InvalidParameter("invalid BLAKE2b key, salt, or personal length".into())
    })?;
    state.update(input);
    Ok(state.finalize_fixed().to_vec())
}

#[derive(Debug, Eq, PartialEq)]
pub struct AeadResult {
    pub rc: i32,
    pub output: Vec<u8>,
    pub output_len: u64,
}

impl AeadResult {
    fn failure() -> Self {
        Self { rc: FAILURE, output: Vec::new(), output_len: 0 }
    }
}

pub fn aead_encrypt(
    message: &[u8],
    aad: &[u8],
    nonce: &[u8; 12],
    key: &[u8; 32],
    output_capacity: usize,
) -> AeadResult {
    let Some(required) = message.len().checked_add(AEAD_TAG_BYTES) else {
        return AeadResult::failure();
    };
    if message.len() > MAX_SODIUM_MESSAGE_BYTES
        || aad.len() > MAX_SODIUM_AAD_BYTES
        || required > MAX_SODIUM_CIPHERTEXT_BYTES
        || output_capacity < required
        || output_capacity > MAX_SODIUM_OUTPUT_BYTES
    {
        return AeadResult::failure();
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    match cipher.encrypt(nonce.into(), Payload { msg: message, aad }) {
        Ok(output) => AeadResult { rc: SUCCESS, output_len: output.len() as u64, output },
        Err(_) => AeadResult::failure(),
    }
}

pub fn aead_decrypt(
    ciphertext: &[u8],
    aad: &[u8],
    nonce: &[u8; 12],
    key: &[u8; 32],
    output_capacity: usize,
) -> AeadResult {
    let Some(plain_len) = ciphertext.len().checked_sub(AEAD_TAG_BYTES) else {
        return AeadResult::failure();
    };
    if ciphertext.len() > MAX_SODIUM_CIPHERTEXT_BYTES
        || aad.len() > MAX_SODIUM_AAD_BYTES
        || output_capacity < plain_len
        || output_capacity > MAX_SODIUM_OUTPUT_BYTES
    {
        return AeadResult::failure();
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    match cipher.decrypt(nonce.into(), Payload { msg: ciphertext, aad }) {
        Ok(output) => AeadResult { rc: SUCCESS, output_len: output.len() as u64, output },
        Err(_) => AeadResult::failure(),
    }
}
