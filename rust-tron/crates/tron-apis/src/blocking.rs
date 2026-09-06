use std::{
    sync::{Arc, atomic::{AtomicBool, Ordering}},
    time::Duration,
};

use tokio::sync::Semaphore;

/// Cooperative cancellation observed by blocking state, VM, proof and crypto adapters.
#[derive(Clone, Debug)]
pub struct BlockingCancellation(Arc<AtomicBool>);
impl BlockingCancellation {
    #[must_use]
    pub fn is_cancelled(&self) -> bool { self.0.load(Ordering::Acquire) }
    fn cancel(&self) { self.0.store(true, Ordering::Release); }
}

struct CancellationGuard(BlockingCancellation);
impl Drop for CancellationGuard {
    fn drop(&mut self) { self.0.cancel(); }
}

/// Bounds synchronous work independently from Tokio's unbounded blocking pool.
#[derive(Clone, Debug)]
pub struct BlockingExecutor {
    permits: Arc<Semaphore>,
    deadline: Duration,
}
impl BlockingExecutor {
    pub fn new(max_concurrency: usize, deadline: Duration) -> Result<Self, crate::ApiError> {
        if max_concurrency == 0 || deadline.is_zero() {
            return Err(crate::ApiError::InvalidArgument(
                "blocking executor concurrency and deadline must be positive".into(),
            ));
        }
        Ok(Self { permits: Arc::new(Semaphore::new(max_concurrency)), deadline })
    }

    pub async fn run<T, F>(&self, work: F) -> Result<T, tonic::Status>
    where
        T: Send + 'static,
        F: FnOnce(BlockingCancellation) -> Result<T, crate::ApiError> + Send + 'static,
    {
        let deadline = tokio::time::Instant::now() + self.deadline;
        let permit = tokio::time::timeout_at(deadline, Arc::clone(&self.permits).acquire_owned())
            .await
            .map_err(|_| tonic::Status::deadline_exceeded("blocking executor queue deadline exceeded"))?
            .map_err(|_| tonic::Status::unavailable("blocking executor is closed"))?;
        let cancellation = BlockingCancellation(Arc::new(AtomicBool::new(false)));
        let guard = CancellationGuard(cancellation.clone());
        let worker_cancellation = cancellation.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if worker_cancellation.is_cancelled() {
                return Err(crate::ApiError::Unavailable("blocking operation cancelled".into()));
            }
            work(worker_cancellation)
        });
        let result = match tokio::time::timeout_at(deadline, task).await {
            Ok(Ok(result)) => result.map_err(Into::into),
            Ok(Err(error)) => Err(tonic::Status::internal(format!("blocking worker failed: {error}"))),
            Err(_) => Err(tonic::Status::deadline_exceeded("blocking operation deadline exceeded")),
        };
        drop(guard);
        result
    }
}

impl Default for BlockingExecutor {
    fn default() -> Self {
        Self::new(8, Duration::from_secs(10)).expect("valid blocking executor defaults")
    }
}
