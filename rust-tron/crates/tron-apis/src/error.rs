use tron_execution::{PendingReject, ProcessError};
use tron_protocol::protocol::{Return, r#return::ResponseCode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiError {
    InvalidArgument(String),
    NotFound(String),
    FailedPrecondition(String),
    Unavailable(String),
    Internal(String),
}
impl core::fmt::Display for ApiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidArgument(v)
            | Self::NotFound(v)
            | Self::FailedPrecondition(v)
            | Self::Unavailable(v)
            | Self::Internal(v) => f.write_str(v),
        }
    }
}
impl std::error::Error for ApiError {}
impl From<ApiError> for tonic::Status {
    fn from(value: ApiError) -> Self {
        match value {
            ApiError::InvalidArgument(v) => Self::invalid_argument(v),
            ApiError::NotFound(v) => Self::not_found(v),
            ApiError::FailedPrecondition(v) => Self::failed_precondition(v),
            ApiError::Unavailable(v) => Self::unavailable(v),
            ApiError::Internal(v) => Self::internal(v),
        }
    }
}
impl From<tron_shielded::ShieldedError> for ApiError {
    fn from(value: tron_shielded::ShieldedError) -> Self {
        Self::InvalidArgument(value.to_string())
    }
}

#[must_use]
pub fn success_return() -> Return {
    Return {
        result: true,
        code: ResponseCode::Success as i32,
        message: Vec::new(),
    }
}
#[must_use]
pub fn failure_return(code: ResponseCode, message: impl Into<Vec<u8>>) -> Return {
    Return {
        result: false,
        code: code as i32,
        message: message.into(),
    }
}

#[must_use]
pub fn process_return(error: &ProcessError) -> Return {
    match error {
        ProcessError::Duplicate(_) => failure_return(
            ResponseCode::DupTransactionError,
            b"Dup transaction.".to_vec(),
        ),
        ProcessError::Stage { stage, message } => match stage {
            tron_execution::PipelineStage::Admission
                if message.contains("signature") || message.contains("permission") || message.contains("sig") =>
            {
                failure_return(
                    ResponseCode::Sigerror,
                    format!("Validate signature error: {message}").into_bytes(),
                )
            }
            tron_execution::PipelineStage::Admission
                if message.contains("Tapos")
                    || message.contains("tapos")
                    || message.contains("ref block") =>
            {
                failure_return(ResponseCode::TaposError, b"Tapos check error.".to_vec())
            }
            tron_execution::PipelineStage::Admission
                if message.contains("expiration") || message.contains("expired") =>
            {
                failure_return(
                    ResponseCode::TransactionExpirationError,
                    b"Transaction expired".to_vec(),
                )
            }
            tron_execution::PipelineStage::Admission
                if message.contains("too big") || message.contains("size") =>
            {
                failure_return(ResponseCode::TooBigTransactionError, message.as_bytes().to_vec())
            }
            tron_execution::PipelineStage::Admission => failure_return(
                ResponseCode::ContractValidateError,
                format!("Contract validate error : {message}").into_bytes(),
            ),
            tron_execution::PipelineStage::Runtime | tron_execution::PipelineStage::Retry =>
                failure_return(
                    ResponseCode::ContractExeError,
                    format!("Contract execute error : {message}").into_bytes(),
                ),
            tron_execution::PipelineStage::Billing => failure_return(
                ResponseCode::BandwithError,
                b"Account resource insufficient error.".to_vec(),
            ),
            _ => failure_return(
                ResponseCode::OtherError,
                format!("Error: {message}").into_bytes(),
            ),
        },
        ProcessError::State(message) => failure_return(
            ResponseCode::OtherError,
            format!("Error: {message}").into_bytes(),
        ),
    }
}

#[must_use]
pub fn pending_return(reason: &PendingReject) -> Return {
    match reason {
        PendingReject::Duplicate => failure_return(
            ResponseCode::DupTransactionError,
            b"Transaction already exists.".to_vec(),
        ),
        PendingReject::Full | PendingReject::ShieldedFull | PendingReject::Closed => {
            failure_return(ResponseCode::ServerBusy, b"Server busy.".to_vec())
        }
        PendingReject::Expired => failure_return(
            ResponseCode::TransactionExpirationError,
            b"Transaction expired".to_vec(),
        ),
        PendingReject::Execution(message) => failure_return(
            ResponseCode::ContractValidateError,
            format!("Contract validate error : {message}").into_bytes(),
        ),
    }
}
