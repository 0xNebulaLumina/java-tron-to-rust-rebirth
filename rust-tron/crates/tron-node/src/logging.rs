use crate::{build_info::BuildIdentity, deployment::DeploymentMode};
#[derive(Clone, Debug)] pub struct LoggingConfig { pub level:String }
#[derive(Debug)] pub struct LoggingError(pub String);
impl std::fmt::Display for LoggingError{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str(&self.0)}} impl std::error::Error for LoggingError{}
pub fn init_logging(config:&LoggingConfig,build:BuildIdentity,mode:DeploymentMode)->Result<(),LoggingError>{use tracing_subscriber::{fmt,EnvFilter};let filter=EnvFilter::try_new(&config.level).map_err(|e|LoggingError(e.to_string()))?;fmt().json().with_env_filter(filter).with_current_span(false).with_span_list(false).flatten_event(true).try_init().map_err(|e|LoggingError(e.to_string()))?;tracing::info!(event="process_start",release_id=build.release_id,platform_id=build.platform_id,mode=?mode,"node process initialized");Ok(())}
