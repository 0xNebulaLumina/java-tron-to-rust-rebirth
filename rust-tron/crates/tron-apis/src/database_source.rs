use std::{future::Future, pin::Pin};
use tron_config::database_endpoint_authority;

use tron_protocol::protocol::{
    database_client::DatabaseClient, Block, DynamicProperties, EmptyMessage, NumberMessage,
};

pub type DatabaseFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, tonic::Status>> + Send + 'a>>;

/// Remote block source used by a standalone Solidity node.
pub trait DatabaseSource: Send {
    fn get_dynamic_properties(&mut self) -> DatabaseFuture<'_, DynamicProperties>;
    fn get_block_by_num(&mut self, number: i64) -> DatabaseFuture<'_, Block>;
    fn shutdown(&mut self) -> DatabaseFuture<'_, ()>;
}

/// Plaintext tonic client matching java-tron's `DatabaseGrpcClient` transport.
pub struct TonicDatabaseSource {
    client: Option<DatabaseClient<tonic::transport::Channel>>,
}

impl TonicDatabaseSource {
    pub async fn connect(host_port: &str) -> Result<Self, String> {
        let authority = database_endpoint_authority(host_port).map_err(|error| error.to_string())?;
        let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{authority}"))
            .map_err(|error| error.to_string())?;
        let client = DatabaseClient::connect(endpoint).await.map_err(|error| error.to_string())?;
        Ok(Self { client: Some(client) })
    }

    /// Builds a lazy plaintext channel so production composition remains synchronous. The first
    /// database request establishes the transport connection.
    pub fn from_host_port(host_port: &str) -> Result<Self, String> {
        let authority = database_endpoint_authority(host_port).map_err(|error| error.to_string())?;
        let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{authority}"))
            .map_err(|error| error.to_string())?;
        Ok(Self { client: Some(DatabaseClient::new(endpoint.connect_lazy())) })
    }
}

impl DatabaseSource for TonicDatabaseSource {
    fn get_dynamic_properties(&mut self) -> DatabaseFuture<'_, DynamicProperties> {
        Box::pin(async move {
            let client = self.client.as_mut().ok_or_else(|| tonic::Status::unavailable("Database source is shut down"))?;
            Ok(client.get_dynamic_properties(EmptyMessage {}).await?.into_inner())
        })
    }

    fn get_block_by_num(&mut self, number: i64) -> DatabaseFuture<'_, Block> {
        Box::pin(async move {
            let client = self.client.as_mut().ok_or_else(|| tonic::Status::unavailable("Database source is shut down"))?;
            Ok(client.get_block_by_num(NumberMessage { num: number }).await?.into_inner())
        })
    }

    fn shutdown(&mut self) -> DatabaseFuture<'_, ()> {
        Box::pin(async move {
            self.client.take();
            Ok(())
        })
    }
}
