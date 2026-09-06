use prost::Message;

use crate::{RpcApiServices, http_routes::HttpRouteSpec, interceptors::PreservedRawGrpcMessage};

fn http_request<T>(input: T, raw: &[u8]) -> tonic::Request<T> {
    let mut request = tonic::Request::new(input);
    request.extensions_mut().insert(PreservedRawGrpcMessage(bytes::Bytes::copy_from_slice(raw)));
    request
}

impl RpcApiServices {
    /// Executes one descriptor-validated HTTP route through the same concrete C022 tonic adapter
    /// used by the gRPC server. The response is returned as protobuf wire bytes for JSON printing.
    pub async fn execute_http_route(&self, route: &HttpRouteSpec, request: &[u8]) -> Result<Vec<u8>, tonic::Status> {
        let services = self.clone().with_http_cursor(route.cursor);
        match (route.rpc_api, route.rpc_method) {
            ("Wallet", "get_account") => {
                let input = crate::Account::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_account(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "create_transaction") => {
                let input = crate::TransferContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::create_transaction(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "broadcast_transaction") => {
                let input = crate::Transaction::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::broadcast_transaction(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "update_account") => {
                let input = crate::AccountUpdateContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::update_account(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "vote_witness_account") => {
                let input = crate::VoteWitnessContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::vote_witness_account(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "create_asset_issue") => {
                let input = crate::AssetIssueContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::create_asset_issue(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "update_witness") => {
                let input = crate::WitnessUpdateContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::update_witness(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "create_account") => {
                let input = crate::AccountCreateContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::create_account(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "create_witness") => {
                let input = crate::WitnessCreateContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::create_witness(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "transfer_asset") => {
                let input = crate::TransferAssetContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::transfer_asset(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "participate_asset_issue") => {
                let input = crate::ParticipateAssetIssueContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::participate_asset_issue(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "freeze_balance") => {
                let input = crate::FreezeBalanceContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::freeze_balance(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "unfreeze_balance") => {
                let input = crate::UnfreezeBalanceContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::unfreeze_balance(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "unfreeze_asset") => {
                let input = crate::UnfreezeAssetContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::unfreeze_asset(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "withdraw_balance") => {
                let input = crate::WithdrawBalanceContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::withdraw_balance(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "update_asset") => {
                let input = crate::UpdateAssetContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::update_asset(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "list_nodes") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::list_nodes(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_asset_issue_by_account") => {
                let input = crate::Account::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_asset_issue_by_account(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_account_net") => {
                let input = crate::Account::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_account_net(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_asset_issue_by_name") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_asset_issue_by_name(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_asset_issue_list_by_name") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_asset_issue_list_by_name(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_asset_issue_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_asset_issue_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_now_block") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_now_block(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_block_by_num") => {
                let input = crate::NumberMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_block_by_num(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_block_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_block_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_block_by_limit_next") => {
                let input = crate::BlockLimit::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_block_by_limit_next(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_block_by_latest_num") => {
                let input = crate::NumberMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_block_by_latest_num(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_transaction_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_transaction_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_transaction_info_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_transaction_info_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_transaction_count_by_block_num") => {
                let input = crate::NumberMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_transaction_count_by_block_num(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "list_witnesses") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::list_witnesses(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_paginated_now_witness_list") => {
                let input = crate::PaginatedMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_paginated_now_witness_list(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_asset_issue_list") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_asset_issue_list(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_paginated_asset_issue_list") => {
                let input = crate::PaginatedMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_paginated_asset_issue_list(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_paginated_proposal_list") => {
                let input = crate::PaginatedMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_paginated_proposal_list(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_paginated_exchange_list") => {
                let input = crate::PaginatedMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_paginated_exchange_list(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "total_transaction") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::total_transaction(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_next_maintenance_time") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_next_maintenance_time(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletDomain", "validate_address") => return Err(tonic::Status::unimplemented("HTTP-only wallet domain route is not exposed by C022")),
            ("Wallet", "deploy_contract") => {
                let input = crate::CreateSmartContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::deploy_contract(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "trigger_contract") => {
                let input = crate::TriggerSmartContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::trigger_contract(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "trigger_constant_contract") => {
                let input = crate::TriggerSmartContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::trigger_constant_contract(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "estimate_energy") => {
                let input = crate::TriggerSmartContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::estimate_energy(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_contract") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_contract(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_contract_info") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_contract_info(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "clear_contract_abi") => {
                let input = crate::ClearAbiContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::clear_contract_abi(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "proposal_create") => {
                let input = crate::ProposalCreateContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::proposal_create(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "proposal_approve") => {
                let input = crate::ProposalApproveContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::proposal_approve(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "proposal_delete") => {
                let input = crate::ProposalDeleteContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::proposal_delete(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "list_proposals") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::list_proposals(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_proposal_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_proposal_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "exchange_create") => {
                let input = crate::ExchangeCreateContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::exchange_create(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "exchange_inject") => {
                let input = crate::ExchangeInjectContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::exchange_inject(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "exchange_transaction") => {
                let input = crate::ExchangeTransactionContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::exchange_transaction(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "exchange_withdraw") => {
                let input = crate::ExchangeWithdrawContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::exchange_withdraw(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_exchange_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_exchange_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "list_exchanges") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::list_exchanges(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_chain_parameters") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_chain_parameters(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_account_resource") => {
                let input = crate::Account::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_account_resource(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_transaction_sign_weight") => {
                let input = crate::Transaction::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_transaction_sign_weight(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_transaction_approved_list") => {
                let input = crate::Transaction::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_transaction_approved_list(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "account_permission_update") => {
                let input = crate::AccountPermissionUpdateContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::account_permission_update(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_node_info") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_node_info(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "update_setting") => {
                let input = crate::UpdateSettingContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::update_setting(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "update_energy_limit") => {
                let input = crate::UpdateEnergyLimitContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::update_energy_limit(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_delegated_resource") => {
                let input = crate::DelegatedResourceMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_delegated_resource(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_delegated_resource_v2") => {
                let input = crate::DelegatedResourceMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_delegated_resource_v2(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_can_delegated_max_size") => {
                let input = crate::CanDelegatedMaxSizeRequestMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_can_delegated_max_size(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_available_unfreeze_count") => {
                let input = crate::GetAvailableUnfreezeCountRequestMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_available_unfreeze_count(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_can_withdraw_unfreeze_amount") => {
                let input = crate::CanWithdrawUnfreezeAmountRequestMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_can_withdraw_unfreeze_amount(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_delegated_resource_account_index") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_delegated_resource_account_index(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_delegated_resource_account_index_v2") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_delegated_resource_account_index_v2(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "set_account_id") => {
                let input = crate::SetAccountIdContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::set_account_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_account_by_id") => {
                let input = crate::Account::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_account_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_expanded_spending_key") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_expanded_spending_key(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_ak_from_ask") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_ak_from_ask(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_nk_from_nsk") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_nk_from_nsk(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_spending_key") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_spending_key(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_new_shielded_address") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_new_shielded_address(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_diversifier") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_diversifier(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_incoming_viewing_key") => {
                let input = crate::ViewingKeyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_incoming_viewing_key(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_zen_payment_address") => {
                let input = crate::IncomingViewingKeyDiversifierMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_zen_payment_address(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_rcm") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_rcm(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "create_spend_auth_sig") => {
                let input = crate::SpendAuthSigParameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::create_spend_auth_sig(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "is_shielded_trc20_contract_note_spent") => {
                let input = crate::NfTrc20Parameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::is_shielded_trc20_contract_note_spent(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "create_shielded_contract_parameters") => {
                let input = crate::PrivateShieldedTrc20Parameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::create_shielded_contract_parameters(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "create_shielded_contract_parameters_without_ask") => {
                let input = crate::PrivateShieldedTrc20ParametersWithoutAsk::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::create_shielded_contract_parameters_without_ask(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "scan_shielded_trc20_notes_by_ivk") => {
                let input = crate::IvkDecryptTrc20Parameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::scan_shielded_trc20_notes_by_ivk(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "scan_shielded_trc20_notes_by_ovk") => {
                let input = crate::OvkDecryptTrc20Parameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::scan_shielded_trc20_notes_by_ovk(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_trigger_input_for_shielded_trc20_contract") => {
                let input = crate::ShieldedTrc20TriggerContractParameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_trigger_input_for_shielded_trc20_contract(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_brokerage_info") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_brokerage_info(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_reward_info") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_reward_info(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "update_brokerage") => {
                let input = crate::UpdateBrokerageContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::update_brokerage(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "create_common_transaction") => {
                let input = crate::Transaction::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::create_common_transaction(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_transaction_info_by_block_num") => {
                let input = crate::NumberMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_transaction_info_by_block_num(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Monitor", "get_stats_info") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::monitor::monitor_server::Monitor>::get_stats_info(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "market_sell_asset") => {
                let input = crate::MarketSellAssetContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::market_sell_asset(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "market_cancel_order") => {
                let input = crate::MarketCancelOrderContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::market_cancel_order(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_market_order_by_account") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_market_order_by_account(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_market_order_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_market_order_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_market_price_by_pair") => {
                let input = crate::MarketOrderPair::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_market_price_by_pair(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_market_order_list_by_pair") => {
                let input = crate::MarketOrderPair::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_market_order_list_by_pair(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_market_pair_list") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_market_pair_list(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_account_balance") => {
                let input = crate::AccountBalanceRequest::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_account_balance(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_block_balance_trace") => {
                let input = crate::block_balance_trace::BlockIdentifier::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_block_balance_trace(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_burn_trx") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_burn_trx(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_transaction_from_pending") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_transaction_from_pending(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_transaction_list_from_pending") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_transaction_list_from_pending(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_pending_size") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_pending_size(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_energy_prices") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_energy_prices(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_bandwidth_prices") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_bandwidth_prices(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_block") => {
                let input = crate::BlockReq::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_block(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "get_memo_fee") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_memo_fee(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "freeze_balance_v2") => {
                let input = crate::FreezeBalanceV2Contract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::freeze_balance_v2(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "unfreeze_balance_v2") => {
                let input = crate::UnfreezeBalanceV2Contract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::unfreeze_balance_v2(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "withdraw_expire_unfreeze") => {
                let input = crate::WithdrawExpireUnfreezeContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::withdraw_expire_unfreeze(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "delegate_resource") => {
                let input = crate::DelegateResourceContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::delegate_resource(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "un_delegate_resource") => {
                let input = crate::UnDelegateResourceContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::un_delegate_resource(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("Wallet", "cancel_all_unfreeze_v2") => {
                let input = crate::CancelAllUnfreezeV2Contract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::cancel_all_unfreeze_v2(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_account") => {
                let input = crate::Account::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_account(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "list_witnesses") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::list_witnesses(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_paginated_now_witness_list") => {
                let input = crate::PaginatedMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_paginated_now_witness_list(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_asset_issue_list") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_asset_issue_list(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_paginated_asset_issue_list") => {
                let input = crate::PaginatedMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_paginated_asset_issue_list(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_asset_issue_by_name") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_asset_issue_by_name(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_asset_issue_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_asset_issue_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_asset_issue_list_by_name") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_asset_issue_list_by_name(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_now_block") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_now_block(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_block_by_num") => {
                let input = crate::NumberMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_block_by_num(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_delegated_resource") => {
                let input = crate::DelegatedResourceMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_delegated_resource(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_delegated_resource_v2") => {
                let input = crate::DelegatedResourceMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_delegated_resource_v2(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_can_delegated_max_size") => {
                let input = crate::CanDelegatedMaxSizeRequestMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_can_delegated_max_size(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_available_unfreeze_count") => {
                let input = crate::GetAvailableUnfreezeCountRequestMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_available_unfreeze_count(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_can_withdraw_unfreeze_amount") => {
                let input = crate::CanWithdrawUnfreezeAmountRequestMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_can_withdraw_unfreeze_amount(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_delegated_resource_account_index") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_delegated_resource_account_index(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_delegated_resource_account_index_v2") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_delegated_resource_account_index_v2(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_exchange_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_exchange_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "list_exchanges") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::list_exchanges(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_account_by_id") => {
                let input = crate::Account::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_account_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_block_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_block_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_block_by_limit_next") => {
                let input = crate::BlockLimit::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_block_by_limit_next(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_block_by_latest_num") => {
                let input = crate::NumberMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_block_by_latest_num(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "scan_shielded_trc20_notes_by_ivk") => {
                let input = crate::IvkDecryptTrc20Parameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::scan_shielded_trc20_notes_by_ivk(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "scan_shielded_trc20_notes_by_ovk") => {
                let input = crate::OvkDecryptTrc20Parameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::scan_shielded_trc20_notes_by_ovk(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "is_shielded_trc20_contract_note_spent") => {
                let input = crate::NfTrc20Parameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::is_shielded_trc20_contract_note_spent(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "trigger_constant_contract") => {
                let input = crate::TriggerSmartContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::trigger_constant_contract(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "estimate_energy") => {
                let input = crate::TriggerSmartContract::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::estimate_energy(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_transaction_info_by_block_num") => {
                let input = crate::NumberMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_transaction_info_by_block_num(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_market_order_by_account") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_market_order_by_account(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_market_order_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_market_order_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_market_price_by_pair") => {
                let input = crate::MarketOrderPair::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_market_price_by_pair(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_market_order_list_by_pair") => {
                let input = crate::MarketOrderPair::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_market_order_list_by_pair(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_market_pair_list") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_market_pair_list(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_transaction_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_transaction_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_transaction_info_by_id") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_transaction_info_by_id(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_transaction_count_by_block_num") => {
                let input = crate::NumberMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_transaction_count_by_block_num(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_node_info") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::wallet::wallet_server::Wallet>::get_node_info(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_brokerage_info") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_brokerage_info(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_reward_info") => {
                let input = crate::BytesMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_reward_info(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_burn_trx") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_burn_trx(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_bandwidth_prices") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_bandwidth_prices(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_energy_prices") => {
                let input = crate::EmptyMessage::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_energy_prices(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_block") => {
                let input = crate::BlockReq::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_block(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "get_merkle_tree_voucher_info") => {
                let input = crate::OutputPointInfo::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::get_merkle_tree_voucher_info(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "scan_and_mark_note_by_ivk") => {
                let input = crate::IvkDecryptAndMarkParameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::scan_and_mark_note_by_ivk(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "scan_note_by_ivk") => {
                let input = crate::IvkDecryptParameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::scan_note_by_ivk(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "scan_note_by_ovk") => {
                let input = crate::OvkDecryptParameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::scan_note_by_ovk(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            ("WalletSolidity", "is_spend") => {
                let input = crate::NoteParameters::decode(request).map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
                let output = <RpcApiServices as crate::solidity::wallet_solidity_server::WalletSolidity>::is_spend(&services, http_request(input, request)).await?.into_inner();
                Ok(output.encode_to_vec())
            },
            _ => Err(tonic::Status::unimplemented(format!("unmapped HTTP route {}::{}", route.rpc_api, route.rpc_method))),
        }
    }
}
