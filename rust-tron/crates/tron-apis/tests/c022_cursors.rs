use tron_apis::PbftMethod;

#[test]
fn pbft_surface_has_exact_intentional_omissions() {
    for method in [
        PbftMethod::PaginatedWitnesses,
        PbftMethod::TransactionInfoByBlock,
        PbftMethod::MemoFee,
        PbftMethod::ChainParameters,
        PbftMethod::NodeInfo,
        PbftMethod::Pending,
        PbftMethod::WalletExtension,
        PbftMethod::Monitor,
        PbftMethod::Network,
    ] {
        assert!(!method.supported(), "{}", method.name())
    }
    for method in [
        PbftMethod::Account,
        PbftMethod::Assets,
        PbftMethod::NowBlock,
        PbftMethod::Transaction,
        PbftMethod::DelegatedResource,
        PbftMethod::Constant,
        PbftMethod::Market,
        PbftMethod::BandwidthPrices,
        PbftMethod::EnergyPrices,
    ] {
        assert!(method.supported(), "{}", method.name())
    }
}
