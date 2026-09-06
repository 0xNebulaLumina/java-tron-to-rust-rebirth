//! Java-compatible DPoS scheduling, production guards, and maintenance transitions.

pub mod backup;
pub mod maintenance;
pub mod pbft;
pub mod proposal;
pub mod rewards;
pub mod solidity;
pub mod production;
pub mod schedule;
pub mod state;

pub use maintenance::{apply_maintenance_block, MaintenanceConfig, MaintenanceOutcome};
pub use production::{account_block_production, account_production, apply_filled_slot, participation, BackupRole, ProductionGuard, ProductionPlan, ProductionState, ReceivedBlock};
pub use schedule::{java_shuffle, sort_and_truncate_active, sort_witnesses, Clock, DposSlot, FixedClock, ScheduleError, SlotContext, SystemClock, BLOCK_INTERVAL_MS, MAX_ACTIVE_WITNESSES, SINGLE_REPEAT};
pub use proposal::{approval_threshold, has_most_approvals, process_expired_proposals, ParameterRule, ProposalHistory, ProposalScan};
pub use rewards::{accumulate_vi, adjust_allowance, pay_block_reward, pay_fee_pool_reward, pay_reward, pay_standby_rewards, pay_transaction_fee_reward, query_reward, reward_across_cycles, reward_vi, standby_distribution, withdraw_reward, FeePoolReward, RewardPayment, RewardWithdrawal, VoteReward, DEFAULT_BROKERAGE, VI_SCALE};
pub use solidity::{java_fork_pass, maintenance_reset, solidity_position, update_fork, update_solidity, CanonicalForkEvaluator, ForkSpec, ForkState, ForkUpdate, SolidityUpdate};
pub use state::{delegation_brokerage_key, delegation_key, delegation_vote_key, ConsensusRead, StateError, StateFacade, StateView};
