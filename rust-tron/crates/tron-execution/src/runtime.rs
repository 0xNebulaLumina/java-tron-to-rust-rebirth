use std::{sync::Arc, time::{Duration, Instant}};

use prost::Message;
use tron_crypto::{keccak256, top_level_contract_address};
use tron_primitives::{Hash32, TransactionId, TronAddress21};
use tron_protocol::protocol::{
    smart_contract::abi::entry::{EntryType, StateMutabilityType},
    transaction::{contract::ContractType, Contract}, Account, AccountType, CreateSmartContract,
    SmartContract, TriggerSmartContract,
};
use tron_state::{dynamic, Session, StoreKind};
use tron_tvm::{
    DeadlineLimiter, EnergyMeter, ExecutionOutcome, FrameContext, Interpreter, Memory,
    MonotonicClock, NoTrace, Program, Repository, Stack1024, TvmRules, Word,
};

use crate::{
    receipt::EnergyExecutionPlan, ActuatorResult, BuiltinContract, ExecutionRuntimeConfig,
    RegistryError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeKind {
    NonVm,
    Create,
    Trigger,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    Registry(String),
    Vm(String),
    ConstantMethod,
    MissingState(&'static str),
    WrongState(&'static str),
}
impl core::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Registry(value) | Self::Vm(value) => f.write_str(value),
            Self::ConstantMethod => f.write_str("cannot call constant method"),
            Self::MissingState(value) => write!(f, "missing {value}"),
            Self::WrongState(value) => write!(f, "invalid {value}"),
        }
    }
}
impl std::error::Error for RuntimeError {}
impl From<RegistryError> for RuntimeError {
    fn from(value: RegistryError) -> Self {
        Self::Registry(format!("{value:?}"))
    }
}

struct ProcessMonotonicClock(Instant);
impl ProcessMonotonicClock {
    fn start() -> Self { Self(Instant::now()) }
}
impl MonotonicClock for ProcessMonotonicClock {
    fn elapsed(&self) -> Duration { self.0.elapsed() }
}

struct CanonicalVmInvocation {
    frame: FrameContext,
    code: Vec<u8>,
    energy_limit: i64,
    rules: TvmRules,
    deadline: Duration,
    create_contract: Option<SmartContract>,
}

pub struct Runtime<'a> {
    pub config: &'a ExecutionRuntimeConfig,
}
impl<'a> Runtime<'a> {
    pub fn kind(contract: &Contract) -> Result<RuntimeKind, RuntimeError> {
        match ContractType::try_from(contract.r#type) {
            Ok(ContractType::CreateSmartContract) => Ok(RuntimeKind::Create),
            Ok(ContractType::TriggerSmartContract) => Ok(RuntimeKind::Trigger),
            Ok(_) | Err(_) => Ok(RuntimeKind::NonVm),
        }
    }

    pub fn enforce_constant_policy(
        kind: RuntimeKind,
        allow_constantinople: bool,
        is_constant_abi: bool,
    ) -> Result<(), RuntimeError> {
        if kind == RuntimeKind::Trigger && !allow_constantinople && is_constant_abi {
            Err(RuntimeError::ConstantMethod)
        } else {
            Ok(())
        }
    }
    /// Selects the VM wall-clock deadline with Java-compatible constant-call semantics.
    /// A configured constant-call timeout is used verbatim; all other calls use the
    /// network deadline, whose retry attempt retains the production 2x extension.
    #[must_use]
    pub fn execution_deadline(
        is_constant_call: bool,
        network_deadline: Duration,
        configured_constant_timeout: Option<Duration>,
        retry: bool,
    ) -> Duration {
        if is_constant_call {
            if let Some(timeout) = configured_constant_timeout.filter(|timeout| !timeout.is_zero()) {
                return timeout;
            }
        }
        if retry { network_deadline.saturating_mul(2) } else { network_deadline }
    }

    pub fn trigger_is_constant_abi(
        contract: &Contract,
        session: &Session,
        config: &ExecutionRuntimeConfig,
    ) -> Result<bool, RuntimeError> {
        if Self::kind(contract)? != RuntimeKind::Trigger {
            return Ok(false);
        }
        let decoded = config.actuator_registry.decode(contract)?;
        let crate::DecodedContract::BuiltIn(BuiltinContract::TriggerSmartContract(trigger)) = decoded else {
            return Err(RuntimeError::WrongState("VM contract envelope"));
        };
        if trigger.data.len() < 4 {
            return Ok(false);
        }
        let address = TronAddress21::validate_mainnet(&trigger.contract_address)
            .map_err(|_| RuntimeError::WrongState("trigger contract address"))?;
        let mut repository = Repository::from_session(session);
        repository.set_blackhole_address(Self::blackhole(config)?);
        let Some(abi) = repository.abi(&address).map_err(|error| RuntimeError::Vm(error.to_string()))? else {
            return Ok(false);
        };
        let selector = &trigger.data[..4];
        for entry in abi.entrys {
            if EntryType::try_from(entry.r#type) != Ok(EntryType::Function) {
                continue;
            }
            let mut signature = String::with_capacity(entry.name.len() + 2 + entry.inputs.iter().map(|input| input.r#type.len()).sum::<usize>());
            signature.push_str(&entry.name);
            signature.push('(');
            for (index, input) in entry.inputs.iter().enumerate() {
                if index != 0 { signature.push(','); }
                signature.push_str(&input.r#type);
            }
            signature.push(')');
            if &keccak256(signature.as_bytes())[..4] == selector {
                let mutability = StateMutabilityType::try_from(entry.state_mutability).unwrap_or(StateMutabilityType::UnknownMutabilityType);
                return Ok(entry.constant || matches!(mutability, StateMutabilityType::Pure | StateMutabilityType::View));
            }
        }
        Ok(false)
    }

    pub(crate) fn execute_transaction(
        &self,
        contract: &Contract,
        session: &Session,
        actuator_result: &mut ActuatorResult,
        transaction_id: Hash32,
        energy_plan: Option<&EnergyExecutionPlan>,
        retry: bool,
    ) -> Result<RuntimeResult, RuntimeError> {
        match Self::kind(contract)? {
            RuntimeKind::NonVm => {
                self.config.actuator_registry.execute(
                    contract,
                    session,
                    Some(actuator_result),
                    self.config.execution_config.clone(),
                )?;
                Ok(RuntimeResult::from_actuator(actuator_result.clone()))
            }
            RuntimeKind::Create | RuntimeKind::Trigger => {
                let energy_plan = energy_plan.ok_or(RuntimeError::MissingState("VM energy execution plan"))?;
                let invocation = self.canonical_invocation(
                    contract,
                    session,
                    TransactionId::new(transaction_id),
                    energy_plan,
                    retry,
                )?;
                self.execute_vm(session, invocation)
            }
        }
    }

    fn canonical_invocation(
        &self,
        envelope: &Contract,
        session: &Session,
        transaction_id: TransactionId,
        energy_plan: &EnergyExecutionPlan,
        retry: bool,
    ) -> Result<CanonicalVmInvocation, RuntimeError> {
        let decoded = self.config.actuator_registry.decode(envelope)?;
        let mut repository = Repository::from_session(session);
        repository.set_blackhole_address(Self::blackhole(self.config)?);
        let energy_height = repository
            .dynamic_i64("ENERGY_LIMIT_HARD_FORK")
            .map_err(|error| RuntimeError::Vm(error.to_string()))?
            .unwrap_or(i64::MAX);
        let rules = TvmRules::load(&repository, energy_height)
            .map_err(|error| RuntimeError::Vm(error.to_string()))?;
        drop(repository);

        let (owner, address, input, call_value, token_value, token_id, code, version, create_contract) =
            match decoded {
                crate::DecodedContract::BuiltIn(BuiltinContract::CreateSmartContract(create)) => {
                    self.create_invocation(session, create, &transaction_id)?
                }
                crate::DecodedContract::BuiltIn(BuiltinContract::TriggerSmartContract(trigger)) => {
                    self.trigger_invocation(session, trigger)?
                }
                _ => return Err(RuntimeError::WrongState("VM contract envelope")),
            };

        let owner_address = TronAddress21::validate_mainnet(&owner)
            .map_err(|_| RuntimeError::WrongState("VM owner address"))?;
        let contract_address = TronAddress21::validate_mainnet(&address)
            .map_err(|_| RuntimeError::WrongState("VM contract address"))?;
        if session.store(StoreKind::Account).get(&owner).is_none() {
            return Err(RuntimeError::MissingState("VM owner account"));
        }
        let network_deadline = Duration::from_millis(
            optional_dynamic_i64(session, "MAX_CPU_TIME_OF_ONE_TX")?.unwrap_or(50).max(1) as u64,
        );
        let is_constant_call = Self::trigger_is_constant_abi(envelope, session, self.config)?;
        let deadline = Self::execution_deadline(
            is_constant_call,
            network_deadline,
            self.config.constant_call_timeout,
            retry,
        );

        Ok(CanonicalVmInvocation {
            frame: FrameContext {
                code_address: contract_address,
                context_address: contract_address,
                origin: owner_address,
                caller: owner_address,
                input,
                call_value: nonnegative_word(call_value, "VM call value")?,
                token_value: nonnegative_word(token_value, "VM token value")?,
                token_id: nonnegative_word(token_id, "VM token id")?,
                root_txid: transaction_id,
                contract_version: version,
                depth: 0,
                is_static: false,
            },
            code,
            energy_limit: energy_plan.energy_limit,
            rules,
            deadline,
            create_contract,
        })
    }

    #[allow(clippy::type_complexity)]
    fn create_invocation(
        &self,
        session: &Session,
        create: CreateSmartContract,
        transaction_id: &TransactionId,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64, Vec<u8>, i32, Option<SmartContract>), RuntimeError> {
        let owner = TronAddress21::validate_mainnet(&create.owner_address)
            .map_err(|_| RuntimeError::WrongState("create owner address"))?;
        let mut contract = create
            .new_contract
            .ok_or(RuntimeError::MissingState("create contract metadata"))?;
        let derived = top_level_contract_address(transaction_id, &owner);
        if !contract.contract_address.is_empty() && contract.contract_address != derived.as_bytes() {
            return Err(RuntimeError::WrongState("create contract address"));
        }
        contract.contract_address = derived.as_bytes().to_vec();
        contract.origin_address = create.owner_address.clone();
        let code = core::mem::take(&mut contract.bytecode);
        if code.is_empty() { return Err(RuntimeError::MissingState("create init code")); }
        if session.store(StoreKind::Account).get(derived.as_bytes()).is_some()
            || session.store(StoreKind::Contract).get(derived.as_bytes()).is_some()
            || session.store(StoreKind::Code).get(derived.as_bytes()).is_some()
        {
            return Err(RuntimeError::WrongState("create destination state"));
        }
        Ok((
            create.owner_address,
            derived.as_bytes().to_vec(),
            Vec::new(),
            contract.call_value,
            create.call_token_value,
            create.token_id,
            code,
            contract.version,
            Some(contract),
        ))
    }

    #[allow(clippy::type_complexity)]
    fn trigger_invocation(
        &self,
        session: &Session,
        trigger: TriggerSmartContract,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64, Vec<u8>, i32, Option<SmartContract>), RuntimeError> {
        TronAddress21::validate_mainnet(&trigger.owner_address)
            .map_err(|_| RuntimeError::WrongState("trigger owner address"))?;
        TronAddress21::validate_mainnet(&trigger.contract_address)
            .map_err(|_| RuntimeError::WrongState("trigger contract address"))?;
        let bytes = session
            .store(StoreKind::Contract)
            .get(&trigger.contract_address)
            .ok_or(RuntimeError::MissingState("trigger contract metadata"))?;
        let contract = SmartContract::decode(bytes.as_slice())
            .map_err(|_| RuntimeError::WrongState("trigger contract metadata"))?;
        if contract.contract_address != trigger.contract_address {
            return Err(RuntimeError::WrongState("trigger contract metadata address"));
        }
        let account_bytes = session.store(StoreKind::Account).get(&trigger.contract_address)
            .ok_or(RuntimeError::MissingState("trigger contract account"))?;
        let account = Account::decode(account_bytes.as_slice())
            .map_err(|_| RuntimeError::WrongState("trigger contract account"))?;
        if account.r#type != AccountType::Contract as i32 {
            return Err(RuntimeError::WrongState("trigger contract account type"));
        }
        let code = session
            .store(StoreKind::Code)
            .get(&trigger.contract_address)
            .ok_or(RuntimeError::MissingState("trigger runtime code"))?;
        if code.is_empty() { return Err(RuntimeError::MissingState("trigger runtime code")); }
        Ok((
            trigger.owner_address,
            trigger.contract_address,
            trigger.data,
            trigger.call_value,
            trigger.call_token_value,
            trigger.token_id,
            code,
            contract.version,
            None,
        ))
    }

    fn execute_vm(
        &self,
        session: &Session,
        invocation: CanonicalVmInvocation,
    ) -> Result<RuntimeResult, RuntimeError> {
        let mut repository = Repository::from_session(session);
        repository.set_blackhole_address(Self::blackhole(self.config)?);
        if let Some(contract) = invocation.create_contract.as_ref() {
            repository.put_account(&Account {
                address: contract.contract_address.clone(),
                r#type: AccountType::Contract as i32,
                ..Default::default()
            });
            repository.put_contract(contract.clone());
        }
        self.transfer_root_value(&mut repository, &invocation.frame)?;
        let interpreter = Interpreter::new(&self.config.operation_registry, &invocation.rules)
            .with_shielded_parameters(Arc::clone(&self.config.shielded_parameters));
        let mut program = Program::new(invocation.code);
        let mut stack = Stack1024::default();
        let mut memory = Memory::default();
        let mut meter = EnergyMeter::new(invocation.energy_limit)
            .map_err(|fault| RuntimeError::Vm(format!("{fault:?}")))?;
        let mut trace = NoTrace;
        if let Some(observer) = &self.config.deadline_observer {
            observer(invocation.deadline);
        }
        let mut limiter = DeadlineLimiter::new(ProcessMonotonicClock::start(), invocation.deadline);
        let outcome = interpreter.run(
            &invocation.frame,
            &mut program,
            &mut stack,
            &mut memory,
            &mut repository,
            &mut meter,
            &mut limiter,
            &mut trace,
        );
        if matches!(outcome.status, tron_tvm::ExitStatus::Succeeded) {
            if invocation.create_contract.is_some() {
                repository.put_code(invocation.frame.context_address, outcome.return_data.clone());
            }
            repository.flush_into_session().map_err(|error| RuntimeError::Vm(error.to_string()))?;
        }
        Ok(RuntimeResult::from_vm(outcome))
    }

    fn transfer_root_value(
        &self,
        repository: &mut Repository<'_>,
        frame: &FrameContext,
    ) -> Result<(), RuntimeError> {
        if !frame.call_value.is_zero() {
            let amount = frame.call_value.to_i64_safe();
            let owner = repository.balance(&frame.origin).map_err(|error| RuntimeError::Vm(error.to_string()))?;
            let destination = repository.balance(&frame.context_address).map_err(|error| RuntimeError::Vm(error.to_string()))?;
            if owner < amount { return Err(RuntimeError::Vm("insufficient balance for VM call value".into())); }
            let credited = destination.checked_add(amount).ok_or(RuntimeError::WrongState("VM destination balance"))?;
            repository.set_balance(&frame.origin, owner - amount).map_err(|error| RuntimeError::Vm(error.to_string()))?;
            repository.set_balance(&frame.context_address, credited).map_err(|error| RuntimeError::Vm(error.to_string()))?;
        }
        if !frame.token_value.is_zero() {
            let amount = frame.token_value.to_i64_safe();
            let token = frame.token_id.to_i64_safe().to_string();
            let owner = repository.token_balance(&frame.origin, &token).map_err(|error| RuntimeError::Vm(error.to_string()))?;
            let destination = repository.token_balance(&frame.context_address, &token).map_err(|error| RuntimeError::Vm(error.to_string()))?;
            if owner < amount { return Err(RuntimeError::Vm("insufficient token balance for VM call value".into())); }
            let credited = destination.checked_add(amount).ok_or(RuntimeError::WrongState("VM destination token balance"))?;
            repository.set_token_balance(&frame.origin, token.clone(), owner - amount).map_err(|error| RuntimeError::Vm(error.to_string()))?;
            repository.set_token_balance(&frame.context_address, token, credited).map_err(|error| RuntimeError::Vm(error.to_string()))?;
        }
        Ok(())
    }

    fn blackhole(config: &ExecutionRuntimeConfig) -> Result<TronAddress21, RuntimeError> {
        TronAddress21::validate_mainnet(&config.execution_config.blackhole_address)
            .map_err(|_| RuntimeError::WrongState("blackhole address"))
    }
}

fn nonnegative_word(value: i64, field: &'static str) -> Result<Word, RuntimeError> {
    u64::try_from(value).map(Word::from).map_err(|_| RuntimeError::WrongState(field))
}

fn optional_dynamic_i64(session: &Session, name: &'static str) -> Result<Option<i64>, RuntimeError> {
    let key = dynamic::key(name).ok_or(RuntimeError::MissingState("dynamic property key"))?;
    let Some(bytes) = session.store(StoreKind::DynamicProperties).get(key) else { return Ok(None); };
    let value: [u8; 8] = bytes.as_slice().try_into().map_err(|_| RuntimeError::WrongState(name))?;
    Ok(Some(i64::from_be_bytes(value)))
}


#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeResult {
    pub actuator: ActuatorResult,
    pub vm: Option<ExecutionOutcome>,
    pub runtime_error: String,
}
impl RuntimeResult {
    pub fn from_actuator(actuator: ActuatorResult) -> Self {
        let runtime_error = if actuator.code
            == tron_protocol::protocol::transaction::result::Code::Failed
        {
            String::from_utf8_lossy(&actuator.message).into_owned()
        } else {
            String::new()
        };
        Self { actuator, vm: None, runtime_error }
    }
    pub fn from_vm(vm: ExecutionOutcome) -> Self {
        let runtime_error = match vm.status {
            tron_tvm::ExitStatus::Succeeded => String::new(),
            tron_tvm::ExitStatus::Reverted => "REVERT opcode executed".into(),
            tron_tvm::ExitStatus::Faulted(fault) => format!("{fault:?}"),
        };
        Self { actuator: ActuatorResult::default(), vm: Some(vm), runtime_error }
    }
}

pub fn run_with_out_of_time_retry<F>(
    origin: crate::AdmissionOrigin,
    expected: Option<tron_tvm::ContractResult>,
    mut run: F,
) -> Result<(RuntimeResult, bool), RuntimeError>
where
    F: FnMut(bool) -> Result<RuntimeResult, RuntimeError>,
{
    let first = run(false)?;
    let actual = first.vm.as_ref().map(|value| value.contract_result);
    if origin == crate::AdmissionOrigin::Block
        && actual == Some(tron_tvm::ContractResult::OutOfTime)
        && expected != Some(tron_tvm::ContractResult::OutOfTime)
    {
        return Ok((run(true)?, true));
    }
    Ok((first, false))
}

pub fn check_witness_result(
    expected: Option<tron_tvm::ContractResult>,
    actual: tron_tvm::ContractResult,
    vm: bool,
) -> Result<(), RuntimeError> {
    if !vm || expected.is_none() { return Ok(()); }
    let expected = expected.expect("checked above");
    if expected != actual {
        return Err(RuntimeError::Vm(format!(
            "different resultCode, expect: {expected:?}, actual: {actual:?}"
        )));
    }
    Ok(())
}
