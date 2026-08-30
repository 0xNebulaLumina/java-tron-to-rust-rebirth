use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Barrier, LazyLock,
    },
    thread,
    time::{Duration, Instant},
};

use tron_shielded::{
    compute_cm, compute_nf, external_key_path, generate_r, ka_derive_public, load_tron_parameters,
    spend_sig, zip32_xsk_master, BindingSigParams,
    CheckOutputNewParams, CheckOutputParams, CheckSpendParams, ContextTable, FinalCheckNewParams,
    FinalCheckParams, JavaMerklePath, OutputProofParams, ParameterKind, ShieldedError,
    ShieldedRawAdapter, SpendProofParams, TronParameters, Validate, VerificationContext,
    DEFAULT_MAX_CONTEXTS,
};

fn parameter_paths() -> (PathBuf, PathBuf) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../java-tron/framework/src/main/resources/params");
    (root.join("sapling-spend.params"), root.join("sapling-output.params"))
}
static PARAMETERS: LazyLock<Arc<TronParameters>> = LazyLock::new(|| {
    let (spend, output) = parameter_paths();
    load_tron_parameters(spend, output).expect("bundled TRON parameters authenticate")
});

fn parameters() -> Arc<TronParameters> {
    Arc::clone(&PARAMETERS)
}

fn output_params(ctx: u64, diversifier: [u8; 11], pk_d: [u8; 32], value: i64) -> (OutputProofParams, [u8; 32], [u8; 32]) {
    let esk = generate_r();
    let rcm = generate_r();
    let cm = compute_cm(diversifier, pk_d, value as u64, rcm).unwrap();
    let ephemeral_key = ka_derive_public(diversifier, esk).unwrap();
    (
        OutputProofParams {
            ctx,
            esk: esk.to_vec(),
            d: diversifier.to_vec(),
            pk_d: pk_d.to_vec(),
            r: rcm.to_vec(),
            value,
            cv: vec![0; 32],
            zkproof: vec![0; 192],
        },
        cm,
        ephemeral_key,
    )
}

#[test]
fn context_bound_is_explicit_and_nonzero() {
    assert_eq!(DEFAULT_MAX_CONTEXTS, 64);
    assert!(matches!(
        ContextTable::with_max_contexts(0),
        Err(ShieldedError::InvalidParameter(message)) if message == "max contexts must be positive"
    ));
    assert!(ContextTable::with_max_contexts(8).is_ok());
}

#[test]
fn raw_validation_rejects_before_output_mutation() {
    let original_cv = vec![0x51; 32];
    let original_rk = vec![0x52; 32];
    let original_proof = vec![0x53; 192];
    let params = SpendProofParams {
        ctx: 1,
        ak: vec![0; 31],
        nsk: vec![0; 32],
        d: vec![0; 11],
        r: vec![0; 32],
        alpha: vec![0; 32],
        value: 1,
        anchor: vec![0; 32],
        voucher_path: vec![0; 1065],
        cv: original_cv.clone(),
        rk: original_rk.clone(),
        zkproof: original_proof.clone(),
    };

    assert!(params.validate().is_err());
    assert_eq!(params.cv, original_cv);
    assert_eq!(params.rk, original_rk);
    assert_eq!(params.zkproof, original_proof);
}

#[test]
fn binding_and_new_final_wrappers_enforce_declared_shapes() {
    let binding = BindingSigParams {
        ctx: 1,
        value_balance: 0,
        sighash: vec![0; 31],
        result: vec![0x7a; 64],
    };
    assert!(binding.validate().is_err());
    assert_eq!(binding.result, vec![0x7a; 64]);

    let final_new = FinalCheckNewParams {
        value_balance: 0,
        binding_sig: vec![0; 64],
        sighash_value: vec![0; 32],
        spend_cv: vec![0; 32],
        spend_cv_len: 31,
        output_cv: vec![0; 32],
        output_cv_len: 32,
    };
    assert!(final_new.validate().is_err());
}

#[test]
fn exact_java_empty_context_nonzero_binding_balance_fails_without_output_mutation() {
    let adapter = ShieldedRawAdapter::new(parameters());
    let proving = adapter.proving_ctx_init().unwrap();
    let sighash = (0u8..16).chain(0u8..16).collect::<Vec<_>>();
    let original = vec![0x7a; 64];
    let mut binding = BindingSigParams {
        ctx: proving,
        value_balance: 1,
        sighash,
        result: original.clone(),
    };

    assert!(matches!(
        adapter.binding_sig(&mut binding),
        Err(ShieldedError::InvalidParameter(message))
            if message == "value balance is inconsistent with proving context"
    ));
    assert_eq!(binding.result, original);
    adapter.proving_ctx_free(proving).unwrap();
}

#[test]
fn actual_spend_output_proofs_verify_and_finalize() {
    let adapter = ShieldedRawAdapter::new(parameters());
    let proving = adapter.proving_ctx_init().unwrap();
    let keys = external_key_path(&zip32_xsk_master(b"C006 real proof fixture")).unwrap();
    let pk_d: [u8; 32] = keys.payment_address[11..].try_into().unwrap();
    let sighash = [0x5a; 32];

    let mut spends = Vec::new();
    for value in [5i64, 7] {
        let rcm = generate_r();
        let cm = compute_cm(keys.diversifier, pk_d, value as u64, rcm).unwrap();
        let path = JavaMerklePath {
            siblings: (0..32).map(|depth| tron_shielded::empty_root(depth).unwrap()).collect(),
            position: 0,
        };
        let anchor = path.root(cm).unwrap();
        let alpha = generate_r();
        let mut spend = SpendProofParams {
            ctx: proving,
            ak: keys.ak.to_vec(),
            nsk: keys.nsk.to_vec(),
            d: keys.diversifier.to_vec(),
            r: rcm.to_vec(),
            alpha: alpha.to_vec(),
            value,
            anchor: anchor.to_vec(),
            voucher_path: path.encode().unwrap(),
            cv: vec![0; 32],
            rk: vec![0; 32],
            zkproof: vec![0; 192],
        };
        adapter.spend_proof(&mut spend).unwrap();
        assert_ne!(spend.cv, vec![0; 32]);
        assert_ne!(spend.rk, vec![0; 32]);
        assert_ne!(spend.zkproof, vec![0; 192]);
        spends.push((spend, anchor, rcm, alpha, value));
    }
    assert_ne!(spends[0].0.cv, spends[1].0.cv);

    let mut outputs = Vec::new();
    for value in [2i64, 4, 5] {
        let (mut output, cm, ephemeral_key) =
            output_params(proving, keys.diversifier, pk_d, value);
        adapter.output_proof(&mut output).unwrap();
        assert_ne!(output.cv, vec![0; 32]);
        assert_ne!(output.zkproof, vec![0; 192]);
        outputs.push((output, cm, ephemeral_key));
    }
    assert_ne!(outputs[0].0.cv, outputs[1].0.cv);
    assert_ne!(outputs[1].0.cv, outputs[2].0.cv);

    let mut inconsistent_binding = BindingSigParams {
        ctx: proving,
        value_balance: 0,
        sighash: sighash.to_vec(),
        result: vec![0x6b; 64],
    };
    assert!(adapter.binding_sig(&mut inconsistent_binding).is_err());
    assert_eq!(inconsistent_binding.result, vec![0x6b; 64]);

    let mut binding = BindingSigParams {
        ctx: proving,
        value_balance: 1,
        sighash: sighash.to_vec(),
        result: vec![0; 64],
    };
    adapter.binding_sig(&mut binding).unwrap();

    let verification = adapter.verification_ctx_init().unwrap();
    let mut spend_checks = Vec::new();
    for (spend, anchor, rcm, alpha, value) in &spends {
        let check = CheckSpendParams {
            ctx: Some(verification),
            cv: spend.cv.clone(),
            anchor: anchor.to_vec(),
            nullifier: compute_nf(
                keys.diversifier,
                pk_d,
                *value as u64,
                *rcm,
                keys.ak,
                keys.nk,
                0,
            )
            .unwrap()
            .to_vec(),
            rk: spend.rk.clone(),
            zkproof: spend.zkproof.clone(),
            spend_auth_sig: spend_sig(keys.ask, *alpha, sighash).unwrap().to_vec(),
            sighash_value: sighash.to_vec(),
        };
        assert!(adapter.check_spend(&check).unwrap());
        spend_checks.push(check);
    }

    for (output, cm, ephemeral_key) in &outputs {
        assert!(adapter
            .check_output(&CheckOutputParams {
                ctx: Some(verification),
                cv: output.cv.clone(),
                cm: cm.to_vec(),
                ephemeral_key: ephemeral_key.to_vec(),
                zkproof: output.zkproof.clone(),
            })
            .unwrap());
    }
    let mut incremental = VerificationContext::new(parameters());
    for check in &spend_checks {
        assert!(incremental
            .check_spend(
                check.cv.clone().try_into().unwrap(),
                check.anchor.clone().try_into().unwrap(),
                check.nullifier.clone().try_into().unwrap(),
                check.rk.clone().try_into().unwrap(),
                &check.zkproof,
                check.spend_auth_sig.clone().try_into().unwrap(),
                check.sighash_value.clone().try_into().unwrap(),
            )
            .unwrap());
    }
    for (output, cm, ephemeral_key) in &outputs {
        assert!(incremental
            .check_output(
                output.cv.clone().try_into().unwrap(),
                *cm,
                *ephemeral_key,
                &output.zkproof,
            )
            .unwrap());
    }
    assert_eq!(incremental.spend_count(), 2);
    assert_eq!(incremental.output_count(), 3);
    assert_eq!(incremental.preverification_count(), 5);
    assert!(!incremental
        .check_output([0; 32], [0; 32], [0; 32], &[0; 192])
        .unwrap_or(false));
    assert_eq!(incremental.preverification_count(), 5);
    assert!(adapter
        .final_check(&FinalCheckParams {
            ctx: Some(verification),
            value_balance: 1,
            binding_sig: binding.result.clone(),
            sighash_value: sighash.to_vec(),
        })
        .unwrap());

    let mut wrong_sighash = sighash;
    wrong_sighash[0] ^= 1;
    assert!(!adapter
        .final_check(&FinalCheckParams {
            ctx: Some(verification),
            value_balance: 1,
            binding_sig: binding.result.clone(),
            sighash_value: wrong_sighash.to_vec(),
        })
        .unwrap());
    assert!(adapter
        .check_spend_new(&CheckSpendParams {
            ctx: None,
            ..spend_checks[0].clone()
        })
        .unwrap());
    assert!(adapter
        .check_output_new(&CheckOutputNewParams {
            cv: outputs[0].0.cv.clone(),
            cm: outputs[0].1.to_vec(),
            ephemeral_key: outputs[0].2.to_vec(),
            zkproof: outputs[0].0.zkproof.clone(),
        })
        .unwrap());

    let spend_cv = spends.iter().flat_map(|(spend, ..)| spend.cv.iter().copied()).collect::<Vec<_>>();
    let output_cv = outputs.iter().flat_map(|(output, ..)| output.cv.iter().copied()).collect::<Vec<_>>();
    assert_eq!(spend_cv.len(), 64);
    assert_eq!(output_cv.len(), 96);
    assert!(adapter
        .final_check_new(&FinalCheckNewParams {
            value_balance: 1,
            binding_sig: binding.result.clone(),
            sighash_value: sighash.to_vec(),
            spend_cv,
            spend_cv_len: 64,
            output_cv,
            output_cv_len: 96,
        })
        .unwrap());

    adapter.proving_ctx_free(proving).unwrap();
    adapter.verification_ctx_free(verification).unwrap();
}

#[test]
fn invalid_proof_inputs_do_not_mutate_outputs_or_verification_state() {
    let params = parameters();
    let adapter = ShieldedRawAdapter::new(Arc::clone(&params));
    let proving = adapter.proving_ctx_init().unwrap();
    let mut invalid = SpendProofParams {
        ctx: proving,
        ak: vec![0xff; 32],
        nsk: vec![0; 32],
        d: vec![0; 11],
        r: vec![0; 32],
        alpha: vec![0; 32],
        value: 1,
        anchor: vec![0; 32],
        voucher_path: JavaMerklePath { siblings: vec![[0; 32]; 32], position: 0 }.encode().unwrap(),
        cv: vec![0x51; 32],
        rk: vec![0x52; 32],
        zkproof: vec![0x53; 192],
    };
    assert!(adapter.spend_proof(&mut invalid).is_err());
    assert_eq!(invalid.cv, vec![0x51; 32]);
    assert_eq!(invalid.rk, vec![0x52; 32]);
    assert_eq!(invalid.zkproof, vec![0x53; 192]);

    let mut verification = tron_shielded::VerificationContext::new(params);
    assert_eq!(verification.spend_count(), 0);
    assert!(!verification
        .check_spend([0; 32], [0; 32], [0; 32], [0; 32], &[0; 192], [0; 64], [0; 32])
        .unwrap_or(false));
    assert_eq!(verification.spend_count(), 0);
    assert_eq!(verification.output_count(), 0);
    assert!(!verification.check_output([0; 32], [0; 32], [0; 32], &[0; 192]).unwrap_or(false));
    assert_eq!(verification.output_count(), 0);
    adapter.proving_ctx_free(proving).unwrap();
}

#[test]
fn context_wrong_kind_double_free_and_bounds_are_rejected() {
    let table = ContextTable::with_max_contexts(2).unwrap();
    let proving = table.init_proving(parameters()).unwrap();
    let verification = table.init_verification(parameters()).unwrap();
    assert!(matches!(table.init_proving(parameters()), Err(ShieldedError::ContextLimit { max: 2 })));
    assert!(matches!(table.with_verification(proving, |_| Ok(())), Err(ShieldedError::InvalidHandle)));
    assert!(matches!(table.with_proving(verification, |_| Ok(())), Err(ShieldedError::InvalidHandle)));
    assert!(matches!(table.free_verification(proving), Err(ShieldedError::InvalidHandle)));
    assert_eq!(table.len(), 2);
    table.free_proving(proving).unwrap();
    assert!(matches!(table.free_proving(proving), Err(ShieldedError::InvalidHandle)));
    table.free_verification(verification).unwrap();
    assert!(table.is_empty());
}

#[test]
fn freeing_locked_context_does_not_block_other_contexts() {
    let table = Arc::new(ContextTable::with_max_contexts(2).unwrap());
    let locked_handle = table.init_proving(parameters()).unwrap();
    let other_handle = table.init_proving(parameters()).unwrap();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let locked_table = Arc::clone(&table);
    let locked = thread::spawn(move || {
        locked_table
            .with_proving(locked_handle, |_| {
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
    });
    locked_rx.recv().unwrap();

    let free_table = Arc::clone(&table);
    let (free_started_tx, free_started_rx) = mpsc::channel();
    let freeing = thread::spawn(move || {
        free_started_tx.send(()).unwrap();
        free_table.free_proving(locked_handle)
    });
    free_started_rx.recv().unwrap();
    thread::sleep(Duration::from_millis(50));

    let other_table = Arc::clone(&table);
    let (other_done_tx, other_done_rx) = mpsc::channel();
    let other = thread::spawn(move || {
        let result = other_table.with_proving(other_handle, |_| Ok(()));
        other_done_tx.send(result).unwrap();
    });
    let other_result = other_done_rx.recv_timeout(Duration::from_secs(1));

    release_tx.send(()).unwrap();
    locked.join().unwrap();
    freeing.join().unwrap().unwrap();
    other.join().unwrap();
    other_result.expect("unrelated context operation was blocked by free").unwrap();
    table.free_proving(other_handle).unwrap();
}

#[test]
fn same_handle_queued_before_free_obeys_retirement_barrier() {
    let table = Arc::new(ContextTable::with_max_contexts(1).unwrap());
    let handle = table.init_proving(parameters()).unwrap();
    let mutations = Arc::new(AtomicUsize::new(0));
    let (admitted_tx, admitted_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let active_table = Arc::clone(&table);
    let active_mutations = Arc::clone(&mutations);
    let active = thread::spawn(move || {
        active_table
            .with_proving(handle, |_| {
                admitted_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                active_mutations.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();
    });
    admitted_rx.recv().unwrap();

    let free_table = Arc::clone(&table);
    let (free_done_tx, free_done_rx) = mpsc::channel();
    let freeing = thread::spawn(move || {
        let result = free_table.free_proving(handle);
        free_done_tx.send(result).unwrap();
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while !table.is_empty() {
        assert!(Instant::now() < deadline, "free did not retire the handle");
        thread::yield_now();
    }
    assert!(matches!(
        table.with_proving(handle, |_| {
            mutations.fetch_add(100, Ordering::SeqCst);
            Ok(())
        }),
        Err(ShieldedError::InvalidHandle)
    ));
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
    assert!(free_done_rx.recv_timeout(Duration::from_millis(50)).is_err());

    release_tx.send(()).unwrap();
    active.join().unwrap();
    free_done_rx.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
    freeing.join().unwrap();
    assert_eq!(mutations.load(Ordering::SeqCst), 1);
    assert!(matches!(table.with_proving(handle, |_| Ok(())), Err(ShieldedError::InvalidHandle)));
}

#[test]
fn retiring_context_keeps_its_capacity_reserved_until_quiesced() {
    const MAX_CONTEXTS: usize = 3;
    const BATCHES: usize = 8;
    let table = Arc::new(ContextTable::with_max_contexts(MAX_CONTEXTS).unwrap());

    for _ in 0..BATCHES {
        let active_handle = table.init_proving(parameters()).unwrap();
        let idle_handles = [
            table.init_proving(parameters()).unwrap(),
            table.init_proving(parameters()).unwrap(),
        ];
        assert!(matches!(
            table.init_proving(parameters()),
            Err(ShieldedError::ContextLimit { max: MAX_CONTEXTS })
        ));

        let (admitted_tx, admitted_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let active_table = Arc::clone(&table);
        let active = thread::spawn(move || {
            active_table
                .with_proving(active_handle, |_| {
                    admitted_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .unwrap();
        });
        admitted_rx.recv().unwrap();

        let free_table = Arc::clone(&table);
        let (free_done_tx, free_done_rx) = mpsc::channel();
        let freeing = thread::spawn(move || {
            free_done_tx.send(free_table.free_proving(active_handle)).unwrap();
        });

        let deadline = Instant::now() + Duration::from_secs(1);
        while table.len() == MAX_CONTEXTS {
            assert!(Instant::now() < deadline, "free did not retire the active handle");
            thread::yield_now();
        }
        assert!(matches!(
            table.with_proving(active_handle, |_| Ok(())),
            Err(ShieldedError::InvalidHandle)
        ));
        assert!(matches!(
            table.init_proving(parameters()),
            Err(ShieldedError::ContextLimit { max: MAX_CONTEXTS })
        ));
        assert!(free_done_rx.recv_timeout(Duration::from_millis(50)).is_err());

        release_tx.send(()).unwrap();
        active.join().unwrap();
        free_done_rx.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
        freeing.join().unwrap();

        let replacement = table.init_proving(parameters()).unwrap();
        assert_eq!(table.len(), MAX_CONTEXTS);
        assert!(matches!(
            table.init_verification(parameters()),
            Err(ShieldedError::ContextLimit { max: MAX_CONTEXTS })
        ));
        table.free_proving(replacement).unwrap();
        for handle in idle_handles {
            table.free_proving(handle).unwrap();
        }
        assert!(table.is_empty());
    }
}

#[test]
fn bounded_concurrent_contexts_replace_ignored_benchmark() {
    const WORKERS: usize = 8;
    let table = Arc::new(ContextTable::with_max_contexts(WORKERS).unwrap());
    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut workers = Vec::with_capacity(WORKERS);
    for index in 0..WORKERS {
        let table = Arc::clone(&table);
        let barrier = Arc::clone(&barrier);
        let params = parameters();
        workers.push(thread::spawn(move || {
            let handle = if index % 2 == 0 {
                table.init_proving(params).unwrap()
            } else {
                table.init_verification(params).unwrap()
            };
            barrier.wait();
            if index % 2 == 0 {
                table.with_proving(handle, |_| Ok(())).unwrap();
                table.free_proving(handle).unwrap();
            } else {
                table.with_verification(handle, |_| Ok(())).unwrap();
                table.free_verification(handle).unwrap();
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert!(table.is_empty());
}

#[test]
fn authenticated_parameter_snapshot_survives_in_place_mutation() {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);
    let (spend, output) = parameter_paths();
    let temp = std::env::temp_dir().join(format!(
        "tron-shielded-c006-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&temp).unwrap();
    let mutable_spend = temp.join("spend.params");
    fs::copy(&spend, &mutable_spend).unwrap();

    let mut opens = Vec::new();
    let loaded = TronParameters::load_with_opener(&mutable_spend, &output, |kind, path| {
        opens.push(kind);
        let descriptor = File::open(path)?;
        if kind == ParameterKind::Output {
            OpenOptions::new().write(true).open(&mutable_spend)?.set_len(0)?;
        }
        Ok(descriptor)
    });
    assert!(
        loaded.is_ok(),
        "deserialization must use the immutable authenticated snapshot after the source is truncated"
    );
    assert_eq!(opens, vec![ParameterKind::Spend, ParameterKind::Output]);
    assert_eq!(fs::metadata(&mutable_spend).unwrap().len(), 0);

    fs::copy(&spend, &mutable_spend).unwrap();
    OpenOptions::new()
        .write(true)
        .open(&mutable_spend)
        .unwrap()
        .write_all(&[0])
        .unwrap();
    let mut rejected_opens = Vec::new();
    let rejected = TronParameters::load_with_opener(&mutable_spend, &output, |kind, path| {
        rejected_opens.push(kind);
        File::open(path)
    });
    assert!(matches!(
        rejected,
        Err(ShieldedError::ParameterHash { kind: ParameterKind::Spend, .. })
    ));
    assert_eq!(rejected_opens, vec![ParameterKind::Spend]);
    fs::remove_dir_all(temp).unwrap();
}
