use {
    criterion::{criterion_group, criterion_main, Criterion},
    solana_bls_signatures::{
        keypair::Keypair,
        pubkey::{PubkeyProjective, VerifiablePubkey},
        signature::SignatureProjective,
    },
    std::hint::black_box,
};

// Benchmark for verifying a single signature
fn bench_single_signature(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_signature");
    let keypair = Keypair::new();
    let message = b"test message";

    group.bench_function("signature_generation", |b| {
        b.iter(|| black_box(keypair.sign(message)));
    });

    let signature = keypair.sign(message);
    group.bench_function("verify_signature", |b| {
        b.iter(|| black_box(keypair.public.verify_signature(&signature, message)).unwrap());
    });
    group.finish();
}

// Worst-case benchmark for aggregate signature verification
fn bench_aggregate(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregate_verify");
    // Test with a range of validator counts to simulate different scales
    for num_validators in [64, 128, 256, 512, 1024, 2048].iter() {
        let message = b"test message";
        let keypairs: Vec<Keypair> = (0..*num_validators).map(|_| Keypair::new()).collect();
        let pubkeys: Vec<PubkeyProjective> = keypairs.iter().map(|kp| kp.public).collect();
        let signatures: Vec<SignatureProjective> =
            keypairs.iter().map(|kp| kp.sign(message)).collect();

        let pubkey_refs: Vec<&PubkeyProjective> = pubkeys.iter().collect();
        let signature_refs: Vec<&SignatureProjective> = signatures.iter().collect();

        // Benchmark for aggregating multiple signatures
        group.bench_function(format!("{num_validators} signature aggregation"), |b| {
            b.iter(|| black_box(SignatureProjective::aggregate(&signature_refs)));
        });

        #[cfg(feature = "parallel")]
        group.bench_function(
            format!("{num_validators} parallel signature aggregation"),
            |b| {
                b.iter(|| black_box(SignatureProjective::par_aggregate(&signature_refs)));
            },
        );

        // Benchmark for aggregating multiple public keys
        group.bench_function(format!("{num_validators} pubkey aggregation"), |b| {
            b.iter(|| black_box(PubkeyProjective::aggregate(&pubkey_refs)));
        });

        // Benchmark for aggregate verify
        #[cfg(feature = "parallel")]
        group.bench_function(
            format!("{num_validators} parallel pubkey aggregation"),
            |b| {
                b.iter(|| black_box(PubkeyProjective::par_aggregate(&pubkey_refs)));
            },
        );

        group.bench_function(
            format!("{num_validators} sequential aggregate verification"),
            |b| {
                b.iter(|| {
                    let verification_result = black_box(
                        SignatureProjective::aggregate_verify(
                            &pubkey_refs,
                            &signature_refs,
                            message,
                        )
                        .unwrap(),
                    );
                    assert!(verification_result);
                });
            },
        );

        #[cfg(feature = "parallel")]
        group.bench_function(
            format!("{num_validators} parallel aggregate verification"),
            |b| {
                b.iter(|| {
                    let verification_result = black_box(
                        SignatureProjective::par_aggregate_verify(
                            &pubkey_refs,
                            &signature_refs,
                            message,
                        )
                        .unwrap(),
                    );
                    assert!(verification_result);
                });
            },
        );
    }
    group.finish();
}

// Benchmark for generating a new keypair
fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("key_generation", |b| b.iter(|| black_box(Keypair::new)));
}

// Benchmark for creating and verifying a proof of possession
fn bench_proof_of_possession(c: &mut Criterion) {
    let keypair = Keypair::new();
    let pop = keypair.proof_of_possession();

    c.bench_function("proof_of_possession_creation", |b| {
        b.iter(|| black_box(keypair.proof_of_possession()));
    });

    c.bench_function("proof_of_possession_verification", |b| {
        b.iter(|| {
            black_box(keypair.public.verify_proof_of_possession(&pop)).unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_single_signature,
    bench_aggregate,
    bench_key_generation,
    bench_proof_of_possession
);
criterion_main!(benches);
