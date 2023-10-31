use ark_ec::{group::Group, AffineCurve, PairingEngine};
use ark_ff::{Field, PrimeField, UniformRand};
use log::{debug, info};
use mpc_algebra::rss3::RSS3GroupShare;
use mpc_algebra::{
    msm::NaiveMsm, share::field::FieldShare, share::group::GroupShare, share::rss3::*,
    share::pairing::PairingShare, Reveal,
};
use mpc_net::{MpcNet, MpcMultiNet as Net};
use mpc_algebra::share::PanicBeaverSource;

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "unit_test_rss3", about = "Unit Tests of RSS3")]
struct Opt {
    /// Id
    id: usize,

    /// Input file
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

const N: usize = 2;

fn test_sum_field<F: Field>() {
    let rng = &mut ark_std::test_rng();

    for _i in 0..N {
        let a_pub = F::rand(rng);
        let b_pub = F::rand(rng);
        let c_should_be = a_pub + b_pub;

        let mut a_ss = RSS3FieldShare::from_public(a_pub);
        let b_ss = RSS3FieldShare::from_public(b_pub);
        let c_ss = a_ss.add(&b_ss);
        let c_res = c_ss.reveal();
       
        assert_eq!(c_should_be, c_res);
    }
}

fn test_mul_field<F: Field>() {
    let rng = &mut ark_std::test_rng();

    for _i in 0..N {
        let a_pub = F::rand(rng);
        let b_pub = F::rand(rng);
        let c_should_be = a_pub * b_pub;

        let mut a_ss = RSS3FieldShare::from_public(a_pub);
        let b_ss = RSS3FieldShare::from_public(b_pub);
        let c_ss = a_ss.mul(b_ss, &mut PanicBeaverSource::default());
        let c_res = c_ss.reveal();
       
        assert_eq!(c_should_be, c_res);
    }
}

fn test_ip_field<F: Field>() {
    let rng = &mut ark_std::test_rng();

    let iters = 4;
    let size = 100;
    for _iter in 0..iters {
        let a_pubs: Vec<F> = (0..size).map(|_| F::rand(rng)).collect();
        let b_pubs: Vec<F> = (0..size).map(|_| F::rand(rng)).collect();
        let ip_should_be = a_pubs
            .iter()
            .zip(&b_pubs)
            .fold(F::zero(), |x, (a, b)| x + *a * b);

        let as_ss: Vec<_> = a_pubs
            .iter()
            .map(|a| RSS3FieldShare::from_public(*a))
            .collect();
        let bs_ss: Vec<_> = b_pubs
            .iter()
            .map(|b| RSS3FieldShare::from_public(*b))
            .collect();
        let ip_res_ss = as_ss
            .iter()
            .zip(bs_ss)
            .fold(RSS3FieldShare::from_public(F::zero()), |mut x, (a, b)| *x.add(&a.mul(b, &mut PanicBeaverSource::default())));
        let ip_res = ip_res_ss.reveal();
        assert_eq!(ip_res, ip_should_be);
    }
}

fn test_sum_group<G: Group>() {
    let rng = &mut ark_std::test_rng();

    for _i in 0..N {
        let A_pub = G::rand(rng);
        let B_pub = G::rand(rng);
        let C_should_be = A_pub + B_pub;

        let mut A_ss: RSS3GroupShare<G, NaiveMsm<G>> = RSS3GroupShare::from_public(A_pub);
        let B_ss: RSS3GroupShare<G, NaiveMsm<G>> = RSS3GroupShare::from_public(B_pub);
        let C_ss = A_ss.add(&B_ss);
        let C_res = C_ss.reveal();
       
        assert_eq!(C_should_be, C_res);
    }
}

fn test_mul_group<G: Group>() {
    let rng = &mut ark_std::test_rng();

    for _i in 0..N {
        let a_pub = G::ScalarField::rand(rng);
        let mut B_pub = G::rand(rng);
        let mut B_pub0 = B_pub;
        B_pub *= a_pub;
        let C_should_be = B_pub;

        let a_ss = RSS3FieldShare::<G::ScalarField>::from_public(a_pub);
        let mut B_ss: RSS3GroupShare<G, NaiveMsm<G>> = RSS3GroupShare::from_public(B_pub0);
        let C_ss = B_ss.scale(a_ss, &mut PanicBeaverSource::default());
        let C_res = C_ss.reveal();
       
        assert_eq!(C_should_be, C_res);
    }
}

fn test_mul_mulfield<E: PairingEngine>() {
    let rng = &mut ark_std::test_rng();

    let g = E::pairing(
        E::G1Affine::prime_subgroup_generator(),
        E::G2Affine::prime_subgroup_generator(),
    );

    for _i in 0..N {
        let a_exp_pub = E::Fr::rand(rng);
        let b_exp_pub = E::Fr::rand(rng);
        let a_pub = g.pow(a_exp_pub.into_repr());
        let b_pub = g.pow(b_exp_pub.into_repr());
        let c_should_be = a_pub * b_pub;

        let mut a_ss = MulFieldShare::<E::Fqk>::from_public(a_pub);
        let b_ss = MulFieldShare::<E::Fqk>::from_public(b_pub);
        let c_ss = a_ss.mul(b_ss, &mut PanicBeaverSource::default());
        let c_res = c_ss.reveal();
        
        assert_eq!(c_res, c_should_be);
    }
}


fn test_pairing<E: PairingEngine, S: PairingShare<E>>() {
    use mpc_algebra::wire::group::DummyGroupTripleSource;
    let gp1_src = &mut DummyGroupTripleSource::default();
    let gp2_src = &mut DummyGroupTripleSource::default();
    let rng = &mut ark_std::test_rng();
    let g1 = E::G1Affine::prime_subgroup_generator();
    let g2 = E::G2Affine::prime_subgroup_generator();

    for _i in 0..N {
        let a_pub = E::Fr::rand(rng);
        let b_pub = E::Fr::rand(rng);
        let g1ab_should_be = Group::mul(&Group::mul(&g1, &a_pub), &b_pub);
        let g2ab_should_be = Group::mul(&Group::mul(&g2, &a_pub), &b_pub);
        let g1a_plus_b_should_be = Group::mul(&g1, &(a_pub + b_pub));
        let g2a_plus_b_should_be = Group::mul(&g2, &(a_pub + b_pub));

        let a_ss = S::FrShare::from_public(a_pub);
        let b_ss = S::FrShare::from_public(b_pub);
        let g1a_ss = <S::G1AffineShare as GroupShare<E::G1Affine>>::scale_pub_group(g1, &a_ss);
        let g2b_ss = <S::G2AffineShare as GroupShare<E::G2Affine>>::scale_pub_group(g2, &b_ss);
        let g1ab_ss = <S::G1AffineShare as GroupShare<E::G1Affine>>::scale(g1a_ss, b_ss, gp1_src);
        let g2ab_ss = <S::G2AffineShare as GroupShare<E::G2Affine>>::scale(g2b_ss, a_ss, gp2_src);
        let g1ab_res = g1ab_ss.reveal();
        let g2ab_res = g2ab_ss.reveal();

        assert_eq!(g1ab_res, g1ab_should_be);
        assert_eq!(g2ab_res, g2ab_should_be);

        let g1a_plus_b_res = <S::G1AffineShare as GroupShare<E::G1Affine>>::multi_scale_pub_group(
            &[g1, g1],
            &[a_ss, b_ss],
        )
        .reveal();
        assert_eq!(g1a_plus_b_res, g1a_plus_b_should_be);

        let g2a_plus_b_res = <S::G2AffineShare as GroupShare<E::G2Affine>>::multi_scale_pub_group(
            &[g2, g2],
            &[a_ss, b_ss],
        )
        .reveal();
        assert_eq!(g2a_plus_b_res, g2a_plus_b_should_be);
    }
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    debug!("Start");
    let opt = Opt::from_args();
    println!("{:?}", opt);
    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    test_sum_field::<ark_bls12_377::Fr>();
    test_mul_field::<ark_bls12_377::Fr>();
    test_ip_field::<ark_bls12_377::Fr>();

    test_sum_group::<ark_bls12_377::G1Affine>();
    test_mul_group::<ark_bls12_377::G1Affine>();
    test_sum_group::<ark_bls12_377::G1Projective>();
    test_mul_group::<ark_bls12_377::G1Projective>();
    test_sum_group::<ark_bls12_377::G2Affine>();
    test_mul_group::<ark_bls12_377::G2Affine>();
    test_sum_group::<ark_bls12_377::G2Projective>();
    test_mul_group::<ark_bls12_377::G2Projective>();

    test_mul_mulfield::<ark_bls12_377::Bls12_377>();

    test_pairing::<ark_bls12_377::Bls12_377, RSS3PairingShare<ark_bls12_377::Bls12_377>>();

    debug!("Done");
    Net::deinit();
}