#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(unused_imports)]

use ark_ff::Field;
use ark_ec::PairingEngine;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_poly_commit::reveal as pc_reveal;
use blake2::Blake2s;
use mpc_algebra::*;
use Marlin;

use super::*;
use crate::ahp::prover::*;
use ark_poly::EvaluationDomain;
use ark_std::{end_timer, start_timer};

impl<F: PrimeField, S: FieldShare<F>> ShareConversion for ProverMsg<MpcField<F, S>> {
    type Traget = ProverMsg<AdditiveFieldShare<F>>;

    fn share_conversion(self) -> Self::Target {
        match self {
            ProverMsg::EmptyMessage => ProverMsg::EmptyMessage,
            ProverMsg::FieldElements(d) => ProverMsg::FieldElements(d.share_conversion()),
        }
    }
}


impl<E: PairingEngine, S: PairingShare<E>> ShareConversion
    for Proof<
        <MpcPairingEngine<E, S> as PairingEngine>::Fr,
        MarlinKZG10<
            MpcPairingEngine<E, S>,
            DensePolynomial<<MpcPairingEngine<E, S> as PairingEngine>::Fr>,
        >,
    >
{
    type Target =
        Proof<<MpcPairingEngine<E, AdditiveFieldShare> as PairingEngine>::Fr, MarlinKZG10<E, DensePolynomial<<MpcPairingEngine<E, AdditiveFieldShare> as PairingEngine>::Fr>>>;
    struct_share_conversion_simp_impl!(Proof; commitments, evaluations, prover_messages, pc_proof);
}

impl<F: PrimeField, S: FieldShare<F>> ShareConversion for ahp::indexer::IndexInfo<MpcField<F, S>> {
    type Target = ahp::indexer::IndexInfo<AdditiveFieldShare<F>>;
    struct_share_conversion_simp_impl!(ahp::indexer::IndexInfo;
        num_variables,
        num_constraints,
        num_non_zero,
        num_instance_variables,
        f
    );
}

impl<E: PairingEngine, S: PairingShare<E>> ShareConversion
    for IndexVerifierKey<
        <MpcPairingEngine<E, S> as PairingEngine>::Fr,
        MarlinKZG10<
            MpcPairingEngine<E, S>,
            DensePolynomial<<MpcPairingEngine<E, S> as PairingEngine>::Fr>,
        >,
    >
{
    type Target = IndexVerifierKey<
    <MpcPairingEngine<E, AdditiveFieldShare> as PairingEngine>::Fr,
        MarlinKZG10<E, DensePolynomial<<MpcPairingEngine<E, AdditiveFieldShare> as PairingEngine>::Fr>>,
    >;
    struct_share_conversion_simp_impl!(IndexVerifierKey; index_comms, verifier_key, index_info);
}

impl<E: PrimeField, S: FieldShare<E>> ShareConversion for ahp::indexer::Index<MpcField<E, S>> {
    type Target = ahp::indexer::Index<<MpcPairingEngine<E, AdditiveFieldShare> as PairingEngine>>;
    struct_share_conversion_simp_impl!(ahp::indexer::Index; index_info, a, b, c, a_star_arith, b_star_arith, c_star_arith);
}

impl<E: PrimeField, S: FieldShare<E>> ShareConversion
    for ahp::constraint_systems::MatrixEvals<MpcField<E, S>>
{
    type Target = ahp::constraint_systems::MatrixEvals<<MpcPairingEngine<E, AdditiveFieldShare> as PairingEngine>>;
    struct_share_conversion_simp_impl!(ahp::constraint_systems::MatrixEvals; row, col, val);
}
impl<E: PrimeField, S: FieldShare<E>> ShareConversion
    for ahp::constraint_systems::MatrixArithmetization<MpcField<E, S>>
{
    type Target = ahp::constraint_systems::MatrixArithmetization<<MpcPairingEngine<E, AdditiveFieldShare> as PairingEngine>>;
    struct_share_conversion_simp_impl!(ahp::constraint_systems::MatrixArithmetization; row, col, val, row_col, evals_on_K, evals_on_B, row_col_evals_on_B);
}
impl<E: PairingEngine, S: PairingShare<E>> ShareConversion
    for IndexProverKey<
        <MpcPairingEngine<E, S> as PairingEngine>::Fr,
        MarlinKZG10<
            MpcPairingEngine<E, S>,
            DensePolynomial<<MpcPairingEngine<E, S> as PairingEngine>::Fr>,
        >,
    >
{
    type Target = IndexProverKey<
    <MpcPairingEngine<E, AdditiveFieldShare> as PairingEngine>:Fr,
        MarlinKZG10<E, DensePolynomial<<MpcPairingEngine<E, AdditiveFieldShare> as PairingEngine>::Fr>>,
    >;
    struct_share_conversion_simp_impl!(IndexProverKey; index_vk, index_comm_rands, index, committer_key);
}
