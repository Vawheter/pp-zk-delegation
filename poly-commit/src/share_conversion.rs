#![allow(missing_docs)]
use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use mpc_algebra::*;

use crate::{kzg10, marlin_pc, BatchLCProof, LabeledCommitment, LabeledPolynomial, PCCommitment};
use marlin_pc::*;

impl<E: PairingEngine> ShareConversion for Commitment<MpcPairingEngine<E, RSS3PairingShare<E>>> {
    type Target = Commitment<MpcPairingEngine<E, AdditivePairingShare<E>>>;
    struct_share_conversion_simp_impl!(Commitment; comm, shifted_comm);
}

impl<E: PrimeField> ShareConversion
    for kzg10::Randomness<MpcField<E, RSS3FieldShare<E>>, DensePolynomial<MpcField<E, RSS3FieldShare<E>>>>
{
    type Target = kzg10::Randomness<MpcField<E, AdditiveFieldShare<E>>, DensePolynomial<MpcField<E, AdditiveFieldShare<E>>>>;

    struct_share_conversion_simp_impl!(kzg10::Randomness; blinding_polynomial, _field);
}

impl<E: PrimeField> ShareConversion
    for Randomness<MpcField<E, RSS3FieldShare<E>>, DensePolynomial<MpcField<E, RSS3FieldShare<E>>>>
{
    type Target = Randomness<MpcField<E, AdditiveFieldShare<E>>, DensePolynomial<MpcField<E, AdditiveFieldShare<E>>>>;
    struct_share_conversion_simp_impl!(Randomness; rand, shifted_rand);
}

impl<E: PairingEngine> ShareConversion for kzg10::Commitment<MpcPairingEngine<E, RSS3PairingShare<E>>> {
    type Target = kzg10::Commitment<MpcPairingEngine<E, AdditivePairingShare<E>>>;

    fn share_conversion(self) -> Self::Target {
        kzg10::Commitment(self.0.share_conversion())
    }
}

impl<E: PairingEngine> ShareConversion for kzg10::Proof<MpcPairingEngine<E, RSS3PairingShare<E>>> {
    type Target = kzg10::Proof<MpcPairingEngine<E, AdditivePairingShare<E>>>;
    struct_share_conversion_simp_impl!(kzg10::Proof; w, random_v);
}
impl<E: PairingEngine> ShareConversion
    for kzg10::UniversalParams<MpcPairingEngine<E, RSS3PairingShare<E>>>
{
    type Target = kzg10::UniversalParams<MpcPairingEngine<E, AdditivePairingShare<E>>>;
    struct_share_conversion_simp_impl!(kzg10::UniversalParams;
    powers_of_g,
    powers_of_gamma_g,
    h,
    beta_h,
    neg_powers_of_h,
    prepared_h,
    prepared_beta_h);
}

impl<E: PairingEngine> ShareConversion for kzg10::VerifierKey<MpcPairingEngine<E, RSS3PairingShare<E>>> {
    type Target = kzg10::VerifierKey<MpcPairingEngine<E, AdditivePairingShare<E>>>;
    struct_share_conversion_simp_impl!(kzg10::VerifierKey;
    g,
    gamma_g,
    h,
    beta_h,
    prepared_h,
    prepared_beta_h
    );
}
impl<E: PairingEngine> ShareConversion for VerifierKey<MpcPairingEngine<E, RSS3PairingShare<E>>> {
    type Target = VerifierKey<MpcPairingEngine<E, AdditivePairingShare<E>>>;
    struct_share_conversion_simp_impl!(VerifierKey;
         vk,
         degree_bounds_and_shift_powers,
         max_degree,
         supported_degree);
}
impl<E: PairingEngine> ShareConversion
    for BatchLCProof<
        <MpcPairingEngine<E, RSS3PairingShare<E>> as PairingEngine>::Fr,
        DensePolynomial<<MpcPairingEngine<E, RSS3PairingShare<E>> as PairingEngine>::Fr>,
        MarlinKZG10<
            MpcPairingEngine<E, RSS3PairingShare<E>>,
            DensePolynomial<<MpcPairingEngine<E, RSS3PairingShare<E>> as PairingEngine>::Fr>,
        >,
    >
{
    type Target = BatchLCProof<
        <MpcPairingEngine<E, AdditivePairingShare<E>> as PairingEngine>::Fr,
        DensePolynomial<<MpcPairingEngine<E, AdditivePairingShare<E>> as PairingEngine>::Fr>,
        MarlinKZG10<MpcPairingEngine<E, AdditivePairingShare<E>>, DensePolynomial<<MpcPairingEngine<E, AdditivePairingShare<E>> as PairingEngine>::Fr>>,
    >;
    struct_share_conversion_simp_impl!(BatchLCProof; proof, evals);
}

impl<E: PairingEngine> ShareConversion for CommitterKey<MpcPairingEngine<E, RSS3PairingShare<E>>> {
    type Target = CommitterKey<MpcPairingEngine<E, AdditivePairingShare<E>>>;
    struct_share_conversion_simp_impl!(CommitterKey; powers, shifted_powers, powers_of_gamma_g, enforced_degree_bounds, max_degree);
}

impl<C: PCCommitment + ShareConversion> ShareConversion for LabeledCommitment<C>
where
    C::Target: PCCommitment,
{
    type Target = LabeledCommitment<C::Target>;

    fn share_conversion(self) -> Self::Target {
        LabeledCommitment::new(
            self.label().clone(),
            self.commitment.clone().share_conversion(),
            self.degree_bound(),
        )
    }
}

impl<F: PrimeField> ShareConversion
    for LabeledPolynomial<MpcField<F, RSS3FieldShare<F>>, DensePolynomial<MpcField<F, RSS3FieldShare<F>>>>
{
    type Target = LabeledPolynomial<MpcField<F, AdditiveFieldShare<F>>, DensePolynomial<MpcField<F, AdditiveFieldShare<F>>>>;
    fn share_conversion(self) -> Self::Target {
        LabeledPolynomial::new(
            self.label().clone(),
            self.polynomial().clone().share_conversion(),
            self.degree_bound(),
            self.hiding_bound(),
        )
    }
}