#![macro_use]
use derivative::Derivative;
use rand::Rng;

use ark_ec::group::Group;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::prelude::*;
use ark_poly::UVPolynomial;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};

use std::borrow::Cow;
use std::cmp::Ord;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::io::{self, Read, Write};
use std::marker::PhantomData;

use mpc_net::{MpcNet, MpcMultiNet as Net};
use crate::channel::MpcSerNet;

use super::field::{
    DenseOrSparsePolynomial, DensePolynomial, ExtFieldShare, FieldShare, SparsePolynomial,
};
use super::group::GroupShare;
use super::pairing::{AffProjShare, PairingShare};
use super::BeaverSource;
use crate::msm::*;
use crate::Reveal;

use log::debug;
use crate::wire::DummyFieldTripleSource;

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RSS3FieldShare<T> {
    pub val0: T,
    pub val1: T,
}

impl<F: Field> RSS3FieldShare<F> {
    fn default() -> Self {
        Self { val0: F::zero(), val1: F::zero(), }
    }
    
    fn poly_share<'a>(
        p: DenseOrSparsePolynomial<Self>,
    ) -> Vec<ark_poly::univariate::DenseOrSparsePolynomial<'a, F>> {
        match p {
            Ok(p) => Self::d_poly_share(p).into_iter().map(|poly| 
                    ark_poly::univariate::DenseOrSparsePolynomial::DPolynomial(Cow::Owned(poly))
                ).collect(),
            Err(p) => Self::s_poly_share(p).into_iter().map(|poly| 
                    ark_poly::univariate::DenseOrSparsePolynomial::SPolynomial(Cow::Owned(poly))
            ).collect(),
        }
    }

    fn d_poly_share(p: DensePolynomial<Self>) -> Vec<ark_poly::univariate::DensePolynomial<F>> {
        let vec0: Vec<F> = p.clone().into_iter().map(|s| s.val0).collect();
        let vec1: Vec<F> = p.clone().into_iter().map(|s| s.val1).collect();
        debug!("vec0: {:?}", vec0);
        debug!("vec1: {:?}", vec1);
        vec![ark_poly::univariate::DensePolynomial::from_coefficients_vec(
            p.clone().into_iter().map(|s| s.val0).collect(),
        ), ark_poly::univariate::DensePolynomial::from_coefficients_vec(
            p.into_iter().map(|s| s.val1).collect(),
        )]
    }

    fn s_poly_share(p: SparsePolynomial<Self>) -> Vec<ark_poly::univariate::SparsePolynomial<F>> {
        vec![ark_poly::univariate::SparsePolynomial::from_coefficients_vec(
            p.clone().into_iter().map(|(i, s)| (i, s.val0)).collect(),
        ), ark_poly::univariate::SparsePolynomial::from_coefficients_vec(
            p.into_iter().map(|(i, s)| (i, s.val1)).collect(),
        )]
    }

    fn poly_share2<'a>(
        p: DenseOrSparsePolynomial<F>,
    ) -> ark_poly::univariate::DenseOrSparsePolynomial<'a, F> {
        match p {
            Ok(p) => ark_poly::univariate::DenseOrSparsePolynomial::DPolynomial(Cow::Owned(
                ark_poly::univariate::DensePolynomial::from_coefficients_vec(p),
            )),
            Err(p) => ark_poly::univariate::DenseOrSparsePolynomial::SPolynomial(Cow::Owned(
                ark_poly::univariate::SparsePolynomial::from_coefficients_vec(p),
            )),
        }
    }

    fn d_poly_unshare(p: Vec<ark_poly::univariate::DensePolynomial<F>>) -> DensePolynomial<Self> {
        // debug!("p[0].coeffs: {:?}", p[0].coeffs.clone());
        // debug!("p[0].coeffs.len: {:?}", p[0].coeffs.clone().len());
        // debug!("p[1].coeffs: {:?}", p[1].coeffs.clone());
        // debug!("p[1].coeffs.len: {:?}", p[1].coeffs.clone().len());
       
        let len = if p[0].coeffs.len() > p[1].coeffs.len() { p[0].coeffs.len() } else { p[1].coeffs.len() };

        
        let mut p0_coeffs = vec![F::zero(); len];
        let mut p1_coeffs = vec![F::zero(); len];
        
        if !p[0].is_zero() { p0_coeffs = p[0].coeffs.clone() };
        if !p[1].is_zero() { p1_coeffs = p[1].coeffs.clone() };
        // let p1_coeffs = if p[1].is_zero() { vec![F::zero; len] } else { p[1].coeffs.clone() };

        (0..len).into_iter().map(|i| {
            Self {
                val0: p0_coeffs[i],
                val1: p1_coeffs[i],
            }
        }).collect() 
    }
}

impl<F: Field> Reveal for RSS3FieldShare<F> {
    type Base = F;

    /// Reveal shared data, yielding plain data.
    fn reveal(self) -> F {
        let shares_vec: Vec<Vec<F>> = Net::broadcast(&vec![self.val0, self.val1]);
        let mut res0 = F::zero();
        let mut res1 = F::zero();
        for party_id in 0..3 {
            res0 += shares_vec[party_id][0];
            res1 += shares_vec[party_id][1];
        }
        // debug!("res0: {}, res1: {}", res0, res1);

        assert_eq!(res0, res1);
        res0
    }

    /// Construct a share of the sum of the `b` over all machines in the protocol.
    fn from_add_shared(f: Self::Base) -> Self {
        // unimplemented!()
        match Net::party_id() {
            0 => Self { val0: F::zero(), val1: F::zero() },
            1 => Self { val0: F::one(), val1: F::zero() },
            2 => Self { val0: F::zero(), val1: F::one() },
            _ => Self::default(),
        }
    }

    /// Lift public data (same in all machines) into shared data.
    fn from_public(f: F) -> Self {
        match Net::party_id() {
            0 => Self { val0: f, val1: F::zero() },
            1 => Self { val0: F::zero(), val1: f },
            2 => Self { val0: F::zero(), val1: F::zero() },
            _ => Self::default(),
        }
    }

    fn unwrap_as_public(self) -> F {
        unimplemented!()
    }

    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        let my_share = Net::recv_from_king( 
            if Net::am_king() { 
                let r0 = F::rand(rng);
                let r1 = F::rand(rng);
                let r2 = f - r0 - r1;
                let shares = vec![vec![r0, r2],
                                  vec![r1, r0],
                                  vec![r2, r1]];
                Some(shares)
            } else {
                None 
        });
        Self {
            val0: my_share[0],
            val1: my_share[1],
        }
    }

    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        let my_share_batch = Net::recv_from_king(
            if Net::am_king() {
                let mut share_batches0 = vec![];
                let mut share_batches1 = vec![];
                let mut share_batches2 = vec![];
                f.into_iter()
                    .for_each(|x| {
                        let r0 = F::rand(rng);
                        let r1 = F::rand(rng);
                        let r2 = x - r0 - r1;
                        share_batches0.push(vec![r0, r2]);
                        share_batches1.push(vec![r1, r0]);
                        share_batches2.push(vec![r2, r1]);
                    });
                Some(vec![share_batches0, share_batches1, share_batches2])
            } else {
                None
        });
        my_share_batch.into_iter().map(|v| {
            Self {
                val0: v[0],
                val1: v[1],
            }
        }).collect()
    }
}

impl<F: Field> FieldShare<F> for RSS3FieldShare<F> {
    
    fn mul<S: BeaverSource<Self, Self, Self>>(self, other: Self, _source: &mut S) -> Self {
        let z0 = self.val0 * (other.val0 + other.val1) + other.val0 * self.val1;
        let z1 = Net::pass_to_next(&vec![z0])[0];
        Self {
            val0: z0,
            val1: z1,
        }
    }

    fn batch_mul<S: BeaverSource<Self, Self, Self>>(
        xs: Vec<Self>,
        ys: Vec<Self>,
        _source: &mut S,
    ) -> Vec<Self> {
        let z0s: Vec<F> = xs.into_iter()
                            .zip(ys.into_iter())
                            .map(|(x, y)| {
                                x.val0 * (y.val0 + y.val1) + y.val0 * x.val1
                            }).collect();

        let z1s = Net::pass_to_next(&z0s);

        z0s.into_iter()
            .zip(z1s.into_iter())
            .map(|(z0, z1)| {
                Self {
                    val0: z0,
                    val1: z1,
                }
            }).collect()
    }
    
    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> { // Rewrite the function
        let self_vec: Vec<Vec<F>> = selfs.into_iter().map(|s| vec![s.val0, s.val1] ).collect();
        let all_vals = Net::broadcast(&self_vec);
        let len = all_vals[0].len();
        let mut res = vec![F::zero(); len];
        for i in 0..len {
            let mut tmp0 = F::zero();
            let mut tmp1 = F::zero();
            for party_id in 0..3 {
                tmp0 += all_vals[party_id][i][0];
                tmp1 += all_vals[party_id][i][1];
            }
            assert_eq!(tmp0, tmp1);
            res[i] = tmp0;  
        }
        res
    }

    fn add(&mut self, other: &Self) -> &mut Self {
        self.val0 += &other.val0;
        self.val1 += &other.val1;
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.val0 -= &other.val0;
        self.val1 -= &other.val1;
        self
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        self.val0 *= other;
        self.val1 *= other;
        self
    }

    fn shift(&mut self, other: &F) -> &mut Self {
        match Net::party_id() {
            0 => self.val0 += other,
            1 => self.val1 += other,
            _ => (),
        }
        self
    }

    fn univariate_div_qr<'a>(
        num: DenseOrSparsePolynomial<Self>,
        den: DenseOrSparsePolynomial<F>,
    ) -> Option<(DensePolynomial<Self>, DensePolynomial<Self>)> {
        debug!("calling univariate_div_qr");
        debug!("\nnum 0:{:?}", num);
        let num = Self::poly_share(num);
        let den = Self::poly_share2(den);
        debug!("\nnum 1:{:?}", num);

        let mut q_polys: Vec<ark_poly::univariate::DensePolynomial<F>> = vec![];
        let mut r_polys: Vec<ark_poly::univariate::DensePolynomial<F>> = vec![];
        num.into_iter()
            .for_each(|p| {
                let (q, r) = p.divide_with_q_and_r(&den).unwrap();
                q_polys.push(q);
                r_polys.push(r);
            }); 
        debug!("\nq_polys:{:?}", q_polys);
        debug!("\nr_polys:{:?}", r_polys);
        
        debug!("\nSelf::d_poly_unshare(q_polys):{:?}", Self::d_poly_unshare(q_polys.clone()));
        debug!("\nSelf::d_poly_unshare(r_polys):{:?}", Self::d_poly_unshare(r_polys.clone()));

        Some((Self::d_poly_unshare(q_polys), Self::d_poly_unshare(r_polys)))
    }
}


#[derive(Derivative)]
#[derivative(
    Default(bound = "T: Default"),
    Clone(bound = "T: Clone"),
    Copy(bound = "T: Copy"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    PartialOrd(bound = "T: PartialOrd"),
    Ord(bound = "T: Ord"),
    Hash(bound = "T: Hash")
)]
pub struct RSS3GroupShare<T, M> {
    pub val0: T,
    pub val1: T,
    _phants: PhantomData<M>,
}

impl<G: Group, M> RSS3GroupShare<G, M> {
    fn default() -> Self {
        Self { val0: G::zero(), val1: G::zero(), _phants: PhantomData::default() }
    }
}

impl<G: Group, M> Reveal for RSS3GroupShare<G, M> {
    type Base = G;

    fn reveal(self) -> G {
        let shares_vec: Vec<Vec<G>> = Net::broadcast(&vec![self.val0, self.val1]);
        let mut res0 = G::zero();
        let mut res1 = G::zero();
        for party_id in 0..3 {
            // debug!("\nparty_id: {}", party_id);
            // debug!("\nval0: {},\nval1: {}\n", shares_vec[party_id][0], shares_vec[party_id][1]);
            res0 += shares_vec[party_id][0];
            res1 += shares_vec[party_id][1];
        }
        // debug!("res0: {}\nres1: {}\n", res0, res1);

        assert_eq!(res0, res1);
        res0
    }

    fn from_public(f: G) -> Self {
        match Net::party_id() {
            0 => Self { val0: f, val1: G::zero(), _phants: PhantomData::default() },
            1 => Self { val0: G::zero(), val1: f, _phants: PhantomData::default() },
            2 => Self { val0: G::zero(), val1: G::zero(), _phants: PhantomData::default() },
            _ => Self::default(),
        }
    }

    fn from_add_shared(f: Self::Base) -> Self {
        unimplemented!()
    }

    fn unwrap_as_public_vec(self) -> Vec<G> {
        vec![self.val0, self.val1]
    }

    fn from_add_shared_vec(vals: Vec<G>) -> Self {
        Self {
            val0: vals[0],
            val1: vals[1],
            _phants: PhantomData::default(),
        }
    }

    fn unwrap_as_public(self) -> G {
        unimplemented!()
    }

    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        let my_share = Net::recv_from_king( 
            if Net::am_king() { 
                let r0 = G::rand(rng);
                let r1 = G::rand(rng);
                let r2 = f - r0 - r1;
                let shares = vec![vec![r0, r2],
                                  vec![r1, r0],
                                  vec![r2, r1]];
                Some(shares)
            } else {
                None 
        });
        Self {
            val0: my_share[0],
            val1: my_share[1],
            _phants: PhantomData::default(),
        }
    }

    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        let my_share_batch = Net::recv_from_king(
            if Net::am_king() {
                let mut share_batches0 = vec![];
                let mut share_batches1 = vec![];
                let mut share_batches2 = vec![];
                f.into_iter()
                    .for_each(|x| {
                        let r0 = G::rand(rng);
                        let r1 = G::rand(rng);
                        let r2 = x - r0 - r1;
                        share_batches0.push(vec![r0, r2]);
                        share_batches1.push(vec![r1, r0]);
                        share_batches2.push(vec![r2, r1]);
                    });
                Some(vec![share_batches0, share_batches1, share_batches2])
            } else {
                None
        });
        my_share_batch.into_iter().map(|v| {
            Self {
                val0: v[0],
                val1: v[1],
                _phants: PhantomData::default(),
            }
        }).collect()
    }
}

impl<G: Group, M: Msm<G, G::ScalarField>> GroupShare<G> for RSS3GroupShare<G, M> {
    type FieldShare = RSS3FieldShare<G::ScalarField>;
    
    fn map_homo<G2: Group, S2: GroupShare<G2>, Fun: Fn(G) -> G2>(self, f: Fun) -> S2 {
        let vals = self.unwrap_as_public_vec()
                        .into_iter()
                        .map(|x| f(x) )
                        .collect();
        S2::from_add_shared_vec(vals)
    }

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<G> {
        let self_vec: Vec<Vec<G>> = selfs.into_iter().map(|s| vec![s.val0, s.val1] ).collect();
        let all_vals = Net::broadcast(&self_vec);
        let len = all_vals[0].len();
        let mut res = vec![G::zero(); len];
        for i in 0..len {
            let mut tmp0 = G::zero();
            let mut tmp1 = G::zero();
            for party_id in 0..3 {
                tmp0 += all_vals[party_id][i][0];
                tmp1 += all_vals[party_id][i][1];
            }
            assert_eq!(tmp0, tmp1);
            res[i] = tmp0;  
        }
        res
    }

    fn add(&mut self, other: &Self) -> &mut Self {
        self.val0 += &other.val0;
        self.val1 += &other.val1;
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.val0 -= &other.val0;
        self.val1 -= &other.val1;
        self
    }

    fn scale_pub_scalar(&mut self, scalar: &G::ScalarField) -> &mut Self {
        self.val0 *= *scalar;
        self.val1 *= *scalar;
        self
    }

    fn scale_pub_group(mut base: G, scalar: &Self::FieldShare) -> Self {
        let mut tmp = base;
        tmp *= scalar.val1;
        base *= scalar.val0;
        Self {
            val0: base,
            val1: tmp,
            _phants: PhantomData::default(),
        }
    }

    fn shift(&mut self, other: &G) -> &mut Self {
        match Net::party_id() {
            0 => self.val0 += other,
            1 => self.val1 += other,
            _ => (),
        }
        self
    }

    fn scale<S: BeaverSource<Self, Self::FieldShare, Self>>(
        self,
        other: Self::FieldShare,
        _source: &mut S,
    ) -> Self {
        let mut tmp0 = self.val0;
        tmp0 *= other.val0 + other.val1;
        let mut tmp1 = self.val1;
        tmp1 *= other.val0;
        let z0 = tmp0 + tmp1;
        let z1 = Net::pass_to_next(&vec![z0])[0];
        Self {
            val0: z0,
            val1: z1,
            _phants: PhantomData::default(),
        }
    }

    fn multi_scale_pub_group(bases: &[G], scalars: &[Self::FieldShare]) -> Self {
        let scalars0: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.val0.clone()).collect();
        let scalars1: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.val1.clone()).collect();
        Self {
            val0: M::msm(bases, &scalars0),
            val1: M::msm(bases, &scalars1),
            _phants: PhantomData::default(),
        }
    }
}

macro_rules! impl_basics {
    ($share:ident, $bound:ident) => {
        impl<T: $bound> Display for $share<T> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{},{}", self.val0, self.val1)
            }
        }
        impl<T: $bound> Debug for $share<T> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}, {:?}", self.val0, self.val1)
            }
        }
        impl<T: $bound> ToBytes for $share<T> {
            fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                unimplemented!("write")
            }
        }
        impl<T: $bound> FromBytes for $share<T> {
            fn read<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<T: $bound> CanonicalSerialize for $share<T> {
            fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
                unimplemented!("serialize")
            }
            fn serialized_size(&self) -> usize {
                unimplemented!("serialized_size")
            }
        }
        impl<T: $bound> CanonicalSerializeWithFlags for $share<T> {
            fn serialize_with_flags<W: Write, F: Flags>(
                &self,
                _writer: W,
                _flags: F,
            ) -> Result<(), SerializationError> {
                unimplemented!("serialize_with_flags")
            }

            fn serialized_size_with_flags<F: Flags>(&self) -> usize {
                unimplemented!("serialized_size_with_flags")
            }
        }
        impl<T: $bound> CanonicalDeserialize for $share<T> {
            fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
                unimplemented!("deserialize")
            }
        }
        impl<T: $bound> CanonicalDeserializeWithFlags for $share<T> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<T: $bound> UniformRand for $share<T> {
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self { 
                // debug!("calling rand");           
                // Self {
                //     val0: <T as UniformRand>::rand(rng),
                //     val1: <T as UniformRand>::rand(rng),
                // }
                let r0 = <T as UniformRand>::rand(rng);
                let r1 = <T as UniformRand>::rand(rng);
                let r2 = <T as UniformRand>::rand(rng);
                match Net::party_id() {
                    0 => Self { val0: r0, val1: r2 },
                    1 => Self { val0: r1, val1: r0 },
                    2 => Self { val0: r2, val1: r1 },
                    _ => Self::default(),
                }
            }
        }
    };
}
macro_rules! impl_basics_2_param {
    ($share:ident, $bound:ident) => {
        impl<T: $bound, M> Display for $share<T, M> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}, {}", self.val0, self.val1)
            }
        }
        impl<T: $bound, M> Debug for $share<T, M> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}, {:?}", self.val0, self.val1)
            }
        }
        impl<T: $bound, M> ToBytes for $share<T, M> {
            fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                unimplemented!("write")
            }
        }
        impl<T: $bound, M> FromBytes for $share<T, M> {
            fn read<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<T: $bound, M> CanonicalSerialize for $share<T, M> {
            fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
                unimplemented!("serialize")
            }
            fn serialized_size(&self) -> usize {
                unimplemented!("serialized_size")
            }
        }
        impl<T: $bound, M> CanonicalSerializeWithFlags for $share<T, M> {
            fn serialize_with_flags<W: Write, F: Flags>(
                &self,
                _writer: W,
                _flags: F,
            ) -> Result<(), SerializationError> {
                unimplemented!("serialize_with_flags")
            }

            fn serialized_size_with_flags<F: Flags>(&self) -> usize {
                unimplemented!("serialized_size_with_flags")
            }
        }
        impl<T: $bound, M> CanonicalDeserialize for $share<T, M> {
            fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
                unimplemented!("deserialize")
            }
        }
        impl<T: $bound, M> CanonicalDeserializeWithFlags for $share<T, M> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<T: $bound, M> UniformRand for $share<T, M> {
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                // Self {
                //     val0: <T as UniformRand>::rand(rng),
                //     val1: <T as UniformRand>::rand(rng),
                //     _phants: PhantomData::default(),
                // }
                // }
                let r0 = <T as UniformRand>::rand(rng);
                let r1 = <T as UniformRand>::rand(rng);
                let r2 = <T as UniformRand>::rand(rng);
                match Net::party_id() {
                    0 => Self { val0: r0, val1: r2, _phants: PhantomData::default(), },
                    1 => Self { val0: r1, val1: r0, _phants: PhantomData::default(), },
                    2 => Self { val0: r2, val1: r1, _phants: PhantomData::default(), },
                    _ => Self::default(),
                }
            }
        }
    };
}

impl_basics!(RSS3FieldShare, Field);
impl_basics_2_param!(RSS3GroupShare, Group);

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "F: PartialEq"),
    Eq(bound = "F: Eq"),
    Hash(bound = "F: Hash")
)]
pub struct RSS3ExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for RSS3ExtFieldShare<F> {
    type Ext = RSS3FieldShare<F>;
    type Base = RSS3FieldShare<F::BasePrimeField>;
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MulFieldShare<T> {
    pub val0: T,
    pub val1: T,
}

impl<F: Field> MulFieldShare<F> {
    fn default() -> Self {
        Self { val0: F::one(), val1: F::one(), }
    }
}

impl<F: Field> Reveal for MulFieldShare<F> {
    type Base = F;

    fn reveal(self) -> F {
        let shares_vec: Vec<Vec<F>> = Net::broadcast(&vec![self.val0, self.val1]);
        let mut res0 = F::one();
        let mut res1 = F::one();
        for party_id in 0..3 {
            res0 *= shares_vec[party_id][0];
            res1 *= shares_vec[party_id][1];
        }
        assert_eq!(res0, res1);
        res0
    }

    fn from_add_shared(f: Self::Base) -> Self {
        unimplemented!()
    }

    fn from_public(f: F) -> Self {
        match Net::party_id() {
            0 => Self { val0: f, val1: F::one() },
            1 => Self { val0: F::one(), val1: f },
            2 => Self { val0: F::one(), val1: F::one() },
            _ => Self::default(),
        }
    }

    fn unwrap_as_public(self) -> F {
        unimplemented!()
    }
}

impl<F: Field> FieldShare<F> for MulFieldShare<F> {
    fn map_homo<FF: Field, SS: FieldShare<FF>, Fun: Fn(F) -> FF>(self, _f: Fun) -> SS {
        unimplemented!()
    }
    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        let self_vec: Vec<Vec<F>> = selfs.into_iter().map(|s| vec![s.val0, s.val1] ).collect();
        let all_vals = Net::broadcast(&self_vec);
        let len = all_vals[0].len();
        let mut res = vec![F::one(); len];
        for i in 0..len {
            let mut tmp0 = F::one();
            let mut tmp1 = F::one();
            for party_id in 0..3 {
                tmp0 *= all_vals[party_id][i][0];
                tmp1 *= all_vals[party_id][i][1];
            }
            assert_eq!(tmp0, tmp1);
            res[i] = tmp0;  
        }
        res
    }

    fn add(&mut self, _other: &Self) -> &mut Self {
        unimplemented!("add for MulFieldShare")
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        match Net::party_id() {
            0 => self.val0 *= other,
            1 => self.val1 *= other,
            _ => (),
        }
        self
    }

    fn shift(&mut self, _other: &F) -> &mut Self {
        unimplemented!("add for MulFieldShare")
    }

    fn mul<S: BeaverSource<Self, Self, Self>>(self, other: Self, _source: &mut S) -> Self {
        Self {
            val0: self.val0 * other.val0,
            val1: self.val1 * other.val1,
        }
    }

    fn batch_mul<S: BeaverSource<Self, Self, Self>>(
        mut xs: Vec<Self>,
        ys: Vec<Self>,
        _source: &mut S,
    ) -> Vec<Self> {
        for (x, y) in xs.iter_mut().zip(ys.iter()) {
            x.val0 *= y.val0;
            x.val1 *= y.val1;
        }
        xs
    }

    fn inv<S: BeaverSource<Self, Self, Self>>(mut self, _source: &mut S) -> Self {
        self.val0 = self.val0.inverse().unwrap();
        self.val1 = self.val1.inverse().unwrap();
        self
    }

    fn batch_inv<S: BeaverSource<Self, Self, Self>>(xs: Vec<Self>, source: &mut S) -> Vec<Self> {
        xs.into_iter().map(|x| x.inv(source)).collect()
    }
}

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "F: PartialEq"),
    Eq(bound = "F: Eq"),
    Hash(bound = "F: Hash")
)]
pub struct MulExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for MulExtFieldShare<F> {
    type Ext = MulFieldShare<F>;
    type Base = MulFieldShare<F::BasePrimeField>;
}

impl_basics!(MulFieldShare, Field);

macro_rules! groups_share {
    ($struct_name:ident, $affine:ident, $proj:ident) => {
        pub struct $struct_name<E: PairingEngine>(pub PhantomData<E>);

        impl<E: PairingEngine> AffProjShare<E::Fr, E::$affine, E::$proj> for $struct_name<E> {
            type FrShare = RSS3FieldShare<E::Fr>;
            type AffineShare = RSS3GroupShare<E::$affine, crate::msm::AffineMsm<E::$affine>>;
            type ProjectiveShare =
                RSS3GroupShare<E::$proj, crate::msm::ProjectiveMsm<E::$proj>>;

            fn sh_aff_to_proj(g: Self::AffineShare) -> Self::ProjectiveShare {
                g.map_homo(|s| s.into())
            }

            fn sh_proj_to_aff(g: Self::ProjectiveShare) -> Self::AffineShare {
                g.map_homo(|s| s.into())
            }

            fn add_sh_proj_sh_aff(
                mut a: Self::ProjectiveShare,
                o: &Self::AffineShare,
            ) -> Self::ProjectiveShare {
                a.val0.add_assign_mixed(&o.val0);
                a.val1.add_assign_mixed(&o.val1);
                a
            }
            fn add_sh_proj_pub_aff(
                mut a: Self::ProjectiveShare,
                o: &E::$affine,
            ) -> Self::ProjectiveShare {
                match Net::party_id() {
                    0 => a.val0.add_assign_mixed(&o),
                    1 => a.val1.add_assign_mixed(&o),
                    _ => (),
                }
                a
            }
            fn add_pub_proj_sh_aff(_a: &E::$proj, _o: Self::AffineShare) -> Self::ProjectiveShare {
                unimplemented!()
            }
        }
    };
}

groups_share!(RSS3G1Share, G1Affine, G1Projective);
groups_share!(RSS3G2Share, G2Affine, G2Projective);

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct RSS3PairingShare<E: PairingEngine>(pub PhantomData<E>);

impl<E: PairingEngine> PairingShare<E> for RSS3PairingShare<E> {
    type FrShare = RSS3FieldShare<E::Fr>;
    type FqShare = RSS3FieldShare<E::Fq>;
    type FqeShare = RSS3ExtFieldShare<E::Fqe>;
    // Not a typo. We want a multiplicative subgroup.
    type FqkShare = MulExtFieldShare<E::Fqk>;
    type G1AffineShare = RSS3GroupShare<E::G1Affine, crate::msm::AffineMsm<E::G1Affine>>;
    type G2AffineShare = RSS3GroupShare<E::G2Affine, crate::msm::AffineMsm<E::G2Affine>>;
    type G1ProjectiveShare =
        RSS3GroupShare<E::G1Projective, crate::msm::ProjectiveMsm<E::G1Projective>>;
    type G2ProjectiveShare =
        RSS3GroupShare<E::G2Projective, crate::msm::ProjectiveMsm<E::G2Projective>>;
    type G1 = RSS3G1Share<E>;
    type G2 = RSS3G2Share<E>;
}
