use derivative::Derivative;
use log::debug;
use rand::Rng;
use zeroize::Zeroize;

use ark_ec::group::Group;
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::prelude::*;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};
use mpc_trait::MpcWire;

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{self, Read, Write};
use std::iter::Sum;
use std::marker::PhantomData;
use std::ops::*;

use super::super::share::group::GroupShare;
use super::super::share::BeaverSource;
use super::field::MpcField;
use mpc_net::{MpcNet, MpcMultiNet as Net};
use crate::Reveal;
use ark_std::test_rng;

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MpcGroup<G: Group, S: GroupShare<G>> {
    Public(G),
    Shared(S),
}

impl_basics_2!(GroupShare, Group, MpcGroup);

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyGroupTripleSource<T, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

impl<T: Group, S: GroupShare<T>> BeaverSource<S, S::FieldShare, S>
    for DummyGroupTripleSource<T, S>
{
    #[inline]
    fn triple(&mut self) -> (S, S::FieldShare, S) {
        (
            S::from_add_shared(T::zero()),
            <S::FieldShare as Reveal>::from_add_shared(if Net::am_king() {
                T::ScalarField::one()
            } else {
                T::ScalarField::zero()
            }),
            S::from_add_shared(T::zero()),
        )
    }
    #[inline]
    fn inv_pair(&mut self) -> (S::FieldShare, S::FieldShare) {
        (
            <S::FieldShare as Reveal>::from_add_shared(if Net::am_king() {
                T::ScalarField::one()
            } else {
                T::ScalarField::zero()
            }),
            <S::FieldShare as Reveal>::from_add_shared(if Net::am_king() {
                T::ScalarField::one()
            } else {
                T::ScalarField::zero()
            }),
        )
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DealerGroupTripleSource<T, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}
impl<T: Group, S: GroupShare<T>> BeaverSource<S, S::FieldShare, S>
    for DealerGroupTripleSource<T, S>
{
    #[inline]
    fn triples(&mut self, n: usize) -> (Vec<S>, Vec<S::FieldShare>, Vec<S>) {
        let rng = &mut test_rng();
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        let mut zs = Vec::new();
        for _ in 0..n {
            let x = T::rand(rng);
            let y = T::ScalarField::rand(rng);
            let mut z = x;
            z *= y;
            xs.push(x);
            ys.push(y);
            zs.push(z);
        }
        (S::king_share_batch(xs, rng), S::FieldShare::king_share_batch(ys, rng), S::king_share_batch(zs, rng),)
    }
    #[inline]
    fn triple(&mut self) -> (S, S::FieldShare, S) {
        let rng = &mut test_rng();
        let mut x = T::zero();
        let mut y = T::ScalarField::zero();
        let mut z = T::zero();
        if Net::am_king() {
            x = T::rand(rng);
            y = T::ScalarField::rand(rng);
            z = x;
            z *= y;
        }
        (S::king_share(x, rng), S::FieldShare::king_share(y, rng), S::king_share(z, rng),)
    }

    #[inline]
    fn inv_pair(&mut self) -> (S::FieldShare, S::FieldShare) {
        let rng = &mut test_rng();
        let mut x = T::ScalarField::zero();
        let mut inv_x = T::ScalarField::zero();
        if Net::am_king() {
            x = T::ScalarField::rand(rng);
            inv_x = x.inverse().unwrap();
        }
        (S::FieldShare::king_share(x, rng), S::FieldShare::king_share(inv_x, rng))
    }
}

impl_ref_ops!(Add, AddAssign, add, add_assign, Group, GroupShare, MpcGroup);
impl_ref_ops!(Sub, SubAssign, sub, sub_assign, Group, GroupShare, MpcGroup);

impl<T: Group, S: GroupShare<T>> MpcWire for MpcGroup<T, S> {
    #[inline]
    fn publicize(&mut self) {
        match self {
            MpcGroup::Shared(s) => {
                *self = MpcGroup::Public(s.reveal());
            }
            _ => {}
        }
        debug_assert!({
            let self_val = if let MpcGroup::Public(s) = self {
                s.clone()
            } else {
                unreachable!()
            };
            super::macros::check_eq(self_val);
            true
        })
    }
    #[inline]
    fn is_shared(&self) -> bool {
        match self {
            MpcGroup::Shared(_) => true,
            MpcGroup::Public(_) => false,
        }
    }
}

impl<T: Group, S: GroupShare<T>> Reveal for MpcGroup<T, S> {
    type Base = T;
    #[inline]
    fn reveal(self) -> Self::Base {
        let result = match self {
            Self::Shared(s) => s.reveal(),
            Self::Public(s) => s,
        };
        super::macros::check_eq(result.clone());
        result
    }
    #[inline]
    fn from_public(b: Self::Base) -> Self {
        Self::Public(b)
    }
    #[inline]
    fn from_add_shared(b: Self::Base) -> Self {
        Self::Shared(S::from_add_shared(b))
    }
    #[inline]
    fn unwrap_as_public(self) -> Self::Base {
        match self {
            Self::Shared(s) => s.unwrap_as_public(),
            Self::Public(s) => s,
        }
    }
    #[inline]
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        Self::Shared(S::king_share(f, rng))
    }
    #[inline]
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        S::king_share_batch(f, rng).into_iter().map(Self::Shared).collect()
    }
    fn init_protocol() {
        S::init_protocol()
    }
    fn deinit_protocol() {
        S::deinit_protocol()
    }
}

impl<T: Group, S: GroupShare<T>> Mul<MpcField<T::ScalarField, S::FieldShare>> for MpcGroup<T, S> {
    type Output = Self;
    #[inline]
    fn mul(mut self, other: MpcField<T::ScalarField, S::FieldShare>) -> Self::Output {
        self *= &other;
        self
    }
}

impl<'a, T: Group, S: GroupShare<T>> Mul<&'a MpcField<T::ScalarField, S::FieldShare>>
    for MpcGroup<T, S>
{
    type Output = Self;
    #[inline]
    fn mul(mut self, other: &MpcField<T::ScalarField, S::FieldShare>) -> Self::Output {
        self *= other;
        self
    }
}
impl<T: Group, S: GroupShare<T>> MulAssign<MpcField<T::ScalarField, S::FieldShare>>
    for MpcGroup<T, S>
{
    #[inline]
    fn mul_assign(&mut self, other: MpcField<T::ScalarField, S::FieldShare>) {
        *self *= &other;
    }
}
impl<'a, T: Group, S: GroupShare<T>> MulAssign<&'a MpcField<T::ScalarField, S::FieldShare>>
    for MpcGroup<T, S>
{
    #[inline]
    fn mul_assign(&mut self, other: &MpcField<T::ScalarField, S::FieldShare>) {
        match self {
            // for some reason, a two-stage match (rather than a tuple match) avoids moving
            // self
            MpcGroup::Public(x) => match other {
                MpcField::Public(y) => {
                    *x *= *y;
                }
                MpcField::Shared(y) => {
                    let t = MpcGroup::Shared(S::scale_pub_group(*x, &y));
                    *self = t;
                }
            },
            MpcGroup::Shared(x) => match other {
                MpcField::Public(y) => {
                    x.scale_pub_scalar(y);
                }
                MpcField::Shared(y) => {
                    let t = x.scale(*y, &mut DummyGroupTripleSource::default());
                    *x = t;
                }
            },
        }
    }
}

impl<T: Group, S: GroupShare<T>> Group for MpcGroup<T, S> {
    type ScalarField = MpcField<T::ScalarField, S::FieldShare>;
}
impl<T: Group, S: GroupShare<T>> MpcGroup<T, S> {
    pub fn unwrap_as_public_or_add_shared(self) -> T {
        match self {
            Self::Public(p) => p,
            Self::Shared(p) => p.unwrap_as_public(),
        }
    }
    pub fn all_public_or_shared(v: impl IntoIterator<Item = Self>) -> Result<Vec<T>, Vec<S>> {
        let mut out_a = Vec::new();
        let mut out_b = Vec::new();
        for s in v {
            match s {
                Self::Public(x) => out_a.push(x),
                Self::Shared(x) => out_b.push(x),
            }
        }
        if out_a.len() > 0 && out_b.len() > 0 {
            panic!("Heterogeous")
        } else if out_b.len() > 0 {
            Err(out_b)
        } else {
            Ok(out_a)
        }
    }
}
