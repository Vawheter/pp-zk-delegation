#![macro_use]
use ark_std::{collections::BTreeMap, marker::PhantomData, rc::Rc};
use rand::Rng;

// use super::add::{AdditiveFieldShare, AdditiveGroupShare};
use crate::share::add::AdditiveFieldShare;


pub trait ShareConversion {
    // type Target = AdditiveFieldShare;
    type Target;

    fn share_conversion(self) -> Self::Target;
}


// impl<T: ShareConversion> ShareConversion for PhantomData<ShareConversion> {
//     type Target = PhantomData<T::Target>;

//     fn share_conversion(self) -> Self::Target {
//         PhantomData::default()
//     }
// }

impl<T: ShareConversion> ShareConversion for Vec<T> {
    type Target = Vec<T::Target>;

    fn share_conversion(self) -> Self::Target {
        self.into_iter().map(|x| x.share_conversion()).collect()
    }
}

impl<K: ShareConversion + Ord, V: ShareConversion> ShareConversion for BTreeMap<K, V>
where
    K::Target: Ord,
{
    type Target = BTreeMap<K::Target, V::Target>;

    fn share_conversion(self) -> Self::Target {
        self.into_iter().map(|x| x.share_conversion()).collect()
    }
}

impl<T: ShareConversion + Clone> ShareConversion for Rc<T>
where
    T::Target: Clone,
{
    type Target = Rc<T::Target>;

    fn share_conversion(self) -> Self::Target {
        Rc::new((*self).clone().share_conversion())
    }
}

impl<A: ShareConversion, B: ShareConversion> ShareConversion for (A, B) {
    type Target = (A::Target, B::Target);

    fn share_conversion(self) -> Self::Target {
        (self.0.share_conversion(), self.1.share_conversion())
    }
}

#[macro_export]
macro_rules! struct_share_conversion_impl {
    ($s:ty, $con:tt ; $( ($x_ty:ty, $x:tt) ),*) => {
        fn share_conversion(self) -> Self::Target {
            $con {
                $(
                    $x: self.$x.share_conversion(),
                )*
            }
        }
    }
}

#[macro_export]
macro_rules! struct_share_conversion_simp_impl {
    ($con:path ; $( $x:tt ),*) => {
        fn share_conversion(self) -> Self::Target {
            $con {
                $(
                    $x: self.$x.share_conversion(),
                )*
            }
        }
    }
}

// #[macro_export]
// macro_rules! dbg_disp {
//     ($e:expr) => {
//         println!("{}: {}", std::stringify!($e), &$e)
//     }
// }
