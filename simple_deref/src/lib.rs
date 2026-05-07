/// ```
/// # use simple_deref::impl_deref;
///
/// # #[derive(Debug, PartialEq)]
/// struct WrapperMut<T>(T);
///
/// impl_deref!(impl<T> mut WrapperMut<T> => T = .0);
/// let mut wrapper = WrapperMut(0);
/// *wrapper = 2;
/// assert_eq!(wrapper, WrapperMut(2));
/// ```
///
/// ```
/// # use simple_deref::impl_deref;
///
/// struct Wrapper<T>(T);
///
/// impl_deref!(impl<T> ref Wrapper<T> => T = .0);
/// let mut wrapper = Wrapper(2);
/// assert_eq!(*wrapper, 2);
/// ```
///
/// ```
/// # use simple_deref::impl_deref;
///
/// struct Something {
///     inner: i32,
/// }
///
/// impl_deref!(ref Something => i32 = .inner);
/// let mut something = Something { inner: 1234 };
/// assert_eq!(*something, 1234);
/// ```
///
/// ```
/// struct Something(i32);
///
/// simple_deref::impl_deref!(mut Something => i32 = .0);
/// let mut something = Something(1234);
/// assert_eq!(*something, 1234);
/// ```
#[macro_export]
macro_rules! impl_deref {
    ($(impl<$($ge:ident),*>)? mut $src:path => $dst:path = $($tt:tt)*) => {
        $crate::impl_deref!($(impl<$($ge),*>)? ref $src => $dst = $($tt)*);

        impl$(<$($ge),*>)? ::core::ops::DerefMut for $src {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self$($tt)*
            }
        }
    };

    ($(impl<$($ge:ident),*>)? ref $src:path => $dst:path = $($tt:tt)*) => {
        impl$(<$($ge),*>)? ::core::ops::Deref for $src {
            type Target = $dst;

            fn deref(&self) -> &Self::Target {
                &self$($tt)*
            }
        }
    };
}
