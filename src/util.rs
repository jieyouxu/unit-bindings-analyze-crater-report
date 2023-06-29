macro_rules! from_into_string {
    ($for:ident) => {
        impl std::convert::TryFrom<String> for $for {
            type Error = <$for as std::str::FromStr>::Err;
            fn try_from(s: String) -> Result<Self, <$for as std::str::FromStr>::Err> {
                s.parse()
            }
        }

        impl From<$for> for String {
            fn from(s: $for) -> String {
                s.to_string()
            }
        }
    };
}

pub(crate) use from_into_string;

macro_rules! string_enum {
    ($vis:vis enum $name:ident { $($item:ident => $str:expr,)* }) => {
        #[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        $vis enum $name {
            $($item,)*
        }

        impl ::std::str::FromStr for $name {
            type Err = ::failure::Error;

            fn from_str(s: &str) -> ::failure::Fallible<$name> {
                match s {
                    $($str => Ok($name::$item),)*
                    s => ::failure::bail!("invalid {}: {}", stringify!($name), s),
                }
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "{}", self.to_str())
            }
        }

        impl $name {
            #[allow(dead_code)]
            $vis fn to_str(&self) -> &'static str {
                match *self {
                    $($name::$item => $str,)*
                }
            }

            #[allow(dead_code)]
            $vis fn possible_values() -> &'static [&'static str] {
                &[$($str,)*]
            }
        }

        $crate::util::from_into_string!($name);
    }
}

pub(crate) use string_enum;
