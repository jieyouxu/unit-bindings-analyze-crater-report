use percent_encoding::{
    percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS, NON_ALPHANUMERIC,
};
use rustwide::Toolchain as RustwideToolchain;
use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use crate::util::*;

#[derive(Serialize, Deserialize)]
pub struct RawTestResults {
    pub crates: Vec<CrateResult>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CrateResult {
    pub(crate) name: String,
    pub(crate) url: String,
    pub(crate) krate: Crate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<CrateVersionStatus>,
    pub res: Comparison,
    pub(crate) runs: [Option<BuildTestResult>; 2],
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Clone)]
pub enum Crate {
    Registry(RegistryCrate),
    GitHub(GitHubRepo),
    Local(String),
    Path(String),
    Git(GitRepo),
}

impl Crate {
    pub(crate) fn id(&self) -> String {
        match *self {
            Crate::Registry(ref details) => format!("reg/{}/{}", details.name, details.version),
            Crate::GitHub(ref repo) => {
                if let Some(ref sha) = repo.sha {
                    format!("gh/{}/{}/{sha}", repo.org, repo.name)
                } else {
                    format!("gh/{}/{}", repo.org, repo.name)
                }
            }
            Crate::Local(ref name) => format!("local/{name}"),
            Crate::Path(ref path) => {
                format!("path/{}", utf8_percent_encode(path, NON_ALPHANUMERIC))
            }
            Crate::Git(ref repo) => {
                if let Some(ref sha) = repo.sha {
                    format!(
                        "git/{}/{}",
                        utf8_percent_encode(&repo.url, NON_ALPHANUMERIC),
                        sha
                    )
                } else {
                    format!("git/{}", utf8_percent_encode(&repo.url, NON_ALPHANUMERIC),)
                }
            }
        }
    }
}

lazy_static! {
    /// This toolchain is used during internal tests, and must be different than TEST_TOOLCHAIN
    pub(crate) static ref MAIN_TOOLCHAIN: Toolchain = Toolchain {
        source: RustwideToolchain::dist("stable"),
        target: None,
        rustflags: None,
        rustdocflags: None,
        cargoflags: None,
        ci_try: false,
        patches: Vec::new(),
    };

    /// This toolchain is used during internal tests, and must be different than MAIN_TOOLCHAIN
    pub(crate) static ref TEST_TOOLCHAIN: Toolchain = Toolchain {
        source: RustwideToolchain::dist("beta"),
        target: None,
        rustflags: None,
        rustdocflags: None,
        cargoflags: None,
        ci_try: false,
        patches: Vec::new(),
    };
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Debug, Clone)]
pub struct Toolchain {
    pub source: RustwideToolchain,
    pub target: Option<String>,
    pub rustflags: Option<String>,
    pub rustdocflags: Option<String>,
    pub cargoflags: Option<String>,
    pub ci_try: bool,
    pub patches: Vec<CratePatch>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Debug, Clone)]
pub struct CratePatch {
    pub name: String,
    pub repo: String,
    pub branch: String,
}

impl std::str::FromStr for CratePatch {
    type Err = ToolchainParseError;

    fn from_str(input: &str) -> Result<Self, ToolchainParseError> {
        let params: Vec<&str> = input.split('=').collect();

        if params.len() != 3 {
            Err(ToolchainParseError::InvalidFlag(input.to_string()))
        } else {
            Ok(CratePatch {
                name: params[0].into(),
                repo: params[1].into(),
                branch: params[2].into(),
            })
        }
    }
}

impl fmt::Display for CratePatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}={}={}", self.name, self.repo, self.branch)
    }
}

impl Toolchain {
    pub fn to_path_component(&self) -> String {
        use percent_encoding::utf8_percent_encode as encode;

        encode(&self.to_string(), &FILENAME_ENCODE_SET).to_string()
    }
}

impl std::ops::Deref for Toolchain {
    type Target = RustwideToolchain;

    fn deref(&self) -> &Self::Target {
        &self.source
    }
}

impl fmt::Display for Toolchain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(dist) = self.source.as_dist() {
            write!(f, "{}", dist.name())?;
        } else if let Some(ci) = self.source.as_ci() {
            if self.ci_try {
                write!(f, "try#{}", ci.sha())?;
            } else {
                write!(f, "master#{}", ci.sha())?;
            }
        } else {
            panic!("unsupported rustwide toolchain");
        }

        if let Some(ref target) = self.target {
            write!(f, "+target={target}")?;
        }

        if let Some(ref flag) = self.rustflags {
            write!(f, "+rustflags={flag}")?;
        }

        if let Some(ref flag) = self.rustdocflags {
            write!(f, "+rustdocflags={flag}")?;
        }

        if let Some(ref flag) = self.cargoflags {
            write!(f, "+cargoflags={flag}")?;
        }

        for patch in self.patches.iter() {
            write!(f, "+patch={patch}")?;
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ToolchainParseError {
    #[error("empty toolchain name")]
    EmptyName,
    #[error("invalid toolchain source name: {0}")]
    InvalidSourceName(String),
    #[error("invalid toolchain flag: {0}")]
    InvalidFlag(String),
}

pub(crate) const FILENAME_ENCODE_SET: AsciiSet = CONTROLS
    .add(b'<')
    .add(b'>')
    .add(b':')
    .add(b'"')
    .add(b'/')
    .add(b'\\')
    .add(b'|')
    .add(b'?')
    .add(b'*');

impl std::str::FromStr for Toolchain {
    type Err = ToolchainParseError;

    fn from_str(input: &str) -> Result<Self, ToolchainParseError> {
        let mut parts = input.split('+');

        let raw_source = parts.next().ok_or(ToolchainParseError::EmptyName)?;
        let mut ci_try = false;
        let source = if let Some(hash_idx) = raw_source.find('#') {
            let (source_name, sha_with_hash) = raw_source.split_at(hash_idx);

            let sha = &sha_with_hash[1..];
            if sha.is_empty() {
                return Err(ToolchainParseError::EmptyName);
            }

            match source_name {
                "try" => {
                    ci_try = true;
                    RustwideToolchain::ci(sha, false)
                }
                "master" => RustwideToolchain::ci(sha, false),
                name => return Err(ToolchainParseError::InvalidSourceName(name.to_string())),
            }
        } else if raw_source.is_empty() {
            return Err(ToolchainParseError::EmptyName);
        } else {
            RustwideToolchain::dist(raw_source)
        };

        let mut rustflags = None;
        let mut rustdocflags = None;
        let mut cargoflags = None;
        let mut patches: Vec<CratePatch> = vec![];
        let mut target = None;
        for part in parts {
            if let Some(equal_idx) = part.find('=') {
                let (flag, value_with_equal) = part.split_at(equal_idx);
                let value = value_with_equal[1..].to_string();

                if value.is_empty() {
                    return Err(ToolchainParseError::InvalidFlag(flag.to_string()));
                }

                match flag {
                    "rustflags" => rustflags = Some(value),
                    "rustdocflags" => rustdocflags = Some(value),
                    "cargoflags" => cargoflags = Some(value),
                    "patch" => patches.push(value.parse()?),
                    "target" => target = Some(value),
                    unknown => return Err(ToolchainParseError::InvalidFlag(unknown.to_string())),
                }
            } else {
                return Err(ToolchainParseError::InvalidFlag(part.to_string()));
            }
        }

        Ok(Toolchain {
            source,
            target,
            rustflags,
            rustdocflags,
            cargoflags,
            ci_try,
            patches,
        })
    }
}

/// The type of sanitization required for a string.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SanitizationContext {
    Url,
    Path,
}

pub(crate) const REPORT_ENCODE_SET: AsciiSet = percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'?')
    .add(b'{')
    .add(b'}')
    .add(b'+');

impl SanitizationContext {
    fn sanitize(self, input: &str) -> Cow<str> {
        match self {
            SanitizationContext::Url => utf8_percent_encode(input, &REPORT_ENCODE_SET).into(),
            SanitizationContext::Path => utf8_percent_encode(input, &FILENAME_ENCODE_SET).into(),
        }
    }
}

pub(crate) fn crate_to_path_fragment(
    toolchain: &Toolchain,
    krate: &Crate,
    dest: SanitizationContext,
) -> PathBuf {
    let mut path = PathBuf::new();
    path.push(dest.sanitize(&toolchain.to_string()).into_owned());

    match *krate {
        Crate::Registry(ref details) => {
            path.push("reg");

            let name = format!("{}-{}", details.name, details.version);
            path.push(dest.sanitize(&name).into_owned());
        }
        Crate::GitHub(ref repo) => {
            path.push("gh");

            let name = format!("{}.{}", repo.org, repo.name);
            path.push(dest.sanitize(&name).into_owned());
        }
        Crate::Local(ref name) => {
            path.push("local");
            path.push(name);
        }
        Crate::Path(ref krate_path) => {
            path.push("path");
            path.push(dest.sanitize(krate_path).into_owned());
        }
        Crate::Git(ref repo) => {
            path.push("git");
            path.push(dest.sanitize(&repo.url).into_owned());
        }
    }

    path
}

impl fmt::Display for Crate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Crate::Registry(ref krate) => format!("{}-{}", krate.name, krate.version),
                Crate::GitHub(ref repo) =>
                    if let Some(ref sha) = repo.sha {
                        format!("{}/{}/{sha}", repo.org, repo.name)
                    } else {
                        format!("{}/{}", repo.org, repo.name)
                    },
                Crate::Local(ref name) => format!("{name} (local)"),
                Crate::Path(ref path) => format!("{}", utf8_percent_encode(path, NON_ALPHANUMERIC)),
                Crate::Git(ref repo) =>
                    if let Some(ref sha) = repo.sha {
                        format!(
                            "{}/{}",
                            utf8_percent_encode(&repo.url, NON_ALPHANUMERIC),
                            sha
                        )
                    } else {
                        utf8_percent_encode(&repo.url, NON_ALPHANUMERIC).to_string()
                    },
            }
        )
    }
}

impl std::str::FromStr for Crate {
    type Err = ::failure::Error;

    // matches with `Crate::id'
    fn from_str(s: &str) -> failure::Fallible<Self> {
        match s.split('/').collect::<Vec<_>>()[..] {
            ["reg", name, version] => Ok(Crate::Registry(RegistryCrate {
                name: name.to_string(),
                version: version.to_string(),
            })),
            ["gh", org, name, sha] => Ok(Crate::GitHub(GitHubRepo {
                org: org.to_string(),
                name: name.to_string(),
                sha: Some(sha.to_string()),
            })),
            ["gh", org, name] => Ok(Crate::GitHub(GitHubRepo {
                org: org.to_string(),
                name: name.to_string(),
                sha: None,
            })),
            ["git", repo, sha] => Ok(Crate::Git(GitRepo {
                url: percent_decode_str(repo).decode_utf8()?.to_string(),
                sha: Some(sha.to_string()),
            })),
            ["git", repo] => Ok(Crate::Git(GitRepo {
                url: percent_decode_str(repo).decode_utf8()?.to_string(),
                sha: None,
            })),
            ["local", name] => Ok(Crate::Local(name.to_string())),
            ["path", path] => Ok(Crate::Path(
                percent_decode_str(path).decode_utf8()?.to_string(),
            )),
            _ => failure::bail!("unexpected crate value"),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Clone)]
pub struct RegistryCrate {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Clone)]
pub struct GitHubRepo {
    pub org: String,
    pub name: String,
    pub sha: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Clone)]
pub struct GitRepo {
    pub url: String,
    pub sha: Option<String>,
}

string_enum!(pub enum CrateVersionStatus {
    Yanked => "yanked",
    Outdated => "outdated",
    UpToDate => "",
    MissingFromIndex => "missing from the index",
});

string_enum!(pub enum Comparison {
    Regressed => "regressed",
    Fixed => "fixed",
    Skipped => "skipped",
    Unknown => "unknown",
    Error => "error",
    Broken => "broken",
    SameBuildFail => "build-fail",
    SameTestFail => "test-fail",
    SameTestSkipped => "test-skipped",
    SameTestPass => "test-pass",
    SpuriousRegressed => "spurious-regressed",
    SpuriousFixed => "spurious-fixed",
});

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BuildTestResult {
    pub(crate) res: TestResult,
    pub(crate) log: String,
}

macro_rules! test_result_enum {
    (pub enum $name:ident {
        with_reason { $($with_reason_name:ident($reason:ident) => $with_reason_repr:expr,)* }
        without_reason { $($reasonless_name:ident => $reasonless_repr:expr,)* }
    }) => {
        #[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub enum $name {
            $($with_reason_name($reason),)*
            $($reasonless_name,)*
        }

        impl std::str::FromStr for $name {
            type Err = ::failure::Error;

            fn from_str(input: &str) -> ::failure::Fallible<Self> {
                // if there is more than one ':' we assume it's part of a failure reason serialization
                let parts: Vec<&str> = input.splitn(2, ':').collect();

                if parts.len() == 1 {
                    match parts[0] {
                        $($with_reason_repr => Ok($name::$with_reason_name($reason::Unknown)),)*
                        $($reasonless_repr => Ok($name::$reasonless_name),)*
                        other => Err(TestResultParseError::UnknownResult(other.into()).into()),
                    }
                } else {
                    match parts[0] {
                        $($reasonless_repr => Err(TestResultParseError::UnexpectedFailureReason.into()),)*
                        $($with_reason_repr => Ok($name::$with_reason_name(parts[1].parse()?)),)*
                        other => Err(TestResultParseError::UnknownResult(other.into()).into()),
                    }
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match self {
                    $($name::$with_reason_name(reason) => write!(f, "{}:{}", $with_reason_repr, reason),)*
                    $($name::$reasonless_name => write!(f, "{}", $reasonless_repr),)*
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TestResultParseError {
    #[error("unknown test result: {0}")]
    UnknownResult(String),
    #[error("unexpected failure reason")]
    UnexpectedFailureReason,
}

test_result_enum!(pub enum TestResult {
    with_reason {
        BrokenCrate(BrokenReason) => "broken",
        BuildFail(FailureReason) => "build-fail",
        TestFail(FailureReason) => "test-fail",
    }
    without_reason {
        TestSkipped => "test-skipped",
        TestPass => "test-pass",
        Skipped => "skipped",
        Error => "error",
    }
});

from_into_string!(TestResult);

string_enum!(pub enum BrokenReason {
    Unknown => "unknown",
    CargoToml => "cargo-toml",
    Yanked => "yanked",
    MissingDependencies => "missing-deps",
    MissingGitRepository => "missing-git-repository",
});

#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize)]
pub enum FailureReason {
    Unknown,
    OOM,
    Timeout,
    ICE,
    NetworkAccess,
    CompilerDiagnosticChange,
    CompilerError(BTreeSet<DiagnosticCode>),
    DependsOn(BTreeSet<Crate>),
}

impl ::std::str::FromStr for FailureReason {
    type Err = ::failure::Error;

    fn from_str(s: &str) -> ::failure::Fallible<FailureReason> {
        if let (Some(idx), true) = (s.find('('), s.ends_with(')')) {
            let prefix = &s[..idx];
            let contents = s[idx + 1..s.len() - 1].split(", ");
            match prefix {
                "compiler-error" => Ok(FailureReason::CompilerError(
                    contents
                        .map(|st| DiagnosticCode {
                            code: st.to_string(),
                        })
                        .collect(),
                )),
                "depends-on" => {
                    let mut krates: BTreeSet<Crate> = BTreeSet::new();
                    for krate in contents {
                        krates.insert(krate.parse()?);
                    }
                    Ok(FailureReason::DependsOn(krates))
                }
                _ => ::failure::bail!("unexpected prefix: {}", prefix),
            }
        } else {
            match s {
                "network-access" => Ok(FailureReason::NetworkAccess),
                "unknown" => Ok(FailureReason::Unknown),
                "oom" => Ok(FailureReason::OOM),
                "timeout" => Ok(FailureReason::Timeout),
                "ice" => Ok(FailureReason::ICE),
                _ => ::failure::bail!("unexpected value: {}", s),
            }
        }
    }
}

impl FailureReason {
    pub(crate) fn is_spurious(&self) -> bool {
        match *self {
            FailureReason::OOM
            | FailureReason::Timeout
            | FailureReason::NetworkAccess
            | FailureReason::CompilerDiagnosticChange => true,
            FailureReason::CompilerError(_)
            | FailureReason::DependsOn(_)
            | FailureReason::Unknown
            | FailureReason::ICE => false,
        }
    }
}

impl ::std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            FailureReason::Unknown => write!(f, "unknown"),
            FailureReason::OOM => write!(f, "oom"),
            FailureReason::Timeout => write!(f, "timeout"),
            FailureReason::ICE => write!(f, "ice"),
            FailureReason::NetworkAccess => write!(f, "network-access"),
            FailureReason::CompilerError(codes) => write!(
                f,
                "compiler-error({})",
                codes
                    .iter()
                    .map(|diag| diag.code.clone())
                    .collect::<Vec<String>>()
                    .join(", "),
            ),
            FailureReason::DependsOn(deps) => write!(
                f,
                "depends-on({})",
                deps.iter()
                    .map(|dep| dep.id())
                    .collect::<Vec<String>>()
                    .join(", "),
            ),
            FailureReason::CompilerDiagnosticChange => write!(f, "compiler-diagnostic-change"),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Eq, Clone, Hash, PartialOrd, Ord)]
pub struct DiagnosticCode {
    pub(crate) code: String,
}
