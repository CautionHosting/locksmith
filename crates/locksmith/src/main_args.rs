pub const USAGE: &str = "Usage: locksmith ADDRESS [BUNDLE] [POLICY] [--keymaker-pcr-policy PATH]\nBUNDLE defaults to bundle.json. Policy precedence: flag, positional, KEYMAKER_PCR_POLICY_JSON.";

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub address: String,
    pub bundlefile: String,
    pub policyfile: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{reason} [{location}]")]
pub struct ArgsError {
    reason: &'static str,
    location: &'static std::panic::Location<'static>,
}

impl ArgsError {
    #[track_caller]
    fn new(reason: &'static str) -> Self {
        Self {
            reason,
            location: std::panic::Location::caller(),
        }
    }
}

pub fn parse(
    args: impl IntoIterator<Item = String>,
    env_policy: Option<String>,
) -> Result<Args, ArgsError> {
    let mut args = args.into_iter();
    let mut positionals = Vec::new();
    let mut flag_policy = None;
    while let Some(arg) = args.next() {
        if arg == "--keymaker-pcr-policy" {
            if flag_policy.is_some() {
                return Err(ArgsError::new("duplicate --keymaker-pcr-policy"));
            }
            let value = args
                .next()
                .filter(|s| !s.is_empty() && !s.starts_with('-'))
                .ok_or_else(|| ArgsError::new("--keymaker-pcr-policy requires a path"))?;
            flag_policy = Some(value);
        } else if arg.starts_with('-') {
            return Err(ArgsError::new("unknown option"));
        } else {
            positionals.push(arg);
        }
    }
    if positionals.len() > 3 {
        return Err(ArgsError::new("too many positional arguments"));
    }
    let mut positionals = positionals.into_iter();
    let address = positionals
        .next()
        .ok_or_else(|| ArgsError::new("missing socket address"))?;
    let bundlefile = positionals.next().unwrap_or_else(|| "bundle.json".into());
    let policyfile = flag_policy
        .or_else(|| positionals.next())
        .or(env_policy)
        .ok_or_else(|| ArgsError::new("missing Keymaker PCR policy path"))?;
    Ok(Args {
        address,
        bundlefile,
        policyfile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str], env: Option<&str>) -> Result<Args, ArgsError> {
        parse(args.iter().map(|s| (*s).into()), env.map(str::to_owned))
    }

    #[test]
    fn legacy_arguments_and_environment_fallback() {
        let args = parse_args(&["127.0.0.1:49504"], Some("env.json")).unwrap();
        assert_eq!(args.bundlefile, "bundle.json");
        assert_eq!(args.policyfile, "env.json");
        let args = parse_args(&["address", "bundle", "positional"], Some("env")).unwrap();
        assert_eq!(args.bundlefile, "bundle");
        assert_eq!(args.policyfile, "positional");
    }

    #[test]
    fn named_policy_overrides_positional_and_environment() {
        let args = parse_args(
            &[
                "address",
                "bundle",
                "positional",
                "--keymaker-pcr-policy",
                "named",
            ],
            Some("env"),
        )
        .unwrap();
        assert_eq!(args.policyfile, "named");
        let args = parse_args(&["--keymaker-pcr-policy", "named", "address"], None).unwrap();
        assert_eq!(args.bundlefile, "bundle.json");
        assert_eq!(args.policyfile, "named");
    }

    #[test]
    fn invalid_arguments_have_usage_errors() {
        for args in [
            vec![],
            vec!["address"],
            vec!["address", "--keymaker-pcr-policy"],
            vec!["address", "--keymaker-pcr-policy", ""],
            vec!["address", "--unknown"],
            vec!["address", "--keymaker-pcr-policy", "--unknown"],
            vec![
                "address",
                "--keymaker-pcr-policy",
                "a",
                "--keymaker-pcr-policy",
                "b",
            ],
            vec!["address", "bundle", "policy", "extra"],
        ] {
            assert!(parse_args(&args, None).is_err(), "accepted {args:?}");
        }
    }
}
