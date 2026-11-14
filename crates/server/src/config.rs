/// Server settings, read from environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `LARDER_BIND`, default `0.0.0.0:8080` (reachable from the home network).
    pub bind: String,
    /// `LARDER_DATABASE`, default `larder-server.db` in the working directory.
    pub database: String,
    /// `LARDER_ALLOW_REGISTRATION`, default `true`. Set to `false` once the
    /// household has its accounts.
    pub allow_registration: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let value = |name: &str| {
            get(name)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let allow_registration = match value("LARDER_ALLOW_REGISTRATION").as_deref() {
            None | Some("true") | Some("1") => true,
            Some("false") | Some("0") => false,
            Some(other) => {
                return Err(format!(
                    "LARDER_ALLOW_REGISTRATION must be true or false, not {other:?}"
                ));
            }
        };
        Ok(Self {
            bind: value("LARDER_BIND").unwrap_or_else(|| "0.0.0.0:8080".into()),
            database: value("LARDER_DATABASE").unwrap_or_else(|| "larder-server.db".into()),
            allow_registration,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(vars: &[(&str, &str)]) -> Result<Config, String> {
        Config::from_lookup(|name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        })
    }

    #[test]
    fn defaults() {
        assert_eq!(
            config(&[]).unwrap(),
            Config {
                bind: "0.0.0.0:8080".into(),
                database: "larder-server.db".into(),
                allow_registration: true,
            }
        );
    }

    #[test]
    fn overrides_and_blank_values() {
        let c = config(&[
            ("LARDER_BIND", "127.0.0.1:9000"),
            ("LARDER_DATABASE", "  "),
            ("LARDER_ALLOW_REGISTRATION", "false"),
        ])
        .unwrap();
        assert_eq!(c.bind, "127.0.0.1:9000");
        assert_eq!(c.database, "larder-server.db");
        assert!(!c.allow_registration);
    }

    #[test]
    fn invalid_boolean_is_an_error_not_a_silent_default() {
        assert!(config(&[("LARDER_ALLOW_REGISTRATION", "nope")]).is_err());
    }
}
