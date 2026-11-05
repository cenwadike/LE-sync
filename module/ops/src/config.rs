//! The environment file (`config/<env>.toml`): flat `key = value` lines under `[section]`
//! headers, the same file `scripts/*.sh` read. One file per environment is the only thing that
//! differs between a local run and the testnet.
use le_sync_core::instance::{InstanceConfig, Timing};
use le_sync_core::sync::Version;
use le_sync_core::Bytes32;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Config {
    pub path: PathBuf,
    map: BTreeMap<(String, String), String>,
}

impl Config {
    pub fn parse(text: &str, path: &Path) -> Result<Config, String> {
        let mut map = BTreeMap::new();
        let mut section = String::new();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(s) = line.strip_prefix('[') {
                section = s
                    .strip_suffix(']')
                    .ok_or_else(|| {
                        format!("{}:{}: unclosed section header", path.display(), n + 1)
                    })?
                    .trim()
                    .to_string();
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| format!("{}:{}: expected `key = value`", path.display(), n + 1))?;
            let v = v.trim();
            let v = if let Some(rest) = v.strip_prefix('"') {
                rest.split('"').next().unwrap_or("").to_string()
            } else {
                v.split('#').next().unwrap_or("").trim().to_string()
            };
            map.insert((section.clone(), k.trim().to_string()), v);
        }
        Ok(Config {
            path: path.to_path_buf(),
            map,
        })
    }

    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Config::parse(&text, path)
    }

    /// The value, or an error that says which file and key is missing.
    pub fn get(&self, section: &str, key: &str) -> Result<&str, String> {
        self.map
            .get(&(section.to_string(), key.to_string()))
            .map(|s| s.as_str())
            .ok_or_else(|| format!("[{section}] {key} is not in {}", self.path.display()))
    }

    /// A value that must be filled (by `scripts/deploy.sh` or by hand).
    pub fn need(&self, section: &str, key: &str) -> Result<&str, String> {
        let v = self.get(section, key)?;
        if v.is_empty() {
            return Err(format!(
                "[{section}] {key} is empty in {}: run scripts/deploy.sh, or fill it in",
                self.path.display()
            ));
        }
        Ok(v)
    }

    pub fn or<'a>(&'a self, section: &str, key: &str, default: &'a str) -> &'a str {
        match self.get(section, key) {
            Ok(v) if !v.is_empty() => v,
            _ => default,
        }
    }

    pub fn num(&self, section: &str, key: &str) -> Result<u64, String> {
        self.need(section, key)?
            .parse::<u64>()
            .map_err(|e| format!("[{section}] {key}: {e}"))
    }

    pub fn num_or(&self, section: &str, key: &str, default: u64) -> Result<u64, String> {
        match self.get(section, key) {
            Ok(v) if !v.is_empty() => v
                .parse::<u64>()
                .map_err(|e| format!("[{section}] {key}: {e}")),
            _ => Ok(default),
        }
    }

    /// `[eth] source`: `live` or `replay`.
    pub fn replay(&self) -> bool {
        self.or("eth", "source", "live") == "replay"
    }

    pub fn beacon_url(&self) -> Result<String, String> {
        Ok(if self.replay() {
            self.need("eth", "replay_url")?
        } else {
            self.need("eth", "beacon_url")?
        }
        .trim_end_matches('/')
        .to_string())
    }

    pub fn execution_url(&self) -> Result<String, String> {
        Ok(if self.replay() {
            self.need("eth", "replay_url")?
        } else {
            self.need("eth", "execution_url")?
        }
        .trim_end_matches('/')
        .to_string())
    }

    /// The instance as `deploy.sh` wrote it: the same fields, so the same instance ID, on
    /// every machine that reads the file.
    pub fn instance_config(&self) -> Result<InstanceConfig, String> {
        let forks = parse_forks(self.need("instance", "forks")?)?;
        InstanceConfig::new(
            self.num("eth", "chain_id")?,
            hex32(self.need("instance", "genesis_validators_root")?)?,
            self.num("instance", "slots_per_epoch")?,
            self.num("instance", "epochs_per_period")?,
            u16::try_from(self.num("instance", "sync_committee_size")?)
                .map_err(|_| "[instance] sync_committee_size does not fit 16 bits".to_string())?,
            self.num("instance", "electra_fork_epoch")?,
            None,
            &forks,
            Timing {
                genesis_time: self.num("instance", "genesis_time")?,
                seconds_per_slot: self.num("instance", "seconds_per_slot")?,
            },
            hex32(self.need("instance", "trusted_root")?)?,
        )
        .map_err(|e| format!("the instance configuration is not valid: {e:?}"))
    }
}

pub fn hex32(s: &str) -> Result<Bytes32, String> {
    let raw =
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| format!("hex `{s}`: {e}"))?;
    <Bytes32>::try_from(raw.as_slice()).map_err(|_| format!("`{s}`: expected 32 bytes"))
}

/// `"electra:222464:0x90000074,fulu:272640:0x90000075"` -> `[(epoch, version)]` in epoch order.
pub fn parse_forks(s: &str) -> Result<Vec<(u64, Version)>, String> {
    let mut out = vec![];
    for item in s.split(',').map(str::trim).filter(|i| !i.is_empty()) {
        let mut p = item.split(':');
        let (_name, epoch, ver) = (p.next(), p.next(), p.next());
        let (Some(epoch), Some(ver), None) = (epoch, ver, p.next()) else {
            return Err(format!("fork `{item}`: expected name:epoch:version"));
        };
        let epoch = epoch
            .parse::<u64>()
            .map_err(|e| format!("fork `{item}`: epoch: {e}"))?;
        let ver = hex::decode(ver.strip_prefix("0x").unwrap_or(ver))
            .map_err(|e| format!("fork `{item}`: version: {e}"))?;
        let ver = Version::try_from(ver.as_slice())
            .map_err(|_| format!("fork `{item}`: version is not 4 bytes"))?;
        out.push((epoch, ver));
    }
    if out.is_empty() {
        return Err("[instance] forks is empty".to_string());
    }
    out.sort_by_key(|f| f.0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped file: if its shape and this parser drift apart, this fails.
    const LOCAL: &str = include_str!("../../../config/local.toml");

    #[test]
    fn parses_the_environment_file() {
        let c = Config::parse(LOCAL, Path::new("local.toml")).unwrap();
        assert_eq!(
            c.get("lez", "sequencer_url").unwrap(),
            "http://127.0.0.1:3040"
        );
        assert_eq!(c.num("eth", "chain_id").unwrap(), 1);
        assert_eq!(c.get("eth", "network").unwrap(), "mainnet");
        assert_eq!(c.num("instance", "genesis_time").unwrap(), 1606824023);
        assert!(!c.replay());
        assert_eq!(c.num_or("submitter", "poll_seconds", 12).unwrap(), 12);
        assert!(c.get("nope", "x").is_err());
    }

    #[test]
    fn replay_switches_both_endpoints() {
        let t = LOCAL.replace("source = \"live\"", "source = \"replay\"");
        let c = Config::parse(&t, Path::new("x")).unwrap();
        assert_eq!(c.beacon_url().unwrap(), "http://127.0.0.1:5052");
        assert_eq!(c.execution_url().unwrap(), "http://127.0.0.1:5052");
    }

    #[test]
    fn the_instance_is_built_from_the_file_and_is_stable() {
        let c = Config::parse(LOCAL, Path::new("x")).unwrap();
        let a = c.instance_config().unwrap();
        let b = Config::parse(LOCAL, Path::new("y"))
            .unwrap()
            .instance_config()
            .unwrap();
        assert_eq!(a.id(), b.id());
        assert_eq!(a.chain_id, 1);
        assert_eq!(a.committee_size, 512);
        assert_eq!(a.forks.entries()[1], (411392, [0x06, 0, 0, 0]));
        // a different checkpoint is a different instance
        let trusted_root = c.need("instance", "trusted_root").unwrap();
        let other_root = format!("0x{}", "ce".repeat(32));
        let other_text = LOCAL.replace(
            &format!("trusted_root = \"{trusted_root}\""),
            &format!("trusted_root = \"{other_root}\""),
        );
        let other = Config::parse(&other_text, Path::new("z"))
            .unwrap()
            .instance_config()
            .unwrap();
        assert_ne!(a.id(), other.id());
    }

    #[test]
    fn forks_parse_and_order() {
        assert_eq!(
            parse_forks("b:20:0x02000000, a:10:0x01000000").unwrap(),
            vec![(10, [1, 0, 0, 0]), (20, [2, 0, 0, 0])]
        );
        for bad in [
            "",
            "a:10",
            "a:x:0x01000000",
            "a:10:0x0100",
            "a:10:0x01000000:z",
        ] {
            assert!(parse_forks(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_bad_line_names_its_place() {
        assert!(Config::parse("[a]\nnot a pair\n", Path::new("f.toml"))
            .unwrap_err()
            .contains("f.toml:2"));
        assert!(Config::parse("[a\nk = 1\n", Path::new("f.toml"))
            .unwrap_err()
            .contains("f.toml:1"));
    }
}
