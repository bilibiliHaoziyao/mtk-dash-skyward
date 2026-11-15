//! Giving the phone's own files to the accounts its init gives them.
//!
//! A recovery's ueventd makes the kernel's device nodes root's alone, while
//! the phone's own programs run under the accounts its init scripts name,
//! so the files those programs open are handed over as the phone's init
//! hands them over at boot.

use anyhow::{Context, Result};
use skyward_config::Owners;
use skyward_sys::ueventd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// What handing the files over came to: how many were given to their
/// accounts, and the ones the kernel made none of this boot.
pub struct Given {
    pub handed: usize,
    pub missing: Vec<String>,
}

/// Wait until the kernel has made every node the runs name, or `timeout`
/// has passed: a driver makes its nodes a moment after its module is in,
/// and what opens them cannot until they are there.
pub fn wait_for_nodes(runs: &[Owners], timeout: Duration) {
    let all = |runs: &[Owners]| runs.iter().flat_map(|run| &run.paths).all(|path| Path::new(path).exists());
    let until = Instant::now() + timeout;
    while !all(runs) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Give each of the phone's own files the account and mode its init gives
/// it, as its chown and chmod lines do. A file the kernel made none of on
/// this boot, such as the RPMB unit of a kind of storage the phone does not
/// have, is passed over and named in the answer rather than holding up
/// everything after it.
pub fn give(runs: &[Owners]) -> Result<Given> {
    let known = ueventd::accounts(&ueventd::PASSWD_FILES.iter().chain(&ueventd::GROUP_FILES).copied().collect::<Vec<_>>());
    let id = |name: &str| ueventd::account(&known, name).with_context(|| format!("the phone has no account named {name}"));
    let mut given = Given { handed: 0, missing: Vec::new() };
    for run in runs {
        let (uid, gid) = (id(&run.user)?, id(&run.group)?);
        for path in &run.paths {
            if !Path::new(path).exists() {
                given.missing.push(path.clone());
                continue;
            }
            std::os::unix::fs::chown(path, Some(uid), Some(gid)).with_context(|| format!("give {path} to {}:{}", run.user, run.group))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(run.mode))
                .with_context(|| format!("give {path} the mode {:o}", run.mode))?;
            given.handed += 1;
        }
    }
    Ok(given)
}
