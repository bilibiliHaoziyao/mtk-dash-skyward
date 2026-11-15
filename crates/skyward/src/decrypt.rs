//! Opening the data partition and its users' own files on a thread of its
//! own, so the screen keeps up: the keys come from the secure world, and
//! what a user enters at their screen lock is checked slowly on purpose.

use anyhow::Result;
use skyward_binder::driver::Binder;
use skyward_crypto::data::{self, Closed, Opening};
use skyward_crypto::keymint::KeyMint;
use skyward_sys::worker::Worker;
use std::os::fd::RawFd;

pub enum Job {
    /// Open the partition as far as it opens with nothing a user knows.
    Open,
    /// Open the own files of `user` with what they entered at their screen
    /// lock; `closed` are the users whose own files are still closed.
    Unlock { closed: Vec<Closed>, user: u32, credential: Vec<u8> },
}

/// How a job ended: what it opened, or why it did not.
pub enum Ended {
    Opened(Result<Opening, String>),
    Unlocked(Result<Vec<Closed>, String>),
}

/// A job done on a thread of its own, which the screen lets go once the
/// job has ended.
pub struct Decryptor {
    /// Tells how the job ended, once.
    worker: Worker<Ended>,
}

impl Decryptor {
    pub fn start(job: Job) -> Result<Decryptor> {
        let worker = Worker::start("decrypt", move |tell| {
            tell.tell(match job {
                Job::Open => Ended::Opened(with_key_service(data::open_without_credential)),
                Job::Unlock { closed, user, credential } => {
                    Ended::Unlocked(with_key_service(|service| data::unlock(service, &closed, user, &credential)))
                }
            });
        })?;
        Ok(Decryptor { worker })
    }

    /// Readable once the job has ended.
    pub fn fd(&self) -> RawFd {
        self.worker.fd()
    }

    /// How the job ended, once it has.
    pub fn ended(&self) -> Option<Ended> {
        self.worker.events().pop()
    }
}

/// Do `work` with the phone's key service, reached afresh for it, and say
/// why it failed in words for the page.
///
/// v14: from v13 on, the vendor HALs (keymint included) are started on a
/// background thread so the screen comes up at once. That means the moment
/// a user taps "decrypt", keymint has often not registered with the service
/// directory yet. The old code looked it up once, got "not running", and
/// gave up for good, which made decryption fail every single time. Wait a
/// short while for the registration here. This wait runs on this decrypt
/// worker thread, so the screen keeps responding throughout.
pub fn with_key_service<T>(work: impl FnOnce(&KeyMint) -> Result<T>) -> Result<T, String> {
    use std::time::{Duration, Instant};
    const GRACE: Duration = Duration::from_secs(30);
    const GAP: Duration = Duration::from_millis(250);

    let binder = Binder::open().map_err(|e| format!("{e:#}"))?;
    let start = Instant::now();
    let mut tries = 0u32;

    // Only the lookup is retried. `work` runs exactly once, after the
    // service is reached; a genuine key failure is returned as-is and is
    // never retried.
    let service = loop {
        tries += 1;
        match KeyMint::open(&binder) {
            Ok(service) => {
                if tries > 1 {
                    let _ = skyward_sys::kmsg(&format!("v14: key service registered after {tries} tries"));
                }
                break service;
            }
            Err(e) => {
                let why = format!("{e:#}");
                if start.elapsed() >= GRACE {
                    let _ = skyward_sys::kmsg(&format!("v14: key service never registered after {tries} tries: {why}"));
                    return Err(why);
                }
                if tries == 1 {
                    let _ = skyward_sys::kmsg(&format!("v14: waiting for the key service to register: {why}"));
                }
                std::thread::sleep(GAP);
            }
        }
    };

    work(&service).map_err(|e| format!("{e:#}"))
}
