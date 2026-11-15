// The numbering serves the phone's own driver and the host tests.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

#[cfg(target_os = "android")]
use crate::parcel::Parcel;
#[cfg(target_os = "android")]
use crate::status;
use anyhow::{Context, Result};

/// The directory every program registers with and looks things up in.
const DIRECTORY: &str = "android.os.IServiceManager";

/// What the directory numbers the methods it is asked by here. It numbers
/// its methods in the order its interface declares them, and Android 16
/// declared two lookups of its own ahead of the rest; the directory is the
/// recovery's own program, so the version the recovery was built as says
/// which numbering it keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Methods {
    /// Ask for a service without waiting for one that has not registered
    /// yet.
    check_service: u32,
    /// Register a service.
    add_service: u32,
    /// List the names registered at the dump priorities given.
    list_services: u32,
    /// Ask whether the phone says it has a service, whether or not it is
    /// running.
    is_declared: u32,
}

/// The first version of Android whose directory declares the two lookups.
const LOOKUPS_DECLARED: u32 = 36;

/// How the directory of a recovery built as Android version `sdk` numbers
/// its methods.
fn methods_of(sdk: u32) -> Methods {
    match sdk >= LOOKUPS_DECLARED {
        true => Methods { check_service: 3, add_service: 5, list_services: 6, is_declared: 9 },
        false => Methods { check_service: 2, add_service: 3, list_services: 4, is_declared: 7 },
    }
}

/// The recovery's own version, which its property files give.
const SDK: &str = "ro.build.version.sdk";

/// Both numberings the directory has kept, the older first.
#[cfg(target_os = "android")]
const NUMBERINGS: [Methods; 2] = [
    Methods { check_service: 2, add_service: 3, list_services: 4, is_declared: 7 },
    Methods { check_service: 3, add_service: 5, list_services: 6, is_declared: 9 },
];

/// Which numbering this phone's directory keeps.
///
/// The property files a recovery carries say which version it was built as,
/// and that is not the version the phone runs: a recovery made by someone
/// else, or one built for an older Android and put on a newer phone, brings
/// its own `ro.build.version.sdk` with it while the directory it talks to is
/// the phone's own. Reading the numbering off that property then asks the
/// directory for a method it does not have, and every lookup comes back
/// refused.
///
/// So the numbering is asked of the directory itself: the two odd numbers a
/// lookup and a registration answer to are tried against a name it has to
/// know, its own, and the one that answers both is kept. Only where neither
/// does is the property's guess used, which is where the call itself should
/// say what the directory answered.
#[cfg(target_os = "android")]
fn methods(directory: &crate::driver::Handle) -> Result<Methods> {
    use std::sync::OnceLock;
    static CHOSEN: OnceLock<Methods> = OnceLock::new();
    if let Some(chosen) = CHOSEN.get() {
        return Ok(*chosen);
    }
    let guessed = skyward_sys::prop(SDK).and_then(|sdk| sdk.parse().ok()).map_or(NUMBERINGS[0], methods_of);
    let other = if guessed == NUMBERINGS[0] { NUMBERINGS[1] } else { NUMBERINGS[0] };
    for candidate in [guessed, other] {
        if answers(directory, &candidate) {
            let _ = CHOSEN.set(candidate);
            return Ok(candidate);
        }
    }
    Ok(guessed)
}

/// Whether `directory` answers to `m`: it knows its own name, and hands
/// itself over when asked for by it. Another numbering's numbers reach
/// methods that read the call differently, and one of them answers neither.
#[cfg(target_os = "android")]
fn answers(directory: &crate::driver::Handle, m: &Methods) -> bool {
    let mut call = Parcel::call(DIRECTORY);
    call.string(DIRECTORY);
    if let Ok(reply) = directory.transact(m.is_declared, &call) {
        let mut read = reply.read();
        if status::ok(&mut read).is_ok() && read.bool().unwrap_or(false) {
            let mut call = Parcel::call(DIRECTORY);
            call.string(DIRECTORY);
            if let Ok(reply) = directory.transact(m.check_service, &call) {
                let mut read = reply.read();
                return status::ok(&mut read).is_ok() && matches!(read.object(), Ok(Some(_)));
            }
        }
    }
    false
}

/// Every dump priority a service can register at, and the one a service
/// registers at that asks for none.
const DUMP_PRIORITY_ALL: i32 = 0b1111;
const DUMP_PRIORITY_DEFAULT: i32 = 0b1000;

/// Ask any object which process serves it. libbinder answers this itself,
/// for every object, before any interface sees the call.
const DEBUG_PID: u32 = u32::from_be_bytes(*b"_PID");

/// Ask any object which interface it serves, which libbinder answers the
/// same way.
const INTERFACE: u32 = u32::from_be_bytes(*b"_NTF");

/// Ask a service which version of its interface it serves. Every service
/// of the newer kind answers this, numbered from the top of the range its
/// own methods are numbered from the bottom of.
const INTERFACE_VERSION: u32 = 0x00ff_ffff;

/// Which version of `interface` a service serves. It answers this only
/// once it has taken the call as one for that interface, so a service that
/// will not answer it is one that turns the call away before reading
/// anything of what it carries.
#[cfg(target_os = "android")]
pub fn version(service: &crate::driver::Handle, interface: &str) -> Result<i32> {
    let what = format!("ask which version of {interface} is served");
    let reply = service.transact(INTERFACE_VERSION, &Parcel::call(interface)).with_context(|| what.clone())?;
    let mut read = reply.read();
    status::ok(&mut read).with_context(|| what.clone())?;
    read.i32().with_context(|| what)
}

/// The service registered under `name`, or `None` while nothing has
/// registered it.
#[cfg(target_os = "android")]
pub fn find<'a>(binder: &'a crate::driver::Binder, name: &str) -> Result<Option<crate::driver::Handle<'a>>> {
    let directory = binder.directory()?;
    let mut call = Parcel::call(DIRECTORY);
    call.string(name);
    let reply = directory.transact(methods(&directory)?.check_service, &call).with_context(|| format!("look up {name}"))?;
    let mut read = reply.read();
    status::ok(&mut read).with_context(|| format!("look up {name}"))?;
    match read.object().with_context(|| format!("read what the directory answered for {name}"))? {
        Some(handle) => Ok(Some(crate::driver::Handle::hold(binder, handle)?)),
        None => Ok(None),
    }
}

/// Register the object this program serves under `number`, through
/// `binder`, as the service `name`: for every program to find, none of
/// them in a sandbox, at no dump priority of its own. The directory takes
/// a hardware service only where the phone's description names it.
#[cfg(target_os = "android")]
pub fn add(binder: &crate::driver::Binder, name: &str, number: u64) -> Result<()> {
    let directory = binder.directory()?;
    let mut call = Parcel::call(DIRECTORY);
    call.string(name);
    call.object(number);
    call.bool(false);
    call.i32(DUMP_PRIORITY_DEFAULT);
    let reply = directory.transact(methods(&directory)?.add_service, &call).with_context(|| format!("register {name}"))?;
    status::ok(&mut reply.read()).with_context(|| format!("register {name}"))
}

/// Every name registered with the directory, the directory's own among
/// them.
#[cfg(target_os = "android")]
pub fn names(binder: &crate::driver::Binder) -> Result<Vec<String>> {
    let directory = binder.directory()?;
    let mut call = Parcel::call(DIRECTORY);
    call.i32(DUMP_PRIORITY_ALL);
    let reply = directory.transact(methods(&directory)?.list_services, &call).context("list what has registered")?;
    let mut read = reply.read();
    status::ok(&mut read).context("list what has registered")?;
    let count = read.i32().context("read how many have registered")?;
    anyhow::ensure!(count >= 0, "the directory says {count} have registered");
    (0..count).map(|_| read.string().context("read a registered name")).collect()
}

/// The process that serves an object.
#[cfg(target_os = "android")]
pub fn pid(service: &crate::driver::Handle) -> Result<u32> {
    let reply = service.transact(DEBUG_PID, &Parcel::default()).context("ask which process serves an object")?;
    let pid = reply.read().i32().context("read which process serves an object")?;
    u32::try_from(pid).with_context(|| format!("an object says process {pid} serves it"))
}

/// The interface an object serves, by its full name.
#[cfg(target_os = "android")]
pub fn interface(service: &crate::driver::Handle) -> Result<String> {
    let reply = service.transact(INTERFACE, &Parcel::default()).context("ask which interface an object serves")?;
    reply.read().string().context("read which interface an object serves")
}

/// Whether the phone's own description says it has this service. The
/// directory turns away a hardware service the description does not name,
/// so a service that will not register is often one the directory cannot
/// see described.
#[cfg(target_os = "android")]
pub fn declared(binder: &crate::driver::Binder, name: &str) -> Result<bool> {
    let directory = binder.directory()?;
    let mut call = Parcel::call(DIRECTORY);
    call.string(name);
    let reply = directory.transact(methods(&directory)?.is_declared, &call).with_context(|| format!("ask whether {name} is described"))?;
    let mut read = reply.read();
    status::ok(&mut read).with_context(|| format!("ask whether {name} is described"))?;
    read.bool().with_context(|| format!("read whether {name} is described"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The positions of getService, checkService, addService, listServices,
    /// registerForNotifications, unregisterForNotifications and isDeclared
    /// in IServiceManager.aidl, and of the two lookups Android 16 put after
    /// the first and the second of them.
    #[test]
    fn the_directory_of_android_16_numbers_its_methods_two_and_four_further_on() {
        assert_eq!(methods_of(33), Methods { check_service: 2, add_service: 3, list_services: 4, is_declared: 7 }, "the 13 Ultra's recovery");
        assert_eq!(methods_of(35), methods_of(33));
        assert_eq!(methods_of(36), Methods { check_service: 3, add_service: 5, list_services: 6, is_declared: 9 }, "the 17 Ultra's recovery");
        assert_eq!(methods_of(37), methods_of(36));
    }
}
