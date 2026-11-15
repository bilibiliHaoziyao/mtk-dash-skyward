use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use skyward_config::ramdisk as paths;
use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

mod avb;
mod described;

use skyward_bootimg::{BootImage, Ramdisk, VendorBoot as VendorBootImage, VendorRamdisk};

/// Builds Skyward recovery images from a device's own stock images.
#[derive(Parser)]
#[command(name = "skyward-pack")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print an image's header and the files in its ramdisk.
    List { image: PathBuf },
    /// Write one ramdisk file to stdout.
    Cat { image: PathBuf, path: String },
    /// Unpack and pack an image's ramdisk unchanged, to check that a rebuilt
    /// archive keeps every entry.
    Repack { image: PathBuf, out: PathBuf },
    /// Join a kernel and another image's ramdisk into one boot image.
    Boot {
        /// Image holding the kernel (the device's boot partition).
        #[arg(long)]
        kernel: PathBuf,
        /// Image holding the ramdisk.
        #[arg(long)]
        ramdisk: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Build a Skyward recovery image on top of the device's stock recovery:
    /// its init, adbd, SELinux policy and libraries stay, the recovery
    /// service becomes Skyward. The image fills the whole partition and ends
    /// in an unsigned AVB footer of its own.
    Recovery {
        /// The device's stock recovery image: the whole partition, as the
        /// phone or a full update package holds it, ending in its AVB footer.
        #[arg(long)]
        stock: PathBuf,
        /// Skyward built for the device (aarch64-linux-android).
        #[arg(long)]
        binary: PathBuf,
        /// The first program of a system installed beside the installed
        /// one, skyward-system-init built for the device and linked
        /// statically.
        #[arg(long)]
        system_init: PathBuf,
        /// The device configuration, devices/<codename>.toml.
        #[arg(long)]
        config: PathBuf,
        /// The UI typeface.
        #[arg(long)]
        font: PathBuf,
        /// The terminal's monospaced typeface.
        #[arg(long)]
        mono: PathBuf,
        /// The monospaced typeface's licence, which goes with it.
        #[arg(long)]
        mono_license: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Build a Skyward recovery image for a device whose recovery lives in
    /// its vendor boot partition: the stock image keeps its platform
    /// ramdisk, recompressed where zstd is smaller, the recovery ramdisk of
    /// a custom recovery becomes the rootfs Skyward runs from, and the
    /// image fills the whole partition and ends in an unsigned AVB footer
    /// of its own.
    VendorBoot {
        /// The device's stock vendor boot image: the whole partition, as
        /// the full update package holds it.
        #[arg(long)]
        stock: PathBuf,
        /// A vendor boot image of a custom recovery built for the device,
        /// whose recovery ramdisk gives the rootfs to build on.
        #[arg(long)]
        rootfs: PathBuf,
        /// Skyward built for the device (aarch64-linux-android).
        #[arg(long)]
        binary: PathBuf,
        /// The first program of a system installed beside the installed
        /// one, skyward-system-init built for the device and linked
        /// statically.
        #[arg(long)]
        system_init: PathBuf,
        /// The device configuration, devices/<codename>.toml.
        #[arg(long)]
        config: PathBuf,
        /// The UI typeface.
        #[arg(long)]
        font: PathBuf,
        /// The terminal's monospaced typeface.
        #[arg(long)]
        mono: PathBuf,
        /// The monospaced typeface's licence, which goes with it.
        #[arg(long)]
        mono_license: PathBuf,
        /// Path prefixes to take out of the rootfs, where a folder holds
        /// what Skyward draws itself. Each names a whole tree.
        #[arg(long = "drop", default_value = "twres/")]
        drop_prefixes: Vec<String>,
        /// Kernel modules to add to the platform ramdisk, where the
        /// recovery reads them from /lib/modules. Drivers the stock build
        /// keeps on vendor_dlkm belong here when the recovery needs them
        /// before that partition is mounted, the touchscreen's among them.
        #[arg(long = "module")]
        modules: Vec<PathBuf>,
        /// Programs init starts beside the recovery, for the parts of the
        /// phone the recovery's own programs are not enough for: the
        /// reporter that turns the touchscreen driver's character device
        /// into input events, on a phone whose touch is not evdev. Each is
        /// a shell script in the rootfs, run once at boot.
        #[arg(long = "start")]
        start: Vec<String>,
        /// The level zstd compresses the ramdisks at.
        #[arg(long, default_value_t = 19)]
        zstd_level: i32,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the stock build a device's recovery is made on, as lines of
    /// name=value: its version, where its full update package is, and the
    /// SHA-256 of the recovery partition in that package. Given somewhere
    /// to write it, also take that partition out of the package on its
    /// server, reading only what the partition takes, and write it there
    /// once its SHA-256 is that one.
    Stock {
        /// The device configuration, devices/<codename>.toml.
        #[arg(long)]
        config: PathBuf,
        /// Where to write the stock recovery image.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Take what a device's own partitions say of the programs they carry
    /// out of its stock build's full update package on its server: the
    /// init scripts, the service descriptions, the accounts and the build
    /// properties of each partition that carries such programs, written
    /// under `out` as the partition and then the path in it. Only the
    /// parts of the package that hold these files are downloaded, each
    /// checked against the package's own sum of it.
    Described {
        /// The device configuration, devices/<codename>.toml.
        #[arg(long)]
        config: PathBuf,
        /// A partition to take them out of; vendor, odm and system_ext
        /// when none is named.
        #[arg(long = "partition")]
        partitions: Vec<String>,
        /// The folder to write the files under, which is not there yet.
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::List { image } => list(&image),
        Cmd::Cat { image, path } => {
            let rd = Ramdisk::decode(&BootImage::read(&image)?.ramdisk)?;
            let e = rd.find(&path).with_context(|| format!("{path} is not in the ramdisk"))?;
            std::io::stdout().write_all(&e.data)?;
            Ok(())
        }
        Cmd::Repack { image, out } => {
            let mut img = BootImage::read(&image)?;
            img.ramdisk = Ramdisk::decode(&img.ramdisk)?.encode()?;
            write(&out, &img, &img.to_bytes()?)
        }
        Cmd::Boot { kernel, ramdisk, out } => {
            let mut img = BootImage::read(&ramdisk)?;
            img.kernel = BootImage::read(&kernel)?.kernel;
            write(&out, &img, &img.to_bytes()?)
        }
        Cmd::Recovery { stock, binary, system_init, config, font, mono, mono_license, out } => {
            let size = partition_size(&stock)?;
            let mut img = BootImage::read(&stock)?;
            let mut rd = Ramdisk::decode(&img.ramdisk)?;
            // A stock recovery ramdisk has no third-party tree; refuse to build
            // on top of another custom recovery.
            if let Some(e) = rd.entries.iter().find(|e| e.name == "FFiles" || e.name.starts_with("twres")) {
                anyhow::bail!("{} holds {}, which is not a stock recovery", stock.display(), e.name);
            }
            let read = |p: &PathBuf| std::fs::read(p).with_context(|| format!("read {}", p.display()));
            skyward_config::DeviceConfig::load(&config)?;
            inject_recovery(&mut rd, &read(&binary)?, &read(&system_init)?, &read(&config)?, &read(&font)?, &read(&mono)?, &read(&mono_license)?, &[])?;
            img.ramdisk = rd.encode()?;
            let bytes = img.to_bytes()?;
            write(&out, &img, &avb::footed(&bytes, "recovery", size, &Sha256::digest(&bytes))?)
        }
        Cmd::VendorBoot { stock, rootfs, binary, system_init, config, font, mono, mono_license, drop_prefixes, modules, start, zstd_level, out } => {
            vendor_boot(&stock, &rootfs, &binary, &system_init, &config, &font, &mono, &mono_license, &drop_prefixes, &modules, &start, zstd_level, &out)
        }
        Cmd::Stock { config, out } => {
            let stock = skyward_config::DeviceConfig::load(&config)?.stock.with_context(|| format!("{} names no stock build", config.display()))?;
            println!("version={}\npackage={}\nrecovery={}", stock.version, stock.package, stock.recovery);
            match out {
                Some(out) => take_stock_recovery(&stock, &out),
                None => Ok(()),
            }
        }
        Cmd::Described { config, partitions, out } => {
            let stock = skyward_config::DeviceConfig::load(&config)?.stock.with_context(|| format!("{} names no stock build", config.display()))?;
            let partitions = if partitions.is_empty() { skyward_programs::phone::PARTITIONS.map(str::to_string).to_vec() } else { partitions };
            described::take(&stock.package, &partitions, &out)
        }
    }
}

/// The partition a recovery is made on, as a full update package names it.
const RECOVERY: &str = "recovery";

/// Put Skyward into a recovery ramdisk, however the device holds it: the
/// recovery service becomes Skyward, the commands install scripts look for
/// become links to it, the configuration, the typefaces and the first
/// program of an installed system join them, and the properties a locked
/// recovery needs are set.
fn inject_recovery(
    rd: &mut Ramdisk,
    binary: &[u8],
    system_init: &[u8],
    config: &[u8],
    font: &[u8],
    mono: &[u8],
    mono_license: &[u8],
    start: &[String],
) -> Result<()> {
    rd.replace(paths::RECOVERY, binary.to_vec())?;
    // Install scripts look for the commands a stock recovery lacks
    // among its programs, and its unzip there too, a link to ziptool
    // until it points here; the recovery binary is each of them. A
    // rootfs taken from a custom recovery may hold some of them as
    // programs of its own, which the links take the place of.
    let (_, recovery) = paths::RECOVERY.rsplit_once('/').expect("the recovery binary is in a folder");
    for command in paths::COMMANDS {
        rd.force_link(command, recovery)?;
    }
    rd.add(paths::SYSTEM_INIT, 0o755, system_init.to_vec())?;
    rd.add(paths::CONFIG, 0o644, config.to_vec())?;
    rd.add(paths::FONT, 0o644, font.to_vec())?;
    rd.add(paths::MONO, 0o644, mono.to_vec())?;
    rd.add(paths::MONO_LICENSE, 0o644, mono_license.to_vec())?;
    // A stock ramdisk may run logd without any scheduling profiles,
    // and logd stops as soon as it cannot find the one it asks for.
    if rd.find(paths::TASK_PROFILES).is_none() {
        rd.add(paths::TASK_PROFILES, 0o644, TASK_PROFILES.to_vec())?;
    }
    rd.add(paths::MTP_RC, 0o644, MTP_RC.to_vec())?;
    // A custom recovery's init starts its recovery service with no
    // arguments, since that recovery's own binary takes none; Skyward takes
    // the mode it runs in as a subcommand, and without it the binary stops
    // before it draws anything. The service line is made to name it.
    for service_rc in [SERVICE_RC, SERVICE_RC_LEGACY] {
        let Some(entry) = rd.find(service_rc) else { continue };
        let text = String::from_utf8_lossy(&entry.data).into_owned();
        let from = format!("service recovery /{}", paths::RECOVERY);
        let to = format!("service recovery /{} recovery", paths::RECOVERY);
        if text.contains(&from) && !text.contains(&to) {
            rd.replace(service_rc, text.replace(&from, &to).into_bytes())?;
            println!("the recovery service starts Skyward in its recovery mode");
        } else {
            println!("the recovery service in {service_rc} already names its mode, or says something else");
        }
    }
    // A phone whose touchscreen is not an evdev device has a program of its
    // own that turns the driver's character device into input events, and
    // a script that starts it once the driver is up. That script is not one
    // of the recovery's programs, and nothing else in the rootfs starts it:
    // the custom recovery its init comes from runs it from its own binary.
    // Init runs it here instead, once, at boot.
    if !start.is_empty() {
        for service_rc in [SERVICE_RC, SERVICE_RC_LEGACY] {
            let Some(entry) = rd.find(service_rc) else { continue };
            let mut text = String::from_utf8_lossy(&entry.data).into_owned();
            if !text.ends_with('\n') {
                text.push('\n');
            }
            for (at, script) in start.iter().enumerate() {
                let name = format!("skyward-start-{at}");
                if text.contains(&format!("service {name} ")) {
                    continue;
                }
                text.push_str(&format!(
                    // A service section only says what the program is; what
                    // starts it is a command under a trigger. Without one the
                    // program is never run, which is what kept the touch
                    // reporter from ever starting.
                    "\non boot\n    start {name}\n\nservice {name} /system/bin/sh {script}\n    user root\n    oneshot\n    seclabel u:r:recovery:s0\n"
                ));
                println!("init starts {script} beside the recovery");
            }
            rd.replace(service_rc, text.into_bytes())?;
            break;
        }
    }
    // On an unlocked device adbd keeps root when ro.secure is 0 and
    // lets any computer in without authorization when ro.adb.secure is
    // 0; init lets a later line of a property file override an earlier
    // one. update_engine refuses a package built before the recovery
    // itself unless both of the last two are set; the recovery checks
    // packages against the installed system instead.
    let stock_props = &rd
        .find(paths::PROP_DEFAULT)
        .with_context(|| format!("{} is not in the ramdisk", paths::PROP_DEFAULT))?
        .data;
    let mut props = without(stock_props, &BUILD_VERSION);
    props.extend_from_slice(b"\nro.secure=0\nro.adb.secure=0\nro.debuggable=1\nro.ota.allow_downgrade=true\n");
    rd.replace(paths::PROP_DEFAULT, props)?;
    Ok(())
}

/// Build a Skyward recovery image in the vendor boot partition of a device
/// whose recovery lives there: the stock platform ramdisk stays, recompressed
/// where zstd holds it smaller, and the recovery ramdisk becomes the rootfs
/// Skyward runs from, taken from a custom recovery built for the device.
fn vendor_boot(
    stock: &Path,
    rootfs: &Path,
    binary: &PathBuf,
    system_init: &PathBuf,
    config: &PathBuf,
    font: &PathBuf,
    mono: &PathBuf,
    mono_license: &PathBuf,
    drop_prefixes: &[String],
    modules: &[PathBuf],
    start: &[String],
    zstd_level: i32,
    out: &Path,
) -> Result<()> {
    let partition_size = usize::try_from(fs::metadata(stock).with_context(|| format!("stat {}", stock.display()))?.len())?;
    let stock_img = VendorBootImage::read(stock)?;
    let rootfs_img = VendorBootImage::read(rootfs)?;
    let base = rootfs_img
        .recovery()
        .with_context(|| format!("{} holds no recovery ramdisk", rootfs.display()))?;
    let (mut rd, _) = Ramdisk::decode_any(&base.blob)?;
    let read = |p: &PathBuf| std::fs::read(p).with_context(|| format!("read {}", p.display()));
    skyward_config::DeviceConfig::load(config)?;
    inject_recovery(&mut rd, &read(binary)?, &read(system_init)?, &read(config)?, &read(font)?, &read(mono)?, &read(mono_license)?, start)?;
    for prefix in drop_prefixes {
        let taken: usize = rd.entries.iter().filter(|e| e.name.starts_with(prefix.as_str())).count();
        rd.entries.retain(|e| !e.name.starts_with(prefix.as_str()));
        println!("took {} entries of {} out of the rootfs", taken, prefix);
    }
    let rootfs_blob = rd.encode_zstd(zstd_level)?;
    println!(
        "the recovery ramdisk: {} bytes in, {} entries, {} bytes out at zstd level {}",
        base.blob.len(),
        rd.entries.len(),
        rootfs_blob.len(),
        zstd_level
    );
    // The stock platform ramdisk stays what it was, held however zstd
    // holds it smaller: the bootloader reads zstd ramdisks, as the custom
    // recovery the rootfs came from proves.
    let mut entries = Vec::with_capacity(stock_img.entries.len());
    for e in &stock_img.entries {
        if e.is_recovery() {
            entries.push(VendorRamdisk { name: e.name.clone(), kind: e.kind, blob: rootfs_blob.clone() });
        } else {
            let (mut plain, _) = Ramdisk::decode_any(&e.blob)?;
            if e.is_platform() {
                add_modules(&mut plain, modules)?;
            }
            let plain = plain.archive()?;
            let compressed = zstd::stream::encode_all(&plain[..], zstd_level).context("zstd encode")?;
            println!("the ramdisk {:?}: {} bytes in, {} bytes out at zstd level {}", e.name, e.blob.len(), compressed.len(), zstd_level);
            entries.push(VendorRamdisk { name: e.name.clone(), kind: e.kind, blob: compressed });
        }
    }
    let img = VendorBootImage {
        page_size: stock_img.page_size,
        kernel_addr: stock_img.kernel_addr,
        ramdisk_addr: stock_img.ramdisk_addr,
        tags_addr: stock_img.tags_addr,
        dtb_addr: stock_img.dtb_addr,
        cmdline: stock_img.cmdline.clone(),
        name: stock_img.name.clone(),
        dtb: stock_img.dtb.clone(),
        bootconfig: stock_img.bootconfig.clone(),
        entries,
    };
    let bytes = img.to_bytes()?;
    let bytes = avb::footed(&bytes, "vendor_boot", partition_size, &Sha256::digest(&bytes))?;
    std::fs::write(out, bytes).with_context(|| format!("write {}", out.display()))?;
    println!("wrote {} ({} bytes, the partition holds {})", out.display(), fs::metadata(out)?.len(), partition_size);
    Ok(())
}

/// Put the modules the build adds into the platform ramdisk's /lib/modules,
/// where the recovery reads them from. The stock `modules.dep` keeps naming
/// only the stock modules, so the configuration names these in the order
/// their dependencies need them in.
fn add_modules(rd: &mut Ramdisk, modules: &[PathBuf]) -> Result<()> {
    for path in modules {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .with_context(|| format!("{} has no file name", path.display()))?;
        ensure!(name.ends_with(".ko"), "{} is not a kernel module", path.display());
        let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let bytes = data.len();
        rd.add(&format!("lib/modules/{name}"), 0o644, data)?;
        println!("added {name} to the platform ramdisk ({bytes} bytes)");
    }
    Ok(())
}

/// Take the recovery partition out of the stock build's full update package
/// on its server, reading only what that partition takes of it, and write it
/// to `out` once its SHA-256 is the one the configuration names.
fn take_stock_recovery(stock: &skyward_config::Stock, out: &Path) -> Result<()> {
    let parent = out.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).with_context(|| format!("make {}", parent.display()))?;
    // Taken out beside where it goes, so it is moved there whole.
    let work = tempfile::Builder::new().prefix(".stock").tempdir_in(parent).with_context(|| format!("make a folder in {}", parent.display()))?;
    let payload = unpayload::Payload::open_url(&stock.package).with_context(|| format!("open {}", stock.package))?;
    let options = unpayload::ExtractOptions { output_dir: work.path().to_path_buf(), partitions: vec![RECOVERY.into()], ..Default::default() };
    let report = |event: unpayload::Event<'_>| match event {
        unpayload::Event::Started { partitions } => {
            for (name, bytes) in partitions {
                println!("taking {name} out of the package: {bytes} bytes");
            }
        }
        unpayload::Event::Extracted(image) => println!("took {} out: {} bytes", image.partition, image.size),
        unpayload::Event::Progress { .. } => {}
    };
    let taken = payload.extract(&options, &report).with_context(|| format!("take {RECOVERY} out of {}", stock.package))?;
    let image = taken.iter().find(|i| i.partition == RECOVERY).with_context(|| format!("{} holds no {RECOVERY} partition", stock.package))?;
    let sum = hex::encode(image.sha256.as_deref().context("the package's own sum of the image was not checked")?);
    ensure!(sum == stock.recovery, "the {RECOVERY} partition in {} has the SHA-256 {sum}, where the configuration names {}", stock.package, stock.recovery);
    std::fs::rename(&image.path, out).with_context(|| format!("move {} to {}", image.path.display(), out.display()))?;
    println!("wrote {} ({} bytes), its SHA-256 the one the configuration names", out.display(), image.size);
    Ok(())
}

/// The size of the partition `stock` fills: all of it, as the phone and a
/// full update package hold it, which its AVB footer ends.
fn partition_size(stock: &Path) -> Result<usize> {
    let mut file = File::open(stock).with_context(|| format!("open {}", stock.display()))?;
    let size = file.metadata().with_context(|| format!("stat {}", stock.display()))?.len();
    let mut magic = [0u8; 4];
    if size >= 64 {
        file.seek(SeekFrom::Start(size - 64)).with_context(|| format!("seek in {}", stock.display()))?;
        file.read_exact(&mut magic).with_context(|| format!("read {}", stock.display()))?;
    }
    ensure!(
        &magic == b"AVBf",
        "{} does not end in an AVB footer; give the whole recovery partition, as the phone or a full update package holds it",
        stock.display()
    );
    Ok(usize::try_from(size)?)
}

/// What a recovery image says about the build it is: the version and patch
/// levels of its own ramdisk's system and vendor partition, which are older
/// than those installed beside it whenever the phone has taken an update.
/// The phone's secure services read these to tell the secure world which
/// build is running, and keys the installed system made are refused when
/// they say the wrong one, so they are left out here for the recovery to
/// fill in from the installed system once it has that mounted.
const BUILD_VERSION: [&str; 3] = ["ro.build.version.release", "ro.build.version.security_patch", "ro.vendor.build.security_patch"];

/// The scheduling profiles a recovery's programs look up by name. A
/// recovery's cgroup setup mounts no controllers, so of all a system's
/// profiles do, only the timer slack applies here.
const TASK_PROFILES: &[u8] = include_bytes!("task_profiles.json");

/// The init rules that give the USB port file transfer beside adb, which a
/// stock recovery does not offer.
const MTP_RC: &[u8] = include_bytes!("mtp.rc");

/// Where a recovery's init defines the service that runs its own binary:
/// under the hardware folder from Android 11 on, at the root before that.
const SERVICE_RC: &str = "system/etc/init/hw/init.recovery.service.rc";
const SERVICE_RC_LEGACY: &str = "init.recovery.service.rc";

/// A property file without the lines that set any of `names`.
fn without(props: &[u8], names: &[&str]) -> Vec<u8> {
    let mut out = Vec::with_capacity(props.len());
    for line in props.split_inclusive(|b| *b == b'\n') {
        let key = line.split(|b| *b == b'=').next().unwrap_or_default();
        if !names.iter().any(|n| n.as_bytes() == key) {
            out.extend_from_slice(line);
        }
    }
    out
}

/// Write `bytes`, the image `img` makes, to `out`.
fn write(out: &Path, img: &BootImage, bytes: &[u8]) -> Result<()> {
    std::fs::write(out, bytes).with_context(|| format!("write {}", out.display()))?;
    println!(
        "wrote {} ({} bytes kernel, {} bytes ramdisk, {} bytes in all)",
        out.display(),
        img.kernel.len(),
        img.ramdisk.len(),
        bytes.len()
    );
    Ok(())
}

fn list(image: &Path) -> Result<()> {
    let img = BootImage::read(image)?;
    let h = &img.header;
    println!(
        "header v{}  kernel {} bytes  ramdisk {} bytes  {:?}",
        h.header_version(),
        img.kernel.len(),
        img.ramdisk.len(),
        h.osversionpatch
    );
    if img.ramdisk.is_empty() {
        return Ok(());
    }
    let rd = Ramdisk::decode(&img.ramdisk)?;
    for e in &rd.entries {
        println!("{:06o} {:>5}:{:<5} {:>10}  {}", e.mode, e.uid, e.gid, e.data.len(), e.name);
    }
    println!("{} entries", rd.entries.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lines_that_set_a_name_are_the_only_ones_left_out() {
        let props = b"ro.build.id=TQ\nro.build.version.release=13\nro.build.version.release_or_codename=13\nro.product.name=ishtar\n\
ro.vendor.build.security_patch=2026-10-01\nro.vendor.build.security_patch_level=1\n";
        let out = without(props, &BUILD_VERSION);
        let text = String::from_utf8(out).expect("property files are text");
        assert!(!text.contains("ro.build.version.release=13"));
        assert!(!text.contains("ro.vendor.build.security_patch=2026-10-01"), "the vendor partition's patch level is left out too");
        assert!(text.contains("ro.build.version.release_or_codename=13"), "a longer name is left alone");
        assert!(text.contains("ro.vendor.build.security_patch_level=1"), "a longer name is left alone");
        assert!(text.contains("ro.build.id=TQ") && text.contains("ro.product.name=ishtar"));
    }

    #[test]
    fn the_profiles_name_all_the_recovery_asks_for() {
        let profiles: serde_json::Value = serde_json::from_slice(TASK_PROFILES).expect("the profiles are JSON");
        let names = |key: &str| -> Vec<String> {
            profiles[key].as_array().expect("a list").iter().map(|p| p["Name"].as_str().expect("a name").to_string()).collect()
        };
        let (plain, aggregate) = (names("Profiles"), names("AggregateProfiles"));
        // What libprocessgroup asks for when a program sets its scheduling
        // policy, and what the recovery's own init scripts give logd.
        let asked = [
            "SCHED_SP_DEFAULT",
            "SCHED_SP_BACKGROUND",
            "SCHED_SP_FOREGROUND",
            "SCHED_SP_TOP_APP",
            "SCHED_SP_SYSTEM",
            "SCHED_SP_RT_APP",
            "CPUSET_SP_DEFAULT",
            "CPUSET_SP_BACKGROUND",
            "CPUSET_SP_FOREGROUND",
            "CPUSET_SP_TOP_APP",
            "CPUSET_SP_SYSTEM",
            "CPUSET_SP_RESTRICTED",
            "BlkIOBackground",
            "BlkIOForeground",
            "ServiceCapacityLow",
        ];
        for name in asked {
            assert!(plain.iter().chain(&aggregate).any(|n| n == name), "{name} is missing");
        }
        for a in profiles["AggregateProfiles"].as_array().expect("a list") {
            for part in a["Profiles"].as_array().expect("a list") {
                let part = part.as_str().expect("a name");
                assert!(plain.iter().any(|n| n == part), "{} is made of {part}, which is not a profile", a["Name"]);
            }
        }
    }

    #[test]
    fn the_partition_is_as_large_as_a_stock_image_ending_in_its_footer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.img");
        let mut whole = vec![0u8; 8192];
        whole[8192 - 64..8192 - 60].copy_from_slice(b"AVBf");
        std::fs::write(&path, &whole).unwrap();
        assert_eq!(partition_size(&path).unwrap(), 8192);
        std::fs::write(&path, &whole[..8000]).unwrap();
        assert!(partition_size(&path).is_err(), "an image cut short of its partition's end");
        std::fs::write(&path, b"AVBf").unwrap();
        assert!(partition_size(&path).is_err(), "too short to end in a footer");
    }

    #[test]
    fn a_file_without_a_last_newline_keeps_its_last_line() {
        let out = without(b"a=1\nro.build.version.release=13", &BUILD_VERSION);
        assert_eq!(out, b"a=1\n");
        let kept = without(b"a=1\nb=2", &BUILD_VERSION);
        assert_eq!(kept, b"a=1\nb=2");
    }
}
