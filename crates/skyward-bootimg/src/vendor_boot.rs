//! A vendor boot image with header version 4, the one a device without a
//! recovery partition keeps its recovery programs in: read, changed and
//! written again by the image packer on a computer. Its vendor ramdisks sit
//! in a table the bootloader reads: the platform ramdisk always joins the
//! boot ramdisk, the recovery ramdisk only when the phone starts into
//! recovery or fastboot, and each may be compressed however the bootloader
//! reads.

use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::Path;

const MAGIC: &[u8; 8] = b"VNDRBOOT";
/// The vendor boot image header of version 4, as bootimg.h lays it out.
const HEADER_LEN: usize = 2128;
/// A table entry: sizes, offsets and the name of one ramdisk.
const TABLE_ENTRY_LEN: usize = 108;
const NAME_LEN: usize = 32;
const BOARD_ID_LEN: usize = 16;

/// Ramdisk types of the vendor ramdisk table, as bootimg.h names them.
pub const TYPE_PLATFORM: u32 = 1;
pub const TYPE_RECOVERY: u32 = 2;
pub const TYPE_DLKM: u32 = 3;

/// One vendor ramdisk of the table: its blob as the image holds it,
/// compressed as it was.
#[derive(Clone)]
pub struct Entry {
    pub name: String,
    pub kind: u32,
    pub blob: Vec<u8>,
}

impl Entry {
    pub fn is_recovery(&self) -> bool {
        self.kind == TYPE_RECOVERY
    }

    /// The platform ramdisk: the one the bootloader always joins the boot
    /// ramdisk with, holding the modules and firmware the kernel needs
    /// before any partition is mounted.
    pub fn is_platform(&self) -> bool {
        self.kind == TYPE_PLATFORM
    }
}

/// A vendor boot image split into its header, its vendor ramdisks and the
/// device tree blob beside them.
pub struct VendorBoot {
    pub page_size: u32,
    pub kernel_addr: u32,
    pub ramdisk_addr: u32,
    pub tags_addr: u32,
    pub dtb_addr: u64,
    /// The kernel command line, as the header holds it: fixed width, NUL
    /// filled.
    pub cmdline: Vec<u8>,
    /// The board name, as the header holds it.
    pub name: Vec<u8>,
    pub dtb: Vec<u8>,
    /// The vendor bootconfig, which many images leave out.
    pub bootconfig: Vec<u8>,
    pub entries: Vec<Entry>,
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

impl VendorBoot {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        VendorBoot::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let section = |at: usize, len: usize, what: &str| -> Result<&[u8]> {
            bytes
                .get(at..at + len)
                .ok_or_else(|| anyhow!("{what} runs past the end of the image"))
        };
        if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
            bail!("this is no vendor boot image");
        }
        let (header_version, page_size, kernel_addr, ramdisk_addr, vendor_ramdisk_size) =
            u32x5(&bytes[8..28]);
        if header_version != 4 {
            bail!("header version {header_version} has no vendor ramdisk table");
        }
        let cmdline = section(28, 2048, "the command line")?.to_vec();
        let (tags_addr,) = u32x1(&bytes[2076..2080]);
        let name = bytes[2080..2096].to_vec();
        let (header_size, dtb_size) = u32x2(&bytes[2096..2104]);
        let (dtb_addr,) = u64x1(&bytes[2104..2112]);
        if header_size as usize != HEADER_LEN {
            bail!("the header says it is {header_size} bytes, where version 4 lays out {HEADER_LEN}");
        }
        let (table_size, entry_num, entry_size, bootconfig_size) = u32x4(&bytes[2112..2128]);
        if entry_size as usize != TABLE_ENTRY_LEN {
            bail!("a table entry is {entry_size} bytes, where version 4 lays out {TABLE_ENTRY_LEN}");
        }

        let ramdisk_region = align_up(header_size as usize, page_size as usize);
        let dtb_off = align_up(ramdisk_region + vendor_ramdisk_size as usize, page_size as usize);
        let table_off = align_up(dtb_off + dtb_size as usize, page_size as usize);
        let bootconfig_off = table_off + table_size as usize;
        let dtb = section(dtb_off, dtb_size as usize, "the device tree blob")?.to_vec();
        let table = section(table_off, table_size as usize, "the ramdisk table")?;
        let bootconfig = section(bootconfig_off, bootconfig_size as usize, "the bootconfig")?.to_vec();

        let mut entries = Vec::new();
        for i in 0..entry_num as usize {
            let e = table
                .get(i * TABLE_ENTRY_LEN..(i + 1) * TABLE_ENTRY_LEN)
                .ok_or_else(|| anyhow!("the table holds fewer entries than it names"))?;
            let (ramdisk_size, ramdisk_offset, ramdisk_type) = u32x3(e);
            let name = cstr(&e[12..12 + NAME_LEN]);
            let blob = bytes
                .get(ramdisk_region + ramdisk_offset as usize..
                    ramdisk_region + ramdisk_offset as usize + ramdisk_size as usize)
                .ok_or_else(|| anyhow!("the ramdisk {name:?} runs past the end of the image"))?
                .to_vec();
            if blob.len() != ramdisk_size as usize {
                bail!("the ramdisk {name:?} is cut short of its {} bytes", ramdisk_size);
            }
            let _ = BOARD_ID_LEN;
            entries.push(Entry { name, kind: ramdisk_type, blob });
        }
        if vendor_ramdisk_size != 0 && entries.is_empty() {
            bail!("the image holds vendor ramdisk bytes but names no entries");
        }
        Ok(VendorBoot {
            page_size,
            kernel_addr,
            ramdisk_addr,
            tags_addr,
            dtb_addr,
            cmdline,
            name,
            dtb,
            bootconfig,
            entries,
        })
    }

    /// The image with sizes taken from its parts: the ramdisks packed back
    /// to back, the device tree blob and the table each on the next page,
    /// the bootconfig after the table.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let page = self.page_size as usize;
        let ramdisk_size: usize = self.entries.iter().map(|e| e.blob.len()).sum();
        let table_size = self.entries.len() * TABLE_ENTRY_LEN;
        let mut out = Vec::with_capacity(page + ramdisk_size + self.dtb.len() + table_size + self.bootconfig.len());
        let mut header = vec![0u8; HEADER_LEN];
        header[..8].copy_from_slice(MAGIC);
        let fields = [4u32, self.page_size, self.kernel_addr, self.ramdisk_addr, ramdisk_size as u32];
        for (i, f) in fields.iter().enumerate() {
            header[8 + i * 4..12 + i * 4].copy_from_slice(&f.to_le_bytes());
        }
        let mut cmdline = [0u8; 2048];
        cmdline[..2048.min(self.cmdline.len())].copy_from_slice(&self.cmdline[..2048.min(self.cmdline.len())]);
        header[28..28 + 2048].copy_from_slice(&cmdline);
        header[2076..2080].copy_from_slice(&self.tags_addr.to_le_bytes());
        let mut name = [0u8; 16];
        name[..16.min(self.name.len())].copy_from_slice(&self.name[..16.min(self.name.len())]);
        header[2080..2096].copy_from_slice(&name);
        header[2096..2100].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        header[2100..2104].copy_from_slice(&(self.dtb.len() as u32).to_le_bytes());
        header[2104..2112].copy_from_slice(&self.dtb_addr.to_le_bytes());
        for (i, f) in [table_size as u32, self.entries.len() as u32, TABLE_ENTRY_LEN as u32, self.bootconfig.len() as u32]
            .iter()
            .enumerate()
        {
            header[2112 + i * 4..2116 + i * 4].copy_from_slice(&f.to_le_bytes());
        }
        out.extend_from_slice(&header);
        pad_to(&mut out, page);
        let mut offset = 0u32;
        let mut table = Vec::with_capacity(table_size);
        for e in &self.entries {
            let size = u32::try_from(e.blob.len()).context("a ramdisk of over 4 GiB")?;
            table.extend_from_slice(&size.to_le_bytes());
            table.extend_from_slice(&offset.to_le_bytes());
            table.extend_from_slice(&e.kind.to_le_bytes());
            let mut name = [0u8; NAME_LEN];
            name[..NAME_LEN.min(e.name.len())].copy_from_slice(&e.name.as_bytes()[..NAME_LEN.min(e.name.len())]);
            table.extend_from_slice(&name);
            table.extend_from_slice(&[0u8; BOARD_ID_LEN * 4]);
            out.extend_from_slice(&e.blob);
            offset += size;
        }
        pad_to(&mut out, page);
        out.extend_from_slice(&self.dtb);
        pad_to(&mut out, page);
        out.extend_from_slice(&table);
        out.extend_from_slice(&self.bootconfig);
        Ok(out)
    }

    /// The one ramdisk of a kind, as the table holds one of each.
    pub fn of_kind(&self, kind: u32) -> Option<&Entry> {
        self.entries.iter().find(|e| e.kind == kind)
    }

    pub fn recovery(&self) -> Option<&Entry> {
        self.of_kind(TYPE_RECOVERY)
    }
}

fn align_up(x: usize, page: usize) -> usize {
    x.div_ceil(page) * page
}

fn pad_to(out: &mut Vec<u8>, page: usize) {
    out.resize(align_up(out.len(), page), 0);
}

fn u32x1(b: &[u8]) -> (u32,) {
    (u32::from_le_bytes(b[..4].try_into().expect("four bytes")),)
}

fn u32x2(b: &[u8]) -> (u32, u32) {
    let mut it = b.chunks_exact(4);
    (
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
    )
}

fn u32x3(b: &[u8]) -> (u32, u32, u32) {
    let mut it = b.chunks_exact(4);
    (
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
    )
}

fn u32x4(b: &[u8]) -> (u32, u32, u32, u32) {
    let mut it = b.chunks_exact(4);
    (
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
    )
}

fn u32x5(b: &[u8]) -> (u32, u32, u32, u32, u32) {
    let mut it = b.chunks_exact(4);
    (
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
        u32::from_le_bytes(it.next().unwrap().try_into().unwrap()),
    )
}

fn u64x1(b: &[u8]) -> (u64,) {
    (u64::from_le_bytes(b[..8].try_into().expect("eight bytes")),)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small image: a header, two ramdisks, a device tree blob, a table.
    fn image(entries: Vec<Entry>, dtb: &[u8], bootconfig: &[u8]) -> Vec<u8> {
        let ramdisk_size: usize = entries.iter().map(|e| e.blob.len()).sum();
        let table = entries.len() * TABLE_ENTRY_LEN;
        let mut out = vec![0u8; HEADER_LEN];
        out[..8].copy_from_slice(MAGIC);
        for (i, f) in [4u32, 4096, 0x11, 0x22, ramdisk_size as u32].iter().enumerate() {
            out[8 + i * 4..12 + i * 4].copy_from_slice(&f.to_le_bytes());
        }
        out[28..28 + 6].copy_from_slice(b"cmd=1\0");
        out[2076..2080].copy_from_slice(&0x33u32.to_le_bytes());
        out[2080..2086].copy_from_slice(b"boardy");
        out[2096..2100].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        out[2100..2104].copy_from_slice(&(dtb.len() as u32).to_le_bytes());
        out[2104..2112].copy_from_slice(&0x4444u64.to_le_bytes());
        for (i, f) in [table as u32, entries.len() as u32, TABLE_ENTRY_LEN as u32, bootconfig.len() as u32]
            .iter()
            .enumerate()
        {
            out[2112 + i * 4..2116 + i * 4].copy_from_slice(&f.to_le_bytes());
        }
        pad_to(&mut out, 4096);
        let mut table_bytes = Vec::new();
        let mut offset = 0u32;
        for e in &entries {
            table_bytes.extend_from_slice(&(e.blob.len() as u32).to_le_bytes());
            table_bytes.extend_from_slice(&offset.to_le_bytes());
            table_bytes.extend_from_slice(&e.kind.to_le_bytes());
            let mut name = [0u8; NAME_LEN];
            name[..e.name.len()].copy_from_slice(e.name.as_bytes());
            table_bytes.extend_from_slice(&name);
            table_bytes.extend_from_slice(&[0u8; BOARD_ID_LEN * 4]);
            out.extend_from_slice(&e.blob);
            offset += e.blob.len() as u32;
        }
        pad_to(&mut out, 4096);
        out.extend_from_slice(dtb);
        pad_to(&mut out, 4096);
        out.extend_from_slice(&table_bytes);
        out.extend_from_slice(bootconfig);
        out
    }

    fn entry(name: &str, kind: u32, blob: &[u8]) -> Entry {
        Entry { name: name.into(), kind, blob: blob.to_vec() }
    }

    #[test]
    fn a_round_trip_keeps_every_part() {
        let platform = entry("", TYPE_PLATFORM, b"the platform ramdisk");
        let recovery = entry("recovery", TYPE_RECOVERY, b"the recovery ramdisk");
        let dtb = b"a device tree blob of a few bytes";
        let bootconfig = b"androidboot.x = \"y\"\n";
        let bytes = image(vec![platform, recovery.clone()], dtb, bootconfig);
        let img = VendorBoot::parse(&bytes).expect("the image parses");
        assert_eq!(img.page_size, 4096);
        assert_eq!(img.kernel_addr, 0x11);
        assert_eq!(img.dtb, dtb);
        assert_eq!(img.bootconfig, bootconfig);
        assert_eq!(img.entries.len(), 2);
        assert_eq!(img.recovery().unwrap().blob, b"the recovery ramdisk");
        let again = img.to_bytes().unwrap();
        let back = VendorBoot::parse(&again).expect("the rebuilt image parses");
        assert_eq!(back.entries.len(), 2);
        assert_eq!(back.entries[1].name, "recovery");
        assert_eq!(back.entries[1].blob, b"the recovery ramdisk");
        assert_eq!(back.entries[0].blob, b"the platform ramdisk");
        assert_eq!(back.dtb, dtb);
        assert_eq!(back.bootconfig, bootconfig);
    }

    #[test]
    fn a_replaced_recovery_ramdisk_moves_the_ones_after_it() {
        let bytes = image(
            vec![entry("", TYPE_PLATFORM, b"platform"), entry("recovery", TYPE_RECOVERY, b"old")],
            b"dtb",
            b"",
        );
        let mut img = VendorBoot::parse(&bytes).unwrap();
        img.entries[1].blob = b"a much longer recovery ramdisk than before".to_vec();
        let back = VendorBoot::parse(&img.to_bytes().unwrap()).unwrap();
        assert_eq!(back.entries[0].blob, b"platform", "the platform ramdisk stays first");
        assert_eq!(back.entries[1].blob, b"a much longer recovery ramdisk than before");
        assert_eq!(back.dtb, b"dtb");
    }

    #[test]
    fn no_other_image_passes() {
        assert!(VendorBoot::parse(b"BOOT IMG!and a lot of padding to fill the header up").is_err());
        assert!(VendorBoot::parse(&[]).is_err());
    }
}
