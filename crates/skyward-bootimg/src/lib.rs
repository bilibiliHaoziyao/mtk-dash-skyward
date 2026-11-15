//! Android boot images with header version 3 or 4, the vendor boot images
//! of version 4, and the newc archives their ramdisks are: read, changed
//! and written again, by the image packer on a computer and by the recovery
//! on the phone.

mod image;
mod ramdisk;
mod vendor_boot;

pub use image::BootImage;
pub use ramdisk::{lz4_legacy, Compression, Entry, Ramdisk};
pub use vendor_boot::{Entry as VendorRamdisk, VendorBoot, TYPE_DLKM, TYPE_PLATFORM, TYPE_RECOVERY};
