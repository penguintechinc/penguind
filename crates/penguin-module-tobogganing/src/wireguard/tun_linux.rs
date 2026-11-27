//! Linux TUN device creation via `/dev/net/tun` and `TUNSETIFF` ioctl.
//!
//! This file isolates the `unsafe` code needed for TUN device operations.
//! The ioctl calls interact directly with the kernel but are constrained to a
//! single, small, justifiable boundary.

#![allow(unsafe_code)]

#[allow(unused_imports)]
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::wireguard::WgBackendError;

/// IFF_TUN flag for TUNSETIFF ioctl (from linux/if_tun.h).
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;

/// TUNSETIFF ioctl number. Computed as IOC_WRITE | (size << 16) | ('T' << 8) | 202.
const TUNSETIFF: libc::c_ulong = 0x400454ca;

/// Represents an open TUN device file descriptor.
pub struct TunFd {
    fd: OwnedFd,
    #[allow(dead_code)]
    name: String,
}

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

impl AsFd for TunFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl TunFd {
    /// Opens `/dev/net/tun` and issues `TUNSETIFF` to create a TUN interface
    /// with the given name. Returns an OwnedFd that closes the file on drop.
    pub fn open(name: &str) -> Result<Self, WgBackendError> {
        // SAFETY: open() is a standard POSIX syscall. The path is a static
        // string known to be safe. We check the result and convert the fd to
        // an OwnedFd so it will be properly closed on drop.
        let fd_raw =
            unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };

        if fd_raw < 0 {
            return Err(WgBackendError::Interface(
                "failed to open /dev/net/tun".to_string(),
            ));
        }

        // SAFETY: we just verified fd_raw >= 0, so it's a valid fd.
        let fd = unsafe { OwnedFd::from_raw_fd(fd_raw) };

        // Build the ifreq structure for TUNSETIFF.
        // The structure is: char ifr_name[IFNAMSIZ] + union of data (we use flags).
        let mut ifr: [u8; 40] = [0; 40]; // 40 bytes = IFNAMSIZ (16) + union (24+)
        let name_bytes = name.as_bytes();
        if name_bytes.len() >= 16 {
            return Err(WgBackendError::Interface(
                "TUN interface name too long".to_string(),
            ));
        }
        ifr[0..name_bytes.len()].copy_from_slice(name_bytes);

        // Set the flags field (at offset 16) to IFF_TUN | IFF_NO_PI (no packet info).
        let flags = IFF_TUN | IFF_NO_PI;
        ifr[16] = (flags & 0xff) as u8;
        ifr[17] = ((flags >> 8) & 0xff) as u8;

        // SAFETY: ioctl is a standard Linux syscall. We've constructed a valid
        // ifreq structure with safe data (the interface name is bounds-checked
        // above). The flags are kernel constants known to be safe for TUN devices.
        // The result is checked below.
        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, ifr.as_mut_ptr()) };

        if ret < 0 {
            return Err(WgBackendError::Interface(
                "TUNSETIFF ioctl failed".to_string(),
            ));
        }

        Ok(TunFd {
            fd,
            name: name.to_string(),
        })
    }

    /// Returns the raw file descriptor for use with tokio AsyncFd.
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Returns the interface name.
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }
}
