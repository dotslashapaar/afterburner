use anyhow::{Context, Result};
use std::alloc::{alloc, dealloc, Layout};
use std::ffi::CString;
use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

const SOL_XDP: i32 = 283;
// Options for setsockopt
const XDP_MMAP_OFFSETS: i32 = 1;
const XDP_RX_RING: i32 = 2;
const XDP_TX_RING: i32 = 3;
const XDP_UMEM_REG: i32 = 4;
const XDP_UMEM_FILL_RING: i32 = 5;
const XDP_UMEM_COMPLETION_RING: i32 = 6;

const XDP_PGOFF_RX_RING: u64 = 0;
const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x100000000;
// flag for forcing copy mode
const XDP_COPY: u16 = 1 << 1;

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct XdpMmapOffsets {
    rx: RingOffsets,
    tx: RingOffsets,
    fr: RingOffsets,
    cr: RingOffsets,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct RingOffsets {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

struct XdpRing {
    producer: *mut AtomicU32,
    consumer: *mut AtomicU32,
    desc: *mut u8,
    size: u32,
    ptr: *mut libc::c_void,
    len: usize,
    cached_cons: u32,
}

pub struct XdpSocket {
    fd: RawFd,
    umem_ptr: *mut u8,
    umem_layout: Layout,
    rx_ring: XdpRing,
    fill_ring: XdpRing,
}

unsafe impl Send for XdpSocket {}

impl XdpSocket {
    pub fn new(iface: &str, queue_id: u32) -> Result<Self> {
        unsafe {
            // Creates the Raw AF_XDP Socket
            let fd = libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0);

            if fd < 0 {
                return Err(anyhow::anyhow!("Failed to create AF_XDP socket"));
            }

            // Allocates Aligned Memory
            let frame_size = 2048;
            let frame_count = 4096;
            let mem_size = frame_count * frame_size;
            let page_size = 4096;

            // Creates a layout: 8MB size, 4KB alignment
            let layout = Layout::from_size_align(mem_size, page_size)
                .context("Failed to create memory layout")?;

            // Allocate
            let umem_ptr = alloc(layout);
            if umem_ptr.is_null() {
                libc::close(fd);
                return Err(anyhow::anyhow!("Failed to allocate aligned memory"));
            }

            // Clean the memory (Set to 0) to avoid garbage data
            ptr::write_bytes(umem_ptr, 0, mem_size);

            // Registers UMEM with the Kernel
            let mr = XdpUmemReg {
                addr: umem_ptr as u64,
                len: mem_size as u64,
                chunk_size: frame_size as u32,
                headroom: 0,
                flags: 0,
            };

            let ret = libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_UMEM_REG,
                &mr as *const _ as *const _,
                mem::size_of::<XdpUmemReg>() as u32,
            );

            if ret != 0 {
                dealloc(umem_ptr, layout);
                libc::close(fd);
                return Err(anyhow::anyhow!(
                    "Failed to register UMEM (Error: {})",
                    std::io::Error::last_os_error()
                ));
            }

            // Configuring All Rings
            let ring_size: u32 = 2048;

            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_UMEM_FILL_RING,
                &ring_size as *const _ as *const _,
                4,
            );
            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_UMEM_COMPLETION_RING,
                &ring_size as *const _ as *const _,
                4,
            );
            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_RX_RING,
                &ring_size as *const _ as *const _,
                4,
            );
            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_TX_RING,
                &ring_size as *const _ as *const _,
                4,
            );

            // Get Offsets (Where exactly are the rings in the file descriptor)
            let mut off = XdpMmapOffsets::default();
            let mut optlen = mem::size_of::<XdpMmapOffsets>() as u32;
            if libc::getsockopt(
                fd,
                SOL_XDP,
                XDP_MMAP_OFFSETS,
                &mut off as *mut _ as *mut _,
                &mut optlen,
            ) != 0
            {
                dealloc(umem_ptr, layout);
                libc::close(fd);
                return Err(anyhow::anyhow!("Failed to get offsets"));
            }

            // Map Fill Ring
            let fill_len = off.fr.desc as usize + (ring_size as usize * 8);
            let fill_map = libc::mmap(
                ptr::null_mut(),
                fill_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                XDP_UMEM_PGOFF_FILL_RING as i64,
            );
            if fill_map == libc::MAP_FAILED {
                dealloc(umem_ptr, layout);
                libc::close(fd);
                return Err(anyhow::anyhow!("Failed to map Fill Ring"));
            }
            let fill_ring = XdpRing {
                producer: fill_map.offset(off.fr.producer as isize) as *mut AtomicU32,
                consumer: fill_map.offset(off.fr.consumer as isize) as *mut AtomicU32,
                desc: fill_map.offset(off.fr.desc as isize) as *mut u8,
                size: ring_size,
                ptr: fill_map,
                len: fill_len,
                cached_cons: 0,
            };

            // Map RX Ring
            let rx_len = off.rx.desc as usize + (ring_size as usize * 16);
            let rx_map = libc::mmap(
                ptr::null_mut(),
                rx_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                XDP_PGOFF_RX_RING as i64,
            );
            if rx_map == libc::MAP_FAILED {
                libc::munmap(fill_ring.ptr, fill_ring.len);
                dealloc(umem_ptr, layout);
                libc::close(fd);
                return Err(anyhow::anyhow!("Failed to map RX Ring"));
            }
            let rx_ring = XdpRing {
                producer: rx_map.offset(off.rx.producer as isize) as *mut AtomicU32,
                consumer: rx_map.offset(off.rx.consumer as isize) as *mut AtomicU32,
                desc: rx_map.offset(off.rx.desc as isize) as *mut u8,
                size: ring_size,
                ptr: rx_map,
                len: rx_len,
                cached_cons: 0,
            };

            // Binds the Socket
            let if_name = CString::new(iface)?;
            let if_index = libc::if_nametoindex(if_name.as_ptr());
            let mut sa: libc::sockaddr_xdp = mem::zeroed();
            sa.sxdp_family = libc::AF_XDP as u16;
            sa.sxdp_ifindex = if_index;
            sa.sxdp_queue_id = queue_id;

            // Try Zero-Copy (Flags=0), fallback to Copy Mode
            sa.sxdp_flags = 0;
            if libc::bind(
                fd,
                &sa as *const _ as *const _,
                mem::size_of::<libc::sockaddr_xdp>() as u32,
            ) != 0
            {
                sa.sxdp_flags = XDP_COPY;
                if libc::bind(
                    fd,
                    &sa as *const _ as *const _,
                    mem::size_of::<libc::sockaddr_xdp>() as u32,
                ) != 0
                {
                    libc::munmap(fill_ring.ptr, fill_ring.len);
                    libc::munmap(rx_ring.ptr, rx_ring.len);
                    dealloc(umem_ptr, layout);
                    libc::close(fd);
                    return Err(anyhow::anyhow!(
                        "Failed to bind. Error: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }

            Ok(XdpSocket {
                fd,
                umem_ptr,
                umem_layout: layout,
                rx_ring,
                fill_ring,
            })
        }
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    // Fill Ring : "Here are some buffers for you to fill, kernel"
    pub fn populate_fill_ring(&mut self, n: u32) {
        unsafe {
            let prod = &*self.fill_ring.producer;
            let mut prod_idx = prod.load(Ordering::Relaxed);

            for i in 0..n {
                let idx = prod_idx & (self.fill_ring.size - 1);
                let desc_ptr = (self.fill_ring.desc as *mut u64).offset(idx as isize);
                *desc_ptr = (i as u64) * 2048;
                prod_idx += 1;
            }
            prod.store(prod_idx, Ordering::Release);
        }
    }

    // RX Ring: "Any new packets for me?"
    pub fn poll_rx(&mut self) -> Option<(u32, usize)> {
        unsafe {
            // 1. Check if Producer (Kernel) has moved past Consumer (Us)
            let rx_prod = (&*self.rx_ring.producer).load(Ordering::Acquire);
            let rx_cons = (&*self.rx_ring.consumer).load(Ordering::Relaxed);

            if rx_prod == rx_cons {
                return None; // No packets
            }

            // 2. Read Packet Metadata
            let idx = rx_cons & (self.rx_ring.size - 1);
            let desc_ptr = self.rx_ring.desc.add((idx as usize) * 16);
            let addr = *(desc_ptr as *const u64);
            let len = *(desc_ptr.add(8) as *const u32);

            // 3. Mark packet as consumed
            (&*self.rx_ring.consumer).store(rx_cons + 1, Ordering::Release);

            // 4. RECYCLE: Immediately give the buffer back to Fill Ring
            let fill_prod = &*self.fill_ring.producer;
            let mut fill_prod_idx = fill_prod.load(Ordering::Relaxed);

            // Check for space using cached consumer
            if fill_prod_idx - self.fill_ring.cached_cons >= self.fill_ring.size {
                self.fill_ring.cached_cons = (&*self.fill_ring.consumer).load(Ordering::Acquire);
            }

            if fill_prod_idx - self.fill_ring.cached_cons < self.fill_ring.size {
                let fill_idx = fill_prod_idx & (self.fill_ring.size - 1);
                let fill_desc = (self.fill_ring.desc as *mut u64).offset(fill_idx as isize);
                *fill_desc = addr; // Reuse the exact same buffer address
                fill_prod.store(fill_prod_idx + 1, Ordering::Release);
            }

            Some((1, len as usize))
        }
    }
}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.rx_ring.ptr, self.rx_ring.len);
            libc::munmap(self.fill_ring.ptr, self.fill_ring.len);
            dealloc(self.umem_ptr, self.umem_layout);
            libc::close(self.fd);
        }
    }
}
