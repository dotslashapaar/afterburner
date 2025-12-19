use std::ffi::CString;
use std::{io, mem};
use std::os::fd::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use libc::{
    close, mmap, munmap, setsockopt, socket, AF_XDP, MAP_ANONYMOUS, MAP_FAILED,
    MAP_HUGETLB, MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, PROT_READ, PROT_WRITE,
    SOCK_RAW, SOL_XDP, XDP_COPY, XDP_MMAP_OFFSETS, XDP_PGOFF_RX_RING, XDP_RX_RING,
    XDP_TX_RING, XDP_UMEM_COMPLETION_RING, XDP_UMEM_FILL_RING,
    XDP_UMEM_PGOFF_COMPLETION_RING, XDP_UMEM_PGOFF_FILL_RING, XDP_UMEM_REG,
};

// Constants
const UMEM_SIZE: usize = 8 * 1024 * 1024;
const FRAME_SIZE: usize = 4096;
const NUM_FRAMES: usize = UMEM_SIZE / FRAME_SIZE;
const RING_SIZE: u32 = 2048;

/// Allocate UMEM buffer using mmap, attempting HUGETLB for better TLB performance.
/// Falls back to regular pages if huge pages are unavailable.
unsafe fn allocate_umem(size: usize) -> Result<*mut u8, io::Error> {
    // Try with HUGETLB first (2MB pages reduce TLB entries from 2048 to 4 for 8MB)
    let ptr = mmap(
        ptr::null_mut(),
        size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE,
        -1,
        0,
    );

    if ptr != MAP_FAILED {
        return Ok(ptr as *mut u8);
    }

    // Fallback to regular pages if HUGETLB fails
    eprintln!("[afterburner] HUGETLB allocation failed, falling back to regular pages. \
               For optimal performance, configure huge pages: echo 64 | sudo tee /proc/sys/vm/nr_hugepages");

    let ptr = mmap(
        ptr::null_mut(),
        size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
        -1,
        0,
    );

    if ptr == MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }

    Ok(ptr as *mut u8)
}

#[repr(C)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct XdpMmapOffsets {
    rx: XdpRingOffsets,
    tx: XdpRingOffsets,
    fr: XdpRingOffsets,
    cr: XdpRingOffsets,
}

#[repr(C)]
#[derive(Default)]
struct XdpRingOffsets {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[allow(dead_code)]
struct XdpRing {
    producer: *mut AtomicU32,
    consumer: *mut AtomicU32,
    desc: *mut u8,
    size: u32,
    ptr: *mut libc::c_void,
    len: usize,
}

pub struct XdpSocket {
    pub umem_ptr: *mut u8,
    pub fd: RawFd,
    umem_size: usize,
    rx_ring: XdpRing,
    tx_ring: XdpRing,
    fill_ring: XdpRing,
    comp_ring: XdpRing,
    tx_free_frames: Vec<u64>,
    pending_tx_addr: Option<u64>,
}

impl XdpSocket {
    pub fn new(iface: &str, queue_id: u32) -> Result<Self, io::Error> {
        unsafe {
            // 1. Socket
            let fd = socket(AF_XDP, SOCK_RAW, 0);
            if fd < 0 { return Err(io::Error::last_os_error()); }

            // 2. UMEM (using mmap with HUGETLB for better TLB performance)
            let umem_ptr = allocate_umem(UMEM_SIZE)?;

            let mr = XdpUmemReg {
                addr: umem_ptr as u64, len: UMEM_SIZE as u64, chunk_size: FRAME_SIZE as u32, headroom: 0, flags: 0,
            };
            if setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &mr as *const _ as *const _, mem::size_of::<XdpUmemReg>() as u32) != 0 {
                return Err(io::Error::last_os_error());
            }

            // 3. Ring Sizes
            setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING, &RING_SIZE as *const _ as *const _, 4);
            setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &RING_SIZE as *const _ as *const _, 4);
            setsockopt(fd, SOL_XDP, XDP_RX_RING, &RING_SIZE as *const _ as *const _, 4);
            setsockopt(fd, SOL_XDP, XDP_TX_RING, &RING_SIZE as *const _ as *const _, 4);

            // 4. Offsets
            let mut off = XdpMmapOffsets::default();
            let mut optlen = mem::size_of::<XdpMmapOffsets>() as u32;
            libc::getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &mut off as *mut _ as *mut _, &mut optlen);

            // 5. Map Rings
            
            // FILL (u64 = 8 bytes)
            let fill_len = off.fr.desc as usize + (RING_SIZE as usize * 8);
            let fill_map = mmap(ptr::null_mut(), fill_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_UMEM_PGOFF_FILL_RING as i64);
            if fill_map == MAP_FAILED { return Err(std::io::Error::last_os_error()); }
            
            let fill_ring = XdpRing {
                producer: fill_map.offset(off.fr.producer as isize) as *mut AtomicU32,
                consumer: fill_map.offset(off.fr.consumer as isize) as *mut AtomicU32,
                desc: fill_map.offset(off.fr.desc as isize) as *mut u8,
                size: RING_SIZE, ptr: fill_map, len: fill_len,
            };

            // COMP (u64 = 8 bytes)
            let comp_len = off.cr.desc as usize + (RING_SIZE as usize * 8);
            let comp_map = mmap(ptr::null_mut(), comp_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_UMEM_PGOFF_COMPLETION_RING as i64);
            if comp_map == MAP_FAILED { return Err(std::io::Error::last_os_error()); }
            
            let comp_ring = XdpRing {
                producer: comp_map.offset(off.cr.producer as isize) as *mut AtomicU32,
                consumer: comp_map.offset(off.cr.consumer as isize) as *mut AtomicU32,
                desc: comp_map.offset(off.cr.desc as isize) as *mut u8,
                size: RING_SIZE, ptr: comp_map, len: comp_len,
            };

            // RX (xdp_desc = 16 bytes)
            let rx_len = off.rx.desc as usize + (RING_SIZE as usize * 16); 
            let rx_map = mmap(ptr::null_mut(), rx_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_PGOFF_RX_RING);
            if rx_map == MAP_FAILED { 
                return Err(std::io::Error::last_os_error()); 
            }
            
            let rx_ring = XdpRing {
                producer: rx_map.offset(off.rx.producer as isize) as *mut AtomicU32,
                consumer: rx_map.offset(off.rx.consumer as isize) as *mut AtomicU32,
                desc: rx_map.offset(off.rx.desc as isize) as *mut u8,
                size: RING_SIZE, ptr: rx_map, len: rx_len,
            };

            // TX (xdp_desc = 16 bytes)
            let tx_len = off.tx.desc as usize + (RING_SIZE as usize * 16);
            let tx_map = mmap(ptr::null_mut(), tx_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, libc::XDP_PGOFF_TX_RING);
            if tx_map == MAP_FAILED { return Err(std::io::Error::last_os_error()); }
            
            let tx_ring = XdpRing {
                producer: tx_map.offset(off.tx.producer as isize) as *mut AtomicU32,
                consumer: tx_map.offset(off.tx.consumer as isize) as *mut AtomicU32,
                desc: tx_map.offset(off.tx.desc as isize) as *mut u8,
                size: RING_SIZE, ptr: tx_map, len: tx_len,
            };

            // 6. Init Fill
            let mut prod = (*fill_ring.producer).load(Ordering::Acquire);
            let desc_ptr = fill_ring.desc as *mut u64;
            for i in 0..(NUM_FRAMES / 2) {
                 *desc_ptr.add((prod as usize) & (RING_SIZE as usize - 1)) = (i * FRAME_SIZE) as u64;
                 prod += 1;
            }
            (*fill_ring.producer).store(prod, Ordering::Release);

            // 7. Init TX
            let mut tx_free_frames = Vec::new();
            for i in (NUM_FRAMES/2)..NUM_FRAMES { tx_free_frames.push((i * FRAME_SIZE) as u64); }

            // 8. Bind
            let if_name = CString::new(iface)?;
            let mut sa: libc::sockaddr_xdp = mem::zeroed();
            sa.sxdp_family = AF_XDP as u16;
            sa.sxdp_ifindex = libc::if_nametoindex(if_name.as_ptr());
            sa.sxdp_queue_id = queue_id;
            
            if libc::bind(fd, &sa as *const _ as *const _, mem::size_of::<libc::sockaddr_xdp>() as u32) != 0 {
                sa.sxdp_flags = XDP_COPY;
                libc::bind(fd, &sa as *const _ as *const _, mem::size_of::<libc::sockaddr_xdp>() as u32);
            }

            Ok(XdpSocket {
                fd, umem_ptr, umem_size: UMEM_SIZE, rx_ring, tx_ring, fill_ring, comp_ring,
                tx_free_frames, pending_tx_addr: None,
            })
        }
    }

    pub fn poll_rx(&mut self) -> Option<(u64, usize)> {
        unsafe {
            let cons = (*self.rx_ring.consumer).load(Ordering::Relaxed);
            let prod = (*self.rx_ring.producer).load(Ordering::Acquire);
            if cons == prod { return None; }
            let idx = cons & (self.rx_ring.size - 1);
            let desc = &*(self.rx_ring.desc as *const XdpDesc).add(idx as usize);
            let addr = desc.addr;
            let len = desc.len as usize;
            (*self.rx_ring.consumer).store(cons + 1, Ordering::Release);
            
            // Return frame to fill ring for reuse
            let fill_prod = (*self.fill_ring.producer).load(Ordering::Relaxed);
            let fill_idx = fill_prod & (self.fill_ring.size - 1);
            let fill_desc = self.fill_ring.desc as *mut u64;
            *fill_desc.add(fill_idx as usize) = addr;
            (*self.fill_ring.producer).store(fill_prod + 1, Ordering::Release);
            
            Some((addr, len))
        }
    }

    pub fn get_tx_frame(&mut self) -> Option<&mut [u8]> {
        unsafe {
            let cons = (*self.comp_ring.consumer).load(Ordering::Relaxed);
            let prod = (*self.comp_ring.producer).load(Ordering::Acquire);
            let mut c = cons;
            while c != prod {
                self.tx_free_frames.push(*(self.comp_ring.desc as *const u64).add((c & (self.comp_ring.size - 1)) as usize));
                c += 1;
            }
            if c != cons { (*self.comp_ring.consumer).store(c, Ordering::Release); }

            let t_prod = (*self.tx_ring.producer).load(Ordering::Relaxed);
            let t_cons = (*self.tx_ring.consumer).load(Ordering::Acquire);
            if t_prod - t_cons >= self.tx_ring.size { return None; }
        }

        if let Some(addr) = self.tx_free_frames.pop() {
            self.pending_tx_addr = Some(addr);
            let ptr = unsafe { self.umem_ptr.add(addr as usize) };
            return Some(unsafe { std::slice::from_raw_parts_mut(ptr, FRAME_SIZE) });
        }
        None
    }

    pub fn tx_submit(&mut self, len: usize) {
        if let Some(addr) = self.pending_tx_addr.take() {
            unsafe {
                let prod = (*self.tx_ring.producer).load(Ordering::Relaxed);
                let d = (self.tx_ring.desc as *mut XdpDesc).add((prod & (self.tx_ring.size - 1)) as usize);
                (*d).addr = addr; (*d).len = len as u32; (*d).options = 0;
                (*self.tx_ring.producer).store(prod + 1, Ordering::Release);
                libc::sendto(self.fd, ptr::null(), 0, libc::MSG_DONTWAIT, ptr::null(), 0);
            }
        }
    }

    pub fn cancel_tx(&mut self) {
        if let Some(addr) = self.pending_tx_addr.take() {
            self.tx_free_frames.push(addr);
        }
    }
}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        unsafe {
            // Unmap ring buffers
            munmap(self.fill_ring.ptr, self.fill_ring.len);
            munmap(self.comp_ring.ptr, self.comp_ring.len);
            munmap(self.rx_ring.ptr, self.rx_ring.len);
            munmap(self.tx_ring.ptr, self.tx_ring.len);

            // Unmap UMEM buffer
            munmap(self.umem_ptr as *mut libc::c_void, self.umem_size);

            // Close socket
            close(self.fd);
        }
    }
}