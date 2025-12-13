use anyhow::{Context, Result};
use std::alloc::{alloc, dealloc, Layout};
use std::ffi::CString;
use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::ptr;

const SOL_XDP: i32 = 283;

// Options for setsockopt
const XDP_RX_RING: i32 = 2;
const XDP_TX_RING: i32 = 3;
const XDP_UMEM_REG: i32 = 4;
const XDP_UMEM_FILL_RING: i32 = 5;
const XDP_UMEM_COMPLETION_RING: i32 = 6;

// flag for forcing copy mode
const XDP_COPY: u16 = 1<<1;

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

pub struct XdpSocket {
    fd: RawFd,
    umem_ptr: *mut u8,
    umem_layout: Layout,
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
            let layout = Layout::from_size_align(mem_size, page_size).context("Failed to create memory layout")?;

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
                &mr as *const _ as *const libc::c_void,
                mem::size_of::<XdpUmemReg>() as u32,
            );

            if ret != 0 {
                dealloc(umem_ptr, layout);
                libc::close(fd);
                return Err(anyhow::anyhow!("Failed to register UMEM (Error: {})", std::io::Error::last_os_error()));
            }

            // Configuring All Rings
            let mut ring_size: u32 = 2048;

            // A. Fill Ring (User -> Kernel: "Here are empty buffers")
            if libc::setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING, &ring_size as *const _ as *const libc::c_void, 4) != 0 {
                dealloc(umem_ptr, layout);
                libc::close(fd);
                return Err(anyhow::anyhow!("Failed to set UMEM Fill Ring"));
            }

            // B. Completion Ring (Kernel -> User: "I am done with these buffers")
            if libc::setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ring_size as *const _ as *const libc::c_void, 4) != 0 {
                dealloc(umem_ptr, layout);
                libc::close(fd);
                return Err(anyhow::anyhow!("Failed to set UMEM Completion Ring"));
            }

            // C. RX Ring (Kernel -> User: "Here is a new packet")
            if libc::setsockopt(fd, SOL_XDP, XDP_RX_RING, &ring_size as *const _ as *const libc::c_void, 4) != 0 {
                dealloc(umem_ptr, layout);
                libc::close(fd);
                return Err(anyhow::anyhow!("Failed to set RX Ring"));
            }

            // D. TX Ring (User -> Kernel: "Send this packet")
            if libc::setsockopt(fd, SOL_XDP, XDP_TX_RING, &ring_size as *const _ as *const libc::c_void, 4) != 0 {
                dealloc(umem_ptr, layout);
                libc::close(fd);
                return Err(anyhow::anyhow!("Failed to set TX Ring"));
            }

            // Binds the Socket
            let if_name = CString::new(iface)?;
            let if_index = libc::if_nametoindex(if_name.as_ptr());
            if if_index == 0 {
                dealloc(umem_ptr, layout);
                libc::close(fd);
                return Err(anyhow::anyhow!("Failed to find interface index for {}", iface));
            }

            let mut sa: libc::sockaddr_xdp = mem::zeroed();
            sa.sxdp_family = libc::AF_XDP as u16;
            sa.sxdp_ifindex = if_index;
            sa.sxdp_queue_id = queue_id;
            sa.sxdp_flags = 0;

            let mut ret = libc::bind(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_xdp>() as u32,
            );

            // FALLBACK: If default bind fails, try forcing COPY mode
            if ret != 0 {
                sa.sxdp_flags = XDP_COPY;
                ret = libc::bind(
                    fd,
                    &sa as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_xdp>() as u32,
                );
            }

            if ret != 0 {
                dealloc(umem_ptr, layout);
                libc::close(fd);
                return Err(anyhow::anyhow!("Failed to bind socket (Error: {})", std::io::Error::last_os_error()));
            }

            Ok(XdpSocket {
                fd,
                umem_ptr,
                umem_layout: layout,
            })
        }
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        unsafe {
            if !self.umem_ptr.is_null() {
                dealloc(self.umem_ptr, self.umem_layout);
            }
            libc::close(self.fd);
        }
    }
}
