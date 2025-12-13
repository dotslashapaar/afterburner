#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[map]
static XSK: XskMap = XskMap::with_max_entries(4, 0);

#[xdp]
pub fn afterburner(ctx: XdpContext) -> u32 {
    match try_afterburner(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_afterburner(ctx: XdpContext) -> Result<u32, ()> {
    let eth = ptr_at::<EthHdr>(&ctx, 0).ok_or(())?;

    match eth.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ip = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(())?;
    if ip.proto != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(())?;

    if u16::from_be(udp.dest) == 8003 {
        return Ok(XSK.redirect(0, 0).unwrap_or(xdp_action::XDP_PASS));
        // return Ok(xdp_action::XDP_PASS);
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<&T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    unsafe { Some(&*((start + offset) as *const T)) }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
