#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action::{XDP_ABORTED, XDP_PASS, XDP_TX},
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

const ETH_ALEN: usize = 6;
const MAX_TCP_LENGTH: usize = 2000;

#[xdp]
pub fn valkeyri(ctx: XdpContext) -> u32 {
    match try_valkeyri(ctx) {
        Ok(ret) => ret,
        Err(_) => XDP_ABORTED,
    }
}

fn try_valkeyri(ctx: XdpContext) -> Result<u32, ()> {
    // info!(&ctx, "received a packet");

    let eth_hdr: *mut EthHdr = ptr_at_mut(&ctx, 0)?;

    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(XDP_PASS),
    }

    let ip_hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;

    match unsafe { (*ip_hdr).proto } {
        IpProto::Icmp => {}
        _ => return Ok(XDP_PASS),
    }

    let icmp_hdr: *mut IcmpHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    if unsafe { (*icmp_hdr).type_ } != 8 {
        return Ok(XDP_PASS);
    }

    info!(&ctx, "received an ICMP echo request");

    unsafe {
        mem::swap(&mut (*eth_hdr).src_addr, &mut (*eth_hdr).dst_addr);
        mem::swap(&mut (*ip_hdr).src_addr, &mut (*ip_hdr).dst_addr);

        (*ip_hdr).check = compute_ip_csum(&mut *ip_hdr, false);

        let before = *(icmp_hdr as *const _ as *const u16);
        (*icmp_hdr).type_ = 0;
        let after = *(icmp_hdr as *const _ as *const u16);
        (*icmp_hdr).checksum = !csum16_add(csum16_add(!(*icmp_hdr).checksum, !before), after);
    }

    Ok(XDP_TX)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[inline(always)]
pub unsafe fn compute_ip_csum(ip_hdr: *mut Ipv4Hdr, verify: bool) -> u16 {
    let mut checksum = 0u32;
    let mut next = ip_hdr as *mut u16;

    if !verify {
        (*ip_hdr).check = 0;
    }

    for _ in 0..(mem::size_of::<Ipv4Hdr>() >> 1) {
        checksum += *next as u32;
        next = next.add(1);
    }

    !((checksum & 0xffff) + (checksum >> 16)) as u16
}

#[inline(always)]
pub unsafe fn compute_tcp_csum(ctx: &XdpContext, verify: bool) -> Result<u16, ()> {
    let mut checksum = 0u32;
    let ip_hdr: *mut Ipv4Hdr = ptr_at_mut(ctx, EthHdr::LEN)?;
    let tcp_hdr: *mut TcpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let tcp_len = u16::from_be((*ip_hdr).tot_len) - Ipv4Hdr::LEN as u16;

    if !verify {
        (*tcp_hdr).check = 0;
    }

    checksum += (*ip_hdr).src_addr >> 16;
    checksum += (*ip_hdr).src_addr & 0xffff;
    checksum += (*ip_hdr).dst_addr >> 16;
    checksum += (*ip_hdr).dst_addr & 0xffff;
    checksum += (6_u16.to_be() + tcp_len.to_be()) as u32;

    let mut offset = EthHdr::LEN + Ipv4Hdr::LEN;
    for _ in 0..MAX_TCP_LENGTH / 2 {
        match ptr_at::<u16>(ctx, offset) {
            Ok(buf) => unsafe {
                checksum += *buf as u32;
            },
            _ => break,
        };
        offset += 2;
    }

    while checksum >> 16 != 0 {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }

    Ok(!checksum as u16)
}

#[inline(always)]
fn csum16_add(mut csum: u16, addend: u16) -> u16 {
    csum += addend;
    csum += if csum < addend { 1 } else { 0 };
    csum
}
