use core::mem;

use aya_ebpf::programs::XdpContext;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

const MAX_TCP_LENGTH: usize = 2000;

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
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
