#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action::{XDP_ABORTED, XDP_PASS, XDP_TX},
    helpers::bpf_xdp_adjust_tail,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use common::SockPair;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

const ETH_ALEN: usize = 6;
const MAX_TCP_LENGTH: usize = 2000;

#[map]
static mut CONNTRACK_MAP: HashMap<SockPair, u32> = HashMap::with_max_entries(65535, 0);

#[xdp]
pub fn valkeyri(ctx: XdpContext) -> u32 {
    match try_resp_cache(ctx) {
        Ok(ret) => ret,
        Err(_) => XDP_ABORTED,
    }
}

fn try_resp_cache(ctx: XdpContext) -> Result<u32, ()> {
    let data_end = ctx.data_end();
    let data = ctx.data();

    let eth_hdr: *mut EthHdr = ptr_at_mut(&ctx, 0)?;

    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(XDP_PASS),
    }

    let ip_hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;

    match unsafe { (*ip_hdr).proto } {
        IpProto::Tcp => {}
        _ => return Ok(XDP_PASS),
    }

    let tcp_hdr: *mut TcpHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    let src_ip = unsafe { (*ip_hdr).src_addr };
    let dst_ip = unsafe { (*ip_hdr).dst_addr };

    let src_port = unsafe { (*tcp_hdr).source };
    let dst_port = unsafe { (*tcp_hdr).dest };

    if u16::from_be(dst_port) != 6379 {
        return Ok(XDP_PASS);
    }

    let ip_hdr_len = unsafe { ((*ip_hdr).ihl() * 4) as usize };
    let tcp_hdr_len = unsafe { ((*tcp_hdr).doff() * 4) as usize };

    unsafe {
        if (*tcp_hdr).syn() == 1 && (*tcp_hdr).ack() == 0 {
            let sock_pair = SockPair {
                src_ip,
                dst_ip,
                src_port: src_port as u32,
                dst_port: dst_port as u32,
            };

            info!(&ctx, "Connection initiated");

            CONNTRACK_MAP
                .insert(&sock_pair, &(*tcp_hdr).seq, 0)
                .map_err(|_| ())?;
        }

        if (*tcp_hdr).fin() == 1 && (*tcp_hdr).ack() == 1 {
            let sock_pair = SockPair {
                src_ip,
                dst_ip,
                src_port: src_port as u32,
                dst_port: dst_port as u32,
            };

            if let Some(&syn_seq) = CONNTRACK_MAP.get(&sock_pair) {
                info!(&ctx, "Connection closed");

                (*ip_hdr).tot_len = u16::to_be(ip_hdr_len as u16 + tcp_hdr_len as u16 - 12);
                (*ip_hdr).check = compute_ip_csum(&mut *ip_hdr, false);

                (*tcp_hdr).set_ack(0);
                (*tcp_hdr).set_fin(0);
                (*tcp_hdr).set_rst(1);
                (*tcp_hdr).set_doff(5);
                (*tcp_hdr).window = u16::to_be(0);
                let new_seq = u32::from_be(syn_seq) + 112;
                (*tcp_hdr).seq = u32::to_be(new_seq);
                (*tcp_hdr).ack_seq = u32::to_be(0);
                (*tcp_hdr).check = compute_tcp_csum(&ctx, false)?;
                CONNTRACK_MAP.remove(&sock_pair).map_err(|_| ())?;

                bpf_xdp_adjust_tail(ctx.ctx, 0 - 12);

                return Ok(XDP_PASS);
            }
        }

        if (*tcp_hdr).psh() != 1 || (*tcp_hdr).ack() != 1 {
            return Ok(XDP_PASS);
        }
    }

    let ip_total_len = unsafe { u16::from_be((*ip_hdr).tot_len) as usize };
    let payload_offset = EthHdr::LEN + ip_hdr_len + tcp_hdr_len;
    let payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

    if data + EthHdr::LEN + ip_hdr_len + tcp_hdr_len > data_end {
        return Ok(XDP_PASS);
    }

    // info!(
    //     &ctx,
    //     "ip_hdr_len: {}, tcp_hdr_len: {}, payload_offset: {}, ip_total_len: {}, payload_len: {}",
    //     ip_hdr_len,
    //     tcp_hdr_len,
    //     payload_offset,
    //     ip_total_len,
    //     payload_len
    // );

    if payload_len < 11 {
        return Ok(XDP_PASS);
    }

    let method: [u8; 3] = unsafe { *ptr_at(&ctx, payload_offset + 8)? };

    if method != [b'G', b'E', b'T'] {
        return Ok(XDP_PASS);
    }

    // let src_mac = unsafe { (*eth_hdr).src_addr };
    // let dst_mac = unsafe { (*eth_hdr).dst_addr };

    info!(
        &ctx,
        "Before {:i}:{} -> {:i}:{} ", src_ip, src_port, dst_ip, dst_port,
    );

    unsafe {
        const PAYLOAD_LEN: usize = 8;
        let http_response = &[0x24, 0x32, 0x0d, 0x0a, 0x34, 0x31, 0x0d, 0x0a];
        let payload: *mut [u8; PAYLOAD_LEN] = ptr_at_mut(&ctx, payload_offset)?;

        if data + payload_offset + PAYLOAD_LEN > data_end {
            return Ok(XDP_PASS);
        }

        (*payload).copy_from_slice(http_response);

        mem::swap(&mut (*eth_hdr).src_addr, &mut (*eth_hdr).dst_addr);
        mem::swap(&mut (*ip_hdr).src_addr, &mut (*ip_hdr).dst_addr);
        mem::swap(&mut (*tcp_hdr).source, &mut (*tcp_hdr).dest);

        (*ip_hdr).tot_len = u16::to_be(ip_hdr_len as u16 + tcp_hdr_len as u16 + PAYLOAD_LEN as u16);
        (*ip_hdr).check = compute_ip_csum(&mut *ip_hdr, false);

        // let verified_ip_csum = compute_ip_csum(&mut *ip_hdr, true);
        // info!(&ctx, "verify ip checksum: {}", verified_ip_csum);

        // update seq, ack_seq
        let seq = u32::from_be((*tcp_hdr).seq);
        let ack_seq = (*tcp_hdr).ack_seq;
        let new_ack_seq = u32::to_be(seq + PAYLOAD_LEN as u32);

        (*tcp_hdr).seq = ack_seq;
        (*tcp_hdr).ack_seq = new_ack_seq;
        (*tcp_hdr).check = compute_tcp_csum(&ctx, false)?;

        // let verified_tcp_csum = compute_tcp_csum(&ctx, true)?;
        // info!(&ctx, "verify tcp checksum: {}", verified_tcp_csum);

        // let src_mac = (*eth_hdr).src_addr;
        // let dst_mac = (*eth_hdr).dst_addr;

        // let src_ip = u32::from_be((*ip_hdr).src_addr);
        // let src_port = u16::from_be((*tcp_hdr).source);

        // let dst_ip = u32::from_be((*ip_hdr).dst_addr);
        // let dst_port = u16::from_be((*tcp_hdr).dest);

        // info!(
        //     &ctx,
        //     "After changing {:i}:{}({:x}) -> {:i}:{}({:x})",
        //     src_ip,
        //     src_port,
        //     &src_mac[..ETH_ALEN],
        //     dst_ip,
        //     dst_port,
        //     &dst_mac[..ETH_ALEN]
        // );

        // if (*tcp_hdr).psh() == 1 && (*tcp_hdr).ack() == 1 {
        //     let sock_pair = SockPair {
        //         dst_ip,
        //         src_ip,
        //         src_port: dst_port as u32,
        //         dst_port: src_port as u32,
        //     };

        //     if let Some(conn_state) = CONNTRACK_MAP.get_ptr_mut(&sock_pair) {
        //         if (*conn_state).state == 0 {
        //             info!(&ctx, "Request received");
        //             (*conn_state).state = 1;
        //         }
        //     }
        // }

        bpf_xdp_adjust_tail(
            ctx.ctx,
            0 - (data_end - (data + payload_offset + PAYLOAD_LEN)) as i32,
        );
    }

    Ok(XDP_TX)
}

fn try_tcp_early_return(ctx: XdpContext) -> Result<u32, ()> {
    let data_end = ctx.data_end();
    let data = ctx.data();

    let eth_hdr: *mut EthHdr = ptr_at_mut(&ctx, 0)?;

    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(XDP_PASS),
    }

    let ip_hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;

    match unsafe { (*ip_hdr).proto } {
        IpProto::Tcp => {}
        _ => return Ok(XDP_PASS),
    }

    let tcp_hdr: *mut TcpHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    let src_mac = unsafe { (*eth_hdr).src_addr };
    let dst_mac = unsafe { (*eth_hdr).dst_addr };

    let src_ip = unsafe { u32::from_be((*ip_hdr).src_addr) };
    let src_port = unsafe { u16::from_be((*tcp_hdr).source) };

    let dst_ip = unsafe { u32::from_be((*ip_hdr).dst_addr) };
    let dst_port = unsafe { u16::from_be((*tcp_hdr).dest) };

    if dst_port != 8080 {
        return Ok(XDP_PASS);
    }

    let ip_hdr_len = unsafe { ((*ip_hdr).ihl() * 4) as usize };
    let tcp_hdr_len = unsafe { ((*tcp_hdr).doff() * 4) as usize };
    let ip_total_len = unsafe { u16::from_be((*ip_hdr).tot_len) as usize };
    let payload_offset = EthHdr::LEN + ip_hdr_len + tcp_hdr_len;
    let payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

    if data + EthHdr::LEN + ip_hdr_len + tcp_hdr_len > data_end {
        return Ok(XDP_PASS);
    }

    if payload_len < 71 {
        return Ok(XDP_PASS);
    }

    info!(
        &ctx,
        "ip_hdr_len: {}, tcp_hdr_len: {}, payload_offset: {}, ip_total_len: {}, payload_len: {}",
        ip_hdr_len,
        tcp_hdr_len,
        payload_offset,
        ip_total_len,
        payload_len
    );

    info!(
        &ctx,
        "Before {:i}:{}({:x}) -> {:i}:{}({:x}) ",
        src_ip,
        src_port,
        &src_mac[..ETH_ALEN],
        dst_ip,
        dst_port,
        &dst_mac[..ETH_ALEN]
    );

    unsafe {
        // update payload to
        // < HTTP/1.1 200 OK
        // < Content-Length: 19
        // <
        // It's a fake response

        const PAYLOAD_LEN: usize = 59;
        let http_response = b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\n\r\nIt's a fake response";
        let payload: *mut [u8; PAYLOAD_LEN] = ptr_at_mut(&ctx, payload_offset)?;

        if data + payload_offset + PAYLOAD_LEN > data_end {
            return Ok(XDP_PASS);
        }

        (*payload).copy_from_slice(http_response);

        mem::swap(&mut (*eth_hdr).src_addr, &mut (*eth_hdr).dst_addr);
        mem::swap(&mut (*ip_hdr).src_addr, &mut (*ip_hdr).dst_addr);
        mem::swap(&mut (*tcp_hdr).source, &mut (*tcp_hdr).dest);

        (*ip_hdr).tot_len = u16::to_be(ip_hdr_len as u16 + tcp_hdr_len as u16 + PAYLOAD_LEN as u16);
        (*ip_hdr).check = compute_ip_csum(&mut *ip_hdr, false);

        let verified_ip_csum = compute_ip_csum(&mut *ip_hdr, true);
        info!(&ctx, "verify ip checksum: {}", verified_ip_csum);

        // update seq, ack_seq
        let seq = u32::from_be((*tcp_hdr).seq);
        let ack_seq = (*tcp_hdr).ack_seq;
        let new_ack_seq = u32::to_be(seq + PAYLOAD_LEN as u32);

        (*tcp_hdr).seq = ack_seq;
        (*tcp_hdr).ack_seq = new_ack_seq;
        (*tcp_hdr).check = compute_tcp_csum(&ctx, false)?;

        let verified_tcp_csum = compute_tcp_csum(&ctx, true)?;
        info!(&ctx, "verify tcp checksum: {}", verified_tcp_csum);

        let src_mac = (*eth_hdr).src_addr;
        let dst_mac = (*eth_hdr).dst_addr;

        let src_ip = u32::from_be((*ip_hdr).src_addr);
        let src_port = u16::from_be((*tcp_hdr).source);

        let dst_ip = u32::from_be((*ip_hdr).dst_addr);
        let dst_port = u16::from_be((*tcp_hdr).dest);

        info!(
            &ctx,
            "After changing {:i}:{}({:x}) -> {:i}:{}({:x})",
            src_ip,
            src_port,
            &src_mac[..ETH_ALEN],
            dst_ip,
            dst_port,
            &dst_mac[..ETH_ALEN]
        );

        bpf_xdp_adjust_tail(
            ctx.ctx,
            0 - (data_end - (data + payload_offset + PAYLOAD_LEN)) as i32,
        );
    }

    Ok(XDP_TX)
}

fn try_icmp_echo(ctx: XdpContext) -> Result<u32, ()> {
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
