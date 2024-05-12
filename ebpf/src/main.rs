#![no_std]
#![no_main]

use core::{mem, ops::Deref};

use aya_ebpf::{
    bindings::xdp_action::{XDP_ABORTED, XDP_PASS, XDP_TX},
    helpers::bpf_xdp_adjust_tail,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

const MAX_TCP_LENGTH: usize = 2000;

#[map]
static mut CONNTRACK_MAP: HashMap<SockPair, ConnTrack> = HashMap::with_max_entries(65535, 0);

#[xdp]
pub fn valkeyri(ctx: XdpContext) -> u32 {
    match try_resp_cache(ctx) {
        Ok(ret) => ret,
        Err(_) => XDP_ABORTED,
    }
}

fn try_resp_cache(ctx: XdpContext) -> Result<u32, ()> {
    let ctx = match Context::new(&ctx) {
        Ok(ctx) => ctx,
        Err(_) => return Ok(XDP_PASS),
    };

    let sock_pair = SockPair::new(ctx.ip_hdr, ctx.tcp_hdr);

    if sock_pair.dst_port != 6379 {
        return Ok(XDP_PASS);
    }

    unsafe {
        if ctx.ack_only() {
            if let Some(conn_track) = CONNTRACK_MAP.get_ptr_mut(&sock_pair) {
                match (*conn_track).state {
                    RESP_INITIATED => {
                        // info!(ctx.ctx, "RESP Established");
                        (*conn_track).state = RESP_ESTABLISHED;
                    }
                    _ => {
                        // info!(ctx.ctx, "(ACK) Nothing to do");
                    }
                }
            }
        }

        if !ctx.psh_ack() {
            return Ok(XDP_PASS);
        }
    }

    if ctx.payload_len < 11 {
        return Ok(XDP_PASS);
    }

    let method: [u8; 3] = unsafe { *ptr_at(&ctx, ctx.payload_offset + 8)? };

    match method {
        [b'G', b'E', b'T'] => {}
        [b'P', b'I', b'N'] => {
            unsafe {
                if let Some(conn_track) = CONNTRACK_MAP.get_ptr_mut(&sock_pair) {
                    match (*conn_track).state {
                        RESP_ESTABLISHED => {
                            // info!(ctx.ctx, "RESP already established");
                            let http_response = &[0x2b, 0x50, 0x4f, 0x4e, 0x47, 0x0d, 0x0a];
                            return kernel_reply(&ctx, http_response);
                        }
                        state => {
                            // info!(ctx.ctx, "(PING) Unexpected state: {}", state);
                        }
                    }
                } else {
                    // info!(ctx.ctx, "RESP Initiated");
                    let conn_track = ConnTrack {
                        state: RESP_INITIATED,
                    };
                    CONNTRACK_MAP
                        .insert(&sock_pair, &conn_track, 0)
                        .map_err(|_| ())?;
                }
            }

            return Ok(XDP_PASS);
        }
        _ => return Ok(XDP_PASS),
    }

    let http_response = &[0x24, 0x32, 0x0d, 0x0a, 0x34, 0x31, 0x0d, 0x0a];
    unsafe { kernel_reply(&ctx, http_response) }
}

struct Context<'a> {
    ctx: &'a XdpContext,
    eth_hdr: *mut EthHdr,
    ip_hdr: *mut Ipv4Hdr,
    tcp_hdr: *mut TcpHdr,
    ip_hdr_len: usize,
    tcp_hdr_len: usize,
    payload_len: usize,
    payload_offset: usize,
}

impl Deref for Context<'_> {
    type Target = XdpContext;

    fn deref(&self) -> &Self::Target {
        self.ctx
    }
}

impl<'a> Context<'a> {
    fn new(ctx: &'a XdpContext) -> Result<Self, ()> {
        let data_end = ctx.data_end();
        let data = ctx.data();

        let eth_hdr: *mut EthHdr = ptr_at_mut(ctx, 0)?;

        match unsafe { (*eth_hdr).ether_type } {
            EtherType::Ipv4 => {}
            _ => return Err(()),
        }

        let ip_hdr: *mut Ipv4Hdr = ptr_at_mut(ctx, EthHdr::LEN)?;

        match unsafe { (*ip_hdr).proto } {
            IpProto::Tcp => {}
            _ => return Err(()),
        }

        let tcp_hdr: *mut TcpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

        let ip_hdr_len = unsafe { ((*ip_hdr).ihl() * 4) as usize };
        let tcp_hdr_len = unsafe { ((*tcp_hdr).doff() * 4) as usize };

        let ip_total_len = unsafe { u16::from_be((*ip_hdr).tot_len) as usize };
        let payload_offset = EthHdr::LEN + ip_hdr_len + tcp_hdr_len;
        let payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

        if data + EthHdr::LEN + ip_hdr_len + tcp_hdr_len > data_end {
            return Err(());
        }

        Ok(Self {
            ctx,
            eth_hdr,
            ip_hdr,
            tcp_hdr,
            ip_hdr_len,
            tcp_hdr_len,
            payload_len,
            payload_offset,
        })
    }

    fn ack_only(&self) -> bool {
        unsafe {
            (*self.tcp_hdr).ack() == 1
                && (*self.tcp_hdr).syn() == 0
                && (*self.tcp_hdr).psh() == 0
                && (*self.tcp_hdr).fin() == 0
        }
    }

    fn psh_ack(&self) -> bool {
        unsafe { (*self.tcp_hdr).ack() == 1 && (*self.tcp_hdr).psh() == 1 }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockPair {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

impl SockPair {
    fn new(ip_hdr: *const Ipv4Hdr, tcp_hdr: *const TcpHdr) -> Self {
        Self {
            src_ip: unsafe { u32::from_be((*ip_hdr).src_addr) },
            dst_ip: unsafe { u32::from_be((*ip_hdr).dst_addr) },
            src_port: unsafe { u16::from_be((*tcp_hdr).source) },
            dst_port: unsafe { u16::from_be((*tcp_hdr).dest) },
        }
    }
}

pub const RESP_INITIATED: u32 = 0;
pub const RESP_ESTABLISHED: u32 = 1;
// pub const RESP_PING_RECV: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnTrack {
    pub state: u32,
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
unsafe fn kernel_reply<const N: usize>(ctx: &Context, http_response: &[u8; N]) -> Result<u32, ()> {
    let data_end = ctx.data_end();
    let data = ctx.data();

    if data + ctx.payload_offset + N > data_end {
        return Ok(XDP_PASS);
    }

    mem::swap(&mut (*ctx.eth_hdr).src_addr, &mut (*ctx.eth_hdr).dst_addr);
    mem::swap(&mut (*ctx.ip_hdr).src_addr, &mut (*ctx.ip_hdr).dst_addr);
    mem::swap(&mut (*ctx.tcp_hdr).source, &mut (*ctx.tcp_hdr).dest);

    (*ctx.ip_hdr).tot_len = u16::to_be(ctx.ip_hdr_len as u16 + ctx.tcp_hdr_len as u16 + N as u16);
    (*ctx.ip_hdr).check = compute_ip_csum(&mut *ctx.ip_hdr, false);

    let seq = u32::from_be((*ctx.tcp_hdr).seq);
    let ack_seq = (*ctx.tcp_hdr).ack_seq;
    let new_ack_seq = u32::to_be(seq + ctx.payload_len as u32);

    (*ctx.tcp_hdr).seq = ack_seq;
    (*ctx.tcp_hdr).ack_seq = new_ack_seq;
    (*ctx.tcp_hdr).check = compute_tcp_csum(ctx, false)?;

    let payload: *mut [u8; N] = ptr_at_mut(ctx, ctx.payload_offset)?;
    (*payload)[..N].copy_from_slice(&http_response[..N]);

    bpf_xdp_adjust_tail(
        ctx.ctx.ctx,
        0 - (data_end - (data + ctx.payload_offset + N)) as i32,
    );

    Ok(XDP_TX)
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
unsafe fn compute_ip_csum(ip_hdr: *mut Ipv4Hdr, verify: bool) -> u16 {
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
unsafe fn compute_tcp_csum(ctx: &XdpContext, verify: bool) -> Result<u16, ()> {
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
