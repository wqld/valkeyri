#![no_std]
#![no_main]

mod context;
mod util;

use aya_ebpf::{
    bindings::xdp_action::{XDP_ABORTED, XDP_PASS},
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use context::Context;
use network_types::{ip::Ipv4Hdr, tcp::TcpHdr};
use util::ptr_at;

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

    // info!(
    //     ctx.ctx,
    //     "Process {:i}:{} -> {:i}:{} ",
    //     sock_pair.src_ip,
    //     sock_pair.src_port,
    //     sock_pair.dst_ip,
    //     sock_pair.dst_port,
    // );

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
                            return ctx.kernel_reply(http_response);
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
    unsafe { ctx.kernel_reply(http_response) }
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
