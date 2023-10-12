#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[xdp]
pub fn sync_cookies(ctx: XdpContext) -> u32 {
    match try_sync_cookies(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn process_tcp(ctx: XdpContext) -> Result<u32, ()> {
    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let source = u16::from_be(unsafe { (*tcphdr).source });
    let is_syn = unsafe { (*tcphdr).syn() };
    let is_ack = unsafe { (*tcphdr).ack() };
    let is_fin = unsafe { (*tcphdr).fin() };
    let seq = unsafe { (*tcphdr).seq };
    let ack = unsafe { (*tcphdr).ack_seq };
    let win = unsafe { (*tcphdr).window };

    info!(
        &ctx,
        "SRC: {}, SYN: {}, ACK: {}, FIN: {}, SEQ: {}, ACK: {}, WIN: {}",
        source,
        is_syn,
        is_ack,
        is_fin,
        seq,
        ack,
        win
    );

    Ok(xdp_action::XDP_PASS)
}

fn try_sync_cookies(ctx: XdpContext) -> Result<u32, ()> {
    info!(&ctx, "received a packet");

    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let destination_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let action = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => process_tcp(ctx)?,
        IpProto::Udp => xdp_action::XDP_PASS,
        _ => return Err(()),
    };

    Ok(action)
}

#[inline(always)] //

fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
