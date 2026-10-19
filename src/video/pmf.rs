//! PSMF (`.PMF`) muxing for the animated XMB icon.
//!
//! A PMF is a 2048-byte header followed by an MPEG-2 program stream of
//! 2048-byte packs carrying one H.264 video stream. The layout mirrors a
//! Sony-authored 144 × 80 `ICON1.PMF` (PPSSPP's
//! `pspautotests/tests/video/pmf/test.pmf`) field for field:
//!
//! - Every GOP starts a new pack. That pack carries the system header, a
//!   private-stream-2 (`0xBF`) index of the GOP's access units, and a video
//!   PES with PTS, DTS and a P-STD buffer extension. The GOP's last pack is
//!   padded with a padding stream (`0xBE`).
//! - The `0xBF` index: `01 e0`, the pack (relative to the GOP) holding the
//!   end of each of the first four access units, four zero bytes, then the
//!   byte size of every access unit.
//! - PTS/DTS appear on the GOP's first video PES, then on the first PES that
//!   starts an access unit at least 16 frames after the last stamped one.
//!
//! The format rules, and the reason for each, are in `docs/VIDEO.md`.

use crate::error::{Error, Result};

/// PMF header and program-stream pack size.
pub const SECTOR: usize = 2048;
/// Width of an `ICON1.PMF`, in pixels.
pub const ICON1_WIDTH: u32 = 144;
/// Height of an `ICON1.PMF`, in pixels.
pub const ICON1_HEIGHT: u32 = 80;
/// Frames between IDR pictures in the reference icon.
pub const GOP_FRAMES: usize = 59;
/// 90 kHz ticks per frame at 29.97 fps.
pub const FRAME_TICKS: u64 = 3003;

const PACK_HEADER: usize = 14;
const FIRST_PTS: u64 = 90_000;
const PTS_INTERVAL_FRAMES: usize = 16;
/// Mux rate, in units of 50 bytes/s.
const MUX_RATE: u32 = 25_000;
/// First SCR, 27 MHz, as in the reference.
const SCR_START: u64 = 3_044_236;
/// 27 MHz ticks one pack takes at the mux rate, times [`SCR_DENOMINATOR`].
const SCR_PER_PACK_SCALED: u64 =
    SECTOR as u64 * 27_000_000 * SCR_DENOMINATOR / (MUX_RATE as u64 * 50);
/// SCR is tracked in fifths of a tick: one pack is 44236.8 ticks.
const SCR_DENOMINATOR: u64 = 5;
/// 90 kHz; reference pack 0 arrives this long before its DTS.
const DELIVERY_LEAD: u64 = 76_850;
/// P-STD buffer size, in KiB.
const STD_BUFFER_KB: u16 = 0x55;

const SYSTEM_HEADER: [u8; 18] = [
    0x00, 0x00, 0x01, 0xBB, 0x00, 0x0C, 0x80, 0xC3, 0x51, 0x80, 0xF0, 0x7F, 0xB9, 0xE0, 0x55, 0xBD,
    0xE0, 0x08,
];

const NAL_SEI: u8 = 6;
const NAL_IDR: u8 = 5;
const NAL_AUD: u8 = 9;
const SEI_USER_DATA_UNREGISTERED: u8 = 5;

/// One coded picture: its NAL units, each behind a 4-byte start code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessUnit {
    pub data: Vec<u8>,
    pub idr: bool,
}

/// A muxed PMF and what went into it.
#[derive(Debug, Clone)]
pub struct Pmf {
    pub data: Vec<u8>,
    pub frames: usize,
    pub gops: usize,
    /// Program-stream packs after the header.
    pub packs: usize,
}

/// Whether `data` begins like an H.264 Annex B elementary stream.
pub fn is_annex_b(data: &[u8]) -> bool {
    data.starts_with(&[0, 0, 0, 1]) || data.starts_with(&[0, 0, 1])
}

/// Whether `data` is a PSMF file.
pub fn is_pmf(data: &[u8]) -> bool {
    data.starts_with(b"PSMF")
}

/// Split an Annex B stream into NAL payloads, start codes removed.
fn nal_units(stream: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= stream.len() {
        if stream[i..i + 3] == [0, 0, 1] {
            starts.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    starts
        .iter()
        .enumerate()
        .map(|(n, &start)| {
            let mut end = starts.get(n + 1).map_or(stream.len(), |next| next - 3);
            // The leading zero of a 4-byte start code, or trailing zero bytes.
            while end > start && stream[end - 1] == 0 {
                end -= 1;
            }
            &stream[start..end]
        })
        .collect()
}

/// Group an Annex B stream's NAL units into access units at each delimiter.
///
/// x264's user-data-unregistered SEI (its version string) is dropped; Sony's
/// streams carry none.
pub fn access_units(stream: &[u8]) -> Result<Vec<AccessUnit>> {
    let mut units: Vec<AccessUnit> = Vec::new();
    for nal in nal_units(stream) {
        let Some(&first) = nal.first() else {
            continue;
        };
        let kind = first & 0x1F;
        if kind == NAL_AUD {
            units.push(AccessUnit {
                data: Vec::new(),
                idr: false,
            });
        }
        if kind == NAL_SEI && nal.get(1) == Some(&SEI_USER_DATA_UNREGISTERED) {
            continue;
        }
        let Some(unit) = units.last_mut() else {
            return Err(Error::InvalidVideo(
                "the H.264 stream must open with an access-unit delimiter".into(),
            ));
        };
        unit.idr |= kind == NAL_IDR;
        unit.data.extend_from_slice(&[0, 0, 0, 1]);
        unit.data.extend_from_slice(nal);
    }
    Ok(units)
}

/// A 33-bit timestamp in the 5-byte PES form, behind a 4-bit prefix.
fn ts5(prefix: u8, t: u64) -> [u8; 5] {
    [
        (prefix << 4) | ((((t >> 30) & 7) as u8) << 1) | 1,
        (t >> 22) as u8,
        ((((t >> 15) & 0x7F) as u8) << 1) | 1,
        (t >> 7) as u8,
        (((t & 0x7F) as u8) << 1) | 1,
    ]
}

fn pack_header(scr: u64) -> [u8; PACK_HEADER] {
    let (base, ext) = (scr / 300, scr % 300);
    let rate = (MUX_RATE << 2) | 3;
    [
        0x00,
        0x00,
        0x01,
        0xBA,
        0x40 | ((((base >> 30) & 7) as u8) << 3) | 0x04 | (((base >> 28) & 3) as u8),
        (base >> 20) as u8,
        ((((base >> 15) & 0x1F) as u8) << 3) | 0x04 | (((base >> 13) & 3) as u8),
        (base >> 5) as u8,
        (((base & 0x1F) as u8) << 3) | 0x04 | (((ext >> 7) & 3) as u8),
        (((ext & 0x7F) as u8) << 1) | 1,
        (rate >> 16) as u8,
        (rate >> 8) as u8,
        rate as u8,
        0xF8,
    ]
}

fn pes(out: &mut Vec<u8>, stream_id: u8, header: &[u8], payload: &[u8]) {
    let length = (header.len() + payload.len()) as u16;
    out.extend_from_slice(&[0, 0, 1, stream_id]);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(payload);
}

fn video_header(pts: Option<u64>, pstd: bool, stuffing: usize) -> Vec<u8> {
    let mut fields = Vec::new();
    let mut flags = 0u8;
    if let Some(pts) = pts {
        flags |= 0xC0;
        fields.extend_from_slice(&ts5(3, pts));
        fields.extend_from_slice(&ts5(1, pts - FRAME_TICKS));
    }
    if pstd {
        flags |= 0x01;
        fields.extend_from_slice(&[0x1E, 0x60 | (STD_BUFFER_KB >> 8) as u8, STD_BUFFER_KB as u8]);
    }
    fields.resize(fields.len() + stuffing, 0xFF);
    let mut header = vec![0x81, flags, fields.len() as u8];
    header.extend_from_slice(&fields);
    header
}

/// One pack of a GOP before its pack header: the bytes of the GOP's video
/// it carries, and the access unit it stamps, if any.
struct PackPlan {
    stamp: Option<usize>,
    start: usize,
    end: usize,
    spare: usize,
}

/// Lay one GOP out in packs: each pack's contents after the pack header, and
/// the DTS of the access unit its first video byte belongs to.
fn mux_gop(units: &[AccessUnit], first_frame: usize) -> Result<Vec<(Vec<u8>, u64)>> {
    let data: Vec<u8> = units.iter().flat_map(|u| u.data.iter().copied()).collect();
    let mut starts = Vec::with_capacity(units.len());
    let mut offset = 0;
    for unit in units {
        starts.push(offset);
        offset += unit.data.len();
    }
    let index_len = 6 + 18 + 4 * units.len();

    let mut packs: Vec<PackPlan> = Vec::new();
    let mut pos = 0;
    let mut last_stamp = 0;
    while pos < data.len() {
        let first = packs.is_empty();
        let mut room = SECTOR - PACK_HEADER;
        if first {
            room = room
                .checked_sub(SYSTEM_HEADER.len() + index_len)
                .filter(|r| *r > 9 + 13)
                .ok_or_else(|| {
                    Error::InvalidVideo(format!(
                        "a GOP of {} pictures is too long for its pack index",
                        units.len()
                    ))
                })?;
        }
        let (stamp, header_len) = if first {
            (Some(0), 9 + 13)
        } else {
            // Stamp the first access unit that starts in this pack, if it is
            // far enough from the last stamped one.
            let end = pos + (room - (9 + 10)).min(data.len() - pos);
            let candidate = starts.iter().position(|&s| pos <= s && s < end);
            match candidate {
                Some(i) if i >= last_stamp + PTS_INTERVAL_FRAMES => (Some(i), 9 + 10),
                _ => (None, 9),
            }
        };
        let take = (room - header_len).min(data.len() - pos);
        if let Some(stamp) = stamp {
            last_stamp = stamp;
        }
        packs.push(PackPlan {
            stamp,
            start: pos,
            end: pos + take,
            spare: room - header_len - take,
        });
        pos += take;
    }

    // The pack (relative to the GOP) holding the last byte of each unit.
    let pack_of = |byte: usize| {
        packs
            .iter()
            .position(|p| p.start <= byte && byte < p.end)
            .expect("every byte is in a pack")
    };
    let mut ends: Vec<usize> = units
        .iter()
        .zip(&starts)
        .map(|(u, &s)| pack_of(s + u.data.len() - 1))
        .collect();
    let last = *ends.last().expect("a GOP has a picture");
    ends.resize(ends.len().max(4), last);

    let mut index = vec![0x01, 0xE0];
    for &end in &ends[..4] {
        index.extend_from_slice(&(end as u16).to_be_bytes());
    }
    index.extend_from_slice(&[0, 0, 0, 0]);
    index.extend_from_slice(&((2 + 4 * units.len()) as u16).to_be_bytes());
    index.extend_from_slice(&(units.len() as u16).to_be_bytes());
    for (i, unit) in units.iter().enumerate() {
        let flag: u16 = if i + 1 < units.len() { 0x0080 } else { 0 };
        index.extend_from_slice(&flag.to_be_bytes());
        index.extend_from_slice(&(unit.data.len() as u16).to_be_bytes());
    }
    debug_assert_eq!(6 + index.len(), index_len);

    let mut out = Vec::with_capacity(packs.len());
    for (n, plan) in packs.iter().enumerate() {
        let pts = plan
            .stamp
            .map(|s| FIRST_PTS + (first_frame + s) as u64 * FRAME_TICKS);
        let (stuffing, padding) = if plan.spare >= 6 {
            (0, plan.spare - 6)
        } else {
            (plan.spare, 0)
        };
        let mut packets = Vec::with_capacity(SECTOR - PACK_HEADER);
        if n == 0 {
            packets.extend_from_slice(&SYSTEM_HEADER);
            pes(&mut packets, 0xBF, &[], &index);
        }
        pes(
            &mut packets,
            0xE0,
            &video_header(pts, n == 0, stuffing),
            &data[plan.start..plan.end],
        );
        if plan.spare >= 6 {
            pes(&mut packets, 0xBE, &[], &vec![0xFF; padding]);
        }
        debug_assert_eq!(PACK_HEADER + packets.len(), SECTOR);
        let au = units
            .iter()
            .zip(&starts)
            .position(|(u, &s)| s + u.data.len() > plan.start)
            .expect("the pack starts inside a picture");
        // One frame before the unit's own DTS slot: the reference's timing.
        let dts = (FIRST_PTS + ((first_frame + au) as u64) * FRAME_TICKS) - FRAME_TICKS;
        out.push((packets, dts));
    }
    Ok(out)
}

fn header(stream_size: usize, frames: usize) -> Vec<u8> {
    let end = FIRST_PTS + frames as u64 * FRAME_TICKS;
    let t6 = |t: u64| -> [u8; 6] { t.to_be_bytes()[2..].try_into().expect("6 bytes") };
    let mut meta = Vec::new();
    meta.extend_from_slice(&0x3Eu32.to_be_bytes());
    meta.extend_from_slice(&t6(FIRST_PTS));
    meta.extend_from_slice(&t6(end));
    meta.extend_from_slice(&MUX_RATE.to_be_bytes());
    meta.extend_from_slice(&90_000u32.to_be_bytes());
    meta.extend_from_slice(&[0x01, 0x01]);
    meta.extend_from_slice(&0x24u32.to_be_bytes());
    meta.extend_from_slice(&t6(FIRST_PTS));
    meta.extend_from_slice(&t6(end));
    meta.extend_from_slice(&1u16.to_be_bytes());
    meta.extend_from_slice(&0x12u32.to_be_bytes());
    meta.extend_from_slice(&1u16.to_be_bytes());
    meta.extend_from_slice(&[0xE0, 0x00, 0x20, 0x55]);
    meta.extend_from_slice(&[0; 8]);
    meta.extend_from_slice(&[(ICON1_WIDTH / 16) as u8, (ICON1_HEIGHT / 16) as u8, 0, 0]);

    let mut h = vec![0u8; SECTOR];
    h[0..8].copy_from_slice(b"PSMF0014");
    h[8..12].copy_from_slice(&(SECTOR as u32).to_be_bytes());
    h[12..16].copy_from_slice(&(stream_size as u32).to_be_bytes());
    h[0x50..0x50 + meta.len()].copy_from_slice(&meta);
    h
}

/// Mux a 144 × 80, 29.97 fps H.264 Annex B stream into a PMF.
///
/// The stream must carry an access-unit delimiter before every picture and
/// open with an IDR picture; each IDR picture starts a GOP. Its dimensions
/// and frame rate are taken on trust: the header always describes a 144 × 80
/// icon.
pub fn mux(stream: &[u8]) -> Result<Pmf> {
    let units = access_units(stream)?;
    if !units.first().is_some_and(|u| u.idr) {
        return Err(Error::InvalidVideo(
            "the H.264 stream must open with an IDR picture".into(),
        ));
    }
    if let Some(big) = units.iter().find(|u| u.data.len() > u16::MAX as usize) {
        return Err(Error::InvalidVideo(format!(
            "a {}-byte picture is too large for the pack index",
            big.data.len()
        )));
    }

    let mut gops: Vec<(usize, &[AccessUnit])> = Vec::new();
    let mut gop_start = 0;
    for i in 1..=units.len() {
        if i == units.len() || units[i].idr {
            gops.push((gop_start, &units[gop_start..i]));
            gop_start = i;
        }
    }

    let mut body = Vec::new();
    let mut scr = SCR_START * SCR_DENOMINATOR;
    for &(first_frame, gop) in &gops {
        for (packets, dts) in mux_gop(gop, first_frame)? {
            let due = dts.saturating_sub(DELIVERY_LEAD) * 300 * SCR_DENOMINATOR;
            scr = scr.max(due);
            // Never a tie: one pack is a whole number of fifths.
            let rounded = (scr + SCR_DENOMINATOR / 2) / SCR_DENOMINATOR;
            body.extend_from_slice(&pack_header(rounded));
            body.extend_from_slice(&packets);
            scr += SCR_PER_PACK_SCALED;
        }
    }

    let packs = body.len() / SECTOR;
    let mut data = header(body.len(), units.len());
    data.extend_from_slice(&body);
    Ok(Pmf {
        data,
        frames: units.len(),
        gops: gops.len(),
        packs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An Annex B stream of `frames` pictures, an IDR every `gop`, each
    /// picture `size` bytes of slice data.
    pub(crate) fn synthetic_stream(frames: usize, gop: usize, size: usize) -> Vec<u8> {
        let mut s = Vec::new();
        for i in 0..frames {
            s.extend_from_slice(&[0, 0, 0, 1, 0x09, 0x10]);
            if i % gop == 0 {
                s.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x4D, 0x40, 0x15]);
                s.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xEE, 0x3C, 0x80]);
                // x264's version string, which the muxer drops.
                s.extend_from_slice(&[0, 0, 0, 1, 0x06, 0x05, 0x02, 0xAA, 0xBB, 0x80]);
            }
            let kind = if i % gop == 0 { 0x65 } else { 0x41 };
            s.extend_from_slice(&[0, 0, 1, kind]);
            s.extend((0..size).map(|b| (b % 251) as u8 | 1));
        }
        s
    }

    #[test]
    fn splits_access_units_and_drops_user_data() {
        let units = access_units(&synthetic_stream(3, 2, 10)).unwrap();
        assert_eq!(units.len(), 3);
        assert!(units[0].idr && !units[1].idr && units[2].idr);
        // AUD, SPS, PPS and slice; the SEI is gone.
        assert_eq!(units[0].data.len(), 6 + 8 + 8 + 4 + 1 + 10);
        assert!(!units[0].data.windows(2).any(|w| w == [0x06, 0x05]));
    }

    #[test]
    fn rejects_streams_it_cannot_index() {
        assert!(mux(&[0, 0, 0, 1, 0x41, 1, 2]).is_err());
        let mut no_idr = vec![0, 0, 0, 1, 0x09, 0x10, 0, 0, 1, 0x41];
        no_idr.extend_from_slice(&[1; 16]);
        assert!(mux(&no_idr).is_err());
        assert!(mux(&synthetic_stream(1, 1, 70_000)).is_err());
        assert!(mux(&[]).is_err());
    }

    #[test]
    fn writes_whole_packs_behind_a_psmf_header() {
        let pmf = mux(&synthetic_stream(150, GOP_FRAMES, 900)).unwrap();
        assert_eq!(pmf.frames, 150);
        assert_eq!(pmf.gops, 3);
        assert_eq!(pmf.data.len(), SECTOR * (1 + pmf.packs));
        assert_eq!(&pmf.data[..8], b"PSMF0014");
        let size = u32::from_be_bytes(pmf.data[12..16].try_into().unwrap());
        assert_eq!(size as usize, pmf.packs * SECTOR);
        assert_eq!(&pmf.data[0x8E..0x92], &[144 / 16, 80 / 16, 0, 0]);

        let mut gop_packs = 0;
        let mut last_scr = 0;
        for pack in pmf.data[SECTOR..].chunks(SECTOR) {
            assert_eq!(&pack[..4], &[0, 0, 1, 0xBA]);
            let b = &pack[4..10];
            let base = (u64::from(b[0] >> 3) & 7) << 30
                | (u64::from(b[0]) & 3) << 28
                | u64::from(b[1]) << 20
                | u64::from(b[2] >> 3) << 15
                | (u64::from(b[2]) & 3) << 13
                | u64::from(b[3]) << 5
                | u64::from(b[4] >> 3);
            assert!(base > last_scr, "SCR must rise");
            last_scr = base;
            if pack[14..18] == [0, 0, 1, 0xBB] {
                gop_packs += 1;
                // System header, then the 0xBF index.
                assert_eq!(&pack[32..36], &[0, 0, 1, 0xBF]);
            }
        }
        assert_eq!(gop_packs, pmf.gops);
    }

    #[test]
    fn index_lists_every_picture_size() {
        let stream = synthetic_stream(20, 20, 500);
        let units = access_units(&stream).unwrap();
        let pmf = mux(&stream).unwrap();
        let first = &pmf.data[SECTOR..2 * SECTOR];
        let index = &first[32 + 6..];
        assert_eq!(&index[..2], &[0x01, 0xE0]);
        assert_eq!(u16::from_be_bytes([index[16], index[17]]), 20);
        for (i, unit) in units.iter().enumerate() {
            let at = 18 + 4 * i;
            let size = u16::from_be_bytes([index[at + 2], index[at + 3]]);
            assert_eq!(size as usize, unit.data.len());
        }
    }

    #[test]
    fn packs_carry_the_stream_unchanged() {
        let stream = synthetic_stream(70, GOP_FRAMES, 1300);
        let units = access_units(&stream).unwrap();
        let pmf = mux(&stream).unwrap();
        let mut video = Vec::new();
        for pack in pmf.data[SECTOR..].chunks(SECTOR) {
            let mut at = PACK_HEADER;
            while at + 6 <= pack.len() {
                let id = pack[at + 3];
                if id == 0xBB {
                    at += 6 + u16::from_be_bytes([pack[at + 4], pack[at + 5]]) as usize;
                    continue;
                }
                let len = u16::from_be_bytes([pack[at + 4], pack[at + 5]]) as usize;
                if id == 0xE0 {
                    let header_len = 3 + pack[at + 8] as usize;
                    video.extend_from_slice(&pack[at + 6 + header_len..at + 6 + len]);
                }
                at += 6 + len;
            }
            assert_eq!(at, SECTOR);
        }
        let expected: Vec<u8> = units.iter().flat_map(|u| u.data.clone()).collect();
        assert_eq!(video, expected);
    }
}
