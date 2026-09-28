//! The RIFF/WAVE container an `SND0.AT3` lives in.

/// `WAVE_FORMAT_SONY_SCX`: ATRAC3 in a WAVE file.
pub const FORMAT_ATRAC3: u16 = 0x0270;

/// The `fmt ` chunk of a known-good LP4 SND0, byte for byte.
///
/// Taken from a file that plays in the XMB of a PSP Slim. Everything after
/// the first sixteen bytes is the 14-byte ATRAC3 extension:
///
/// | bytes | value    | meaning                                  |
/// |-------|----------|------------------------------------------|
/// | 0-1   | 1        | always 1                                 |
/// | 2-5   | 0x1000   | samples per channel per block, as stored |
/// | 6-7   | 1        | joint stereo                             |
/// | 8-9   | 1        | joint stereo, repeated                   |
/// | 10-11 | 1        | always 1                                 |
/// | 12-13 | 0        | always 0                                 |
pub const LP4_FMT: [u8; 32] = [
    0x70, 0x02, // format tag: ATRAC3
    0x02, 0x00, // channels
    0x44, 0xAC, 0x00, 0x00, // 44100 Hz
    0x4C, 0x20, 0x00, 0x00, // 8268 bytes/s: 66144 bps
    0xC0, 0x00, // block align: 192
    0x00, 0x00, // bits per sample: none, it is compressed
    0x0E, 0x00, // 14 extension bytes follow
    0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
];

/// Samples of the stream before the loop starts.
///
/// The XMB loops an SND0 only when it carries a loop point, and it honours
/// one only alongside a `fact` chunk whose delay is where the loop starts;
/// a loop without `fact` makes it play nothing. On hardware, a delay of one
/// frame loops cleanly. The first frame decodes from an empty decoder, so it
/// is exactly the part skipped.
pub const LOOP_DELAY: u32 = 1024;

/// Wrap LP4 frames in the container: `fmt ` then `data`, nothing else.
///
/// The XMB plays such a file once and stops. [`write_lp4_looped`] is what
/// pspbuild writes.
pub fn write_lp4(frames: &[u8]) -> Vec<u8> {
    write_chunks(&[(b"fmt ", &LP4_FMT), (b"data", frames)])
}

/// Wrap LP4 frames that loop: `fmt `, `fact`, `smpl`, then `data`.
///
/// `samples` is the length of the loop. The stream holds [`LOOP_DELAY`]
/// samples before it; the loop is samples `LOOP_DELAY` to
/// `LOOP_DELAY + samples - 1`, repeated forever.
pub fn write_lp4_looped(frames: &[u8], samples: u32) -> Vec<u8> {
    let fact = words(&[samples, LOOP_DELAY]);
    let smpl = smpl_chunk(LOOP_DELAY, LOOP_DELAY + samples - 1);
    write_chunks(&[
        (b"fmt ", &LP4_FMT),
        (b"fact", &fact),
        (b"smpl", &smpl),
        (b"data", frames),
    ])
}

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// A `smpl` chunk with one forward loop, laid out as Sony's own SND0s have it:
/// the sample period in nanoseconds, MIDI note 60, one loop, and 24 in the
/// sampler-data field where the standard would have 0.
fn smpl_chunk(start: u32, end: u32) -> Vec<u8> {
    words(&[0, 0, 22_676, 60, 0, 0, 0, 1, 24, 0, 0, start, end, 0, 0])
}

fn write_chunks(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
    let body: usize = chunks.iter().map(|(_, d)| 8 + d.len() + d.len() % 2).sum();
    let mut out = Vec::with_capacity(12 + body);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&((4 + body) as u32).to_le_bytes());
    out.extend_from_slice(b"WAVE");
    for (id, data) in chunks {
        out.extend_from_slice(*id);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(0);
        }
    }
    out
}

/// The `fact` chunk of an ATRAC3 file: how many samples it holds, and how
/// many decoded samples come before the first of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fact {
    pub samples: u32,
    pub delay: u32,
}

/// The first loop of a `smpl` chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loop {
    pub start: u32,
    pub end: u32,
    /// 0 means forever.
    pub play_count: u32,
}

/// One chunk of a RIFF file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub id: [u8; 4],
    /// Offset of the chunk header in the file.
    pub offset: usize,
    /// Size of the chunk body, as declared.
    pub size: u32,
}

impl Chunk {
    /// The identifier as text, for messages.
    pub fn name(&self) -> String {
        String::from_utf8_lossy(&self.id).trim_end().to_string()
    }

    fn body<'a>(&self, file: &'a [u8]) -> &'a [u8] {
        let start = self.offset + 8;
        &file[start..start + self.size as usize]
    }
}

/// The `fmt ` chunk, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fmt {
    pub format_tag: u16,
    pub channels: u16,
    pub sample_rate: u32,
    pub byte_rate: u32,
    pub block_align: u16,
    pub bits_per_sample: u16,
    /// Bytes after the declared extension size, when present.
    pub extension: Vec<u8>,
    /// The whole chunk body.
    pub raw: Vec<u8>,
}

impl Fmt {
    fn parse(body: &[u8]) -> Result<Fmt, String> {
        if body.len() < 16 {
            return Err(format!(
                "the fmt chunk is {} bytes, too short to hold a format",
                body.len()
            ));
        }
        let u16_at = |o: usize| u16::from_le_bytes([body[o], body[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes(body[o..o + 4].try_into().expect("4 bytes"));
        let extension = if body.len() >= 18 {
            let declared = usize::from(u16_at(16));
            body[18..].get(..declared).unwrap_or(&body[18..]).to_vec()
        } else {
            Vec::new()
        };
        Ok(Fmt {
            format_tag: u16_at(0),
            channels: u16_at(2),
            sample_rate: u32_at(4),
            byte_rate: u32_at(8),
            block_align: u16_at(12),
            bits_per_sample: u16_at(14),
            extension,
            raw: body.to_vec(),
        })
    }

    /// Whether the ATRAC3 extension marks the stream as joint stereo.
    pub fn joint_stereo(&self) -> Option<bool> {
        (self.extension.len() >= 8)
            .then(|| u16::from_le_bytes([self.extension[6], self.extension[7]]) == 1)
    }
}

/// A parsed RIFF/WAVE file.
#[derive(Debug, Clone)]
pub struct Wave<'a> {
    pub chunks: Vec<Chunk>,
    pub fmt: Option<Fmt>,
    /// `fact`, when present and at least eight bytes.
    pub fact: Option<Fact>,
    /// The first loop of `smpl`, when there is one.
    pub loop_points: Option<Loop>,
    pub data: Option<&'a [u8]>,
    /// Declared size in the RIFF header.
    pub riff_size: u32,
}

/// Whether `data` is a RIFF/WAVE file.
pub fn is_wave(data: &[u8]) -> bool {
    data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WAVE"
}

/// Parse the chunk structure. Fails only when the structure itself is broken.
pub fn parse(file: &[u8]) -> Result<Wave<'_>, String> {
    if !is_wave(file) {
        return Err("not a RIFF/WAVE file".into());
    }
    let riff_size = u32::from_le_bytes(file[4..8].try_into().expect("4 bytes"));
    let mut chunks = Vec::new();
    let mut fmt = None;
    let mut data = None;
    let mut fact = None;
    let mut loop_points = None;
    let mut offset = 12;
    while offset < file.len() {
        if offset + 8 > file.len() {
            return Err(format!(
                "{} stray bytes after the last chunk",
                file.len() - offset
            ));
        }
        let id: [u8; 4] = file[offset..offset + 4].try_into().expect("4 bytes");
        let size = u32::from_le_bytes(file[offset + 4..offset + 8].try_into().expect("4 bytes"));
        let chunk = Chunk { id, offset, size };
        if offset + 8 + size as usize > file.len() {
            return Err(format!(
                "the '{}' chunk claims {size} bytes but only {} remain",
                chunk.name(),
                file.len() - offset - 8
            ));
        }
        match &id {
            b"fmt " if fmt.is_none() => fmt = Some(Fmt::parse(chunk.body(file))?),
            b"data" if data.is_none() => data = Some(chunk.body(file)),
            b"fact" if fact.is_none() => {
                let body = chunk.body(file);
                let word = |i: usize| {
                    u32::from_le_bytes(body[i * 4..i * 4 + 4].try_into().expect("4 bytes"))
                };
                if body.len() >= 8 {
                    fact = Some(Fact {
                        samples: word(0),
                        delay: word(1),
                    });
                }
            }
            b"smpl" if loop_points.is_none() => {
                let body = chunk.body(file);
                let word = |i: usize| {
                    u32::from_le_bytes(body[i * 4..i * 4 + 4].try_into().expect("4 bytes"))
                };
                if body.len() >= 60 && word(7) >= 1 {
                    loop_points = Some(Loop {
                        start: word(11),
                        end: word(12),
                        play_count: word(14),
                    });
                }
            }
            _ => {}
        }
        // Chunks are padded to an even length.
        offset += 8 + size as usize + (size as usize & 1);
        chunks.push(chunk);
    }
    Ok(Wave {
        chunks,
        fmt,
        fact,
        loop_points,
        data,
        riff_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_files_parse_back() {
        let frames = vec![0xA2u8; 192 * 3];
        let file = write_lp4(&frames);
        assert_eq!(file.len(), 60 + frames.len());
        let wave = parse(&file).unwrap();
        let names: Vec<_> = wave.chunks.iter().map(Chunk::name).collect();
        assert_eq!(names, ["fmt", "data"]);
        let fmt = wave.fmt.unwrap();
        assert_eq!(fmt.format_tag, FORMAT_ATRAC3);
        assert_eq!(fmt.block_align, 192);
        assert_eq!(fmt.byte_rate * 8, 66144);
        assert_eq!(fmt.joint_stereo(), Some(true));
        assert_eq!(wave.data.unwrap(), &frames[..]);
        assert_eq!(wave.riff_size as usize, file.len() - 8);
    }

    #[test]
    fn looped_files_parse_back() {
        let file = write_lp4_looped(&[0xA2u8; 192 * 5], 3000);
        let wave = parse(&file).unwrap();
        let names: Vec<_> = wave.chunks.iter().map(Chunk::name).collect();
        assert_eq!(names, ["fmt", "fact", "smpl", "data"]);
        assert_eq!(
            wave.fact,
            Some(Fact {
                samples: 3000,
                delay: 1024
            })
        );
        assert_eq!(
            wave.loop_points,
            Some(Loop {
                start: 1024,
                end: 4023,
                play_count: 0
            })
        );
        assert_eq!(wave.riff_size as usize, file.len() - 8);
        assert_eq!(wave.data.unwrap().len(), 192 * 5);
    }

    #[test]
    fn broken_structure_is_reported() {
        assert!(parse(b"RIFX\0\0\0\0WAVE").is_err());
        let mut file = write_lp4(&[0; 192]);
        file.truncate(file.len() - 1);
        assert!(parse(&file).unwrap_err().contains("claims"));
    }
}
