use std::io;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"CRU1";
const HEADER_LEN: usize = 17;
const TAG_LEN: usize = 16;
pub(crate) const MAX_DATAGRAM: usize = 1200;
pub(crate) const MAX_PLAINTEXT: usize = MAX_DATAGRAM - HEADER_LEN - TAG_LEN;
pub(crate) const MAX_FRAGMENTS: u16 = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum PacketKind {
    Hello = 1,
    Input = 2,
    Resize = 3,
    FrameAck = 4,
    Frame = 5,
    Close = 6,
    End = 7,
    Ping = 8,
    Pong = 9,
}

impl TryFrom<u8> for PacketKind {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Input),
            3 => Ok(Self::Resize),
            4 => Ok(Self::FrameAck),
            5 => Ok(Self::Frame),
            6 => Ok(Self::Close),
            7 => Ok(Self::End),
            8 => Ok(Self::Ping),
            9 => Ok(Self::Pong),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown Crush packet kind",
            )),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Packet {
    pub(crate) kind: PacketKind,
    pub(crate) sequence: u64,
    pub(crate) fragment: u16,
    pub(crate) fragments: u16,
    pub(crate) payload: Zeroizing<Vec<u8>>,
}

pub(crate) struct SessionCrypto {
    cipher: ChaCha20Poly1305,
}

impl SessionCrypto {
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(key)
                .expect("a 32-byte Crush key is always valid"),
        }
    }

    pub(crate) fn seal(
        &self,
        kind: PacketKind,
        sequence: u64,
        fragment: u16,
        fragments: u16,
        plaintext: &[u8],
    ) -> io::Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Crush packet payload exceeds the safe datagram size",
            ));
        }
        validate_fragment(fragment, fragments)?;

        let header = header(kind, sequence, fragment, fragments);
        let nonce_bytes = nonce(kind, sequence, fragment);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| io::Error::other("failed to encrypt Crush packet"))?;
        let mut datagram = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        datagram.extend_from_slice(&header);
        datagram.extend_from_slice(&ciphertext);
        Ok(datagram)
    }

    pub(crate) fn open(&self, datagram: &[u8]) -> io::Result<Packet> {
        if datagram.len() < HEADER_LEN + TAG_LEN || datagram.len() > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Crush datagram length",
            ));
        }
        if &datagram[..4] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Crush datagram marker",
            ));
        }

        let kind = PacketKind::try_from(datagram[4])?;
        let sequence = u64::from_be_bytes(
            datagram[5..13]
                .try_into()
                .expect("validated packet header length"),
        );
        let fragment = u16::from_be_bytes(
            datagram[13..15]
                .try_into()
                .expect("validated packet header length"),
        );
        let fragments = u16::from_be_bytes(
            datagram[15..17]
                .try_into()
                .expect("validated packet header length"),
        );
        validate_fragment(fragment, fragments)?;
        let nonce_bytes = nonce(kind, sequence, fragment);
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &datagram[HEADER_LEN..],
                    aad: &datagram[..HEADER_LEN],
                },
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Crush packet authentication failed",
                )
            })?;

        Ok(Packet {
            kind,
            sequence,
            fragment,
            fragments,
            payload: Zeroizing::new(plaintext),
        })
    }
}

pub(crate) fn generate_key() -> io::Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *key)
        .map_err(|error| io::Error::other(format!("OS randomness unavailable: {error}")))?;
    Ok(key)
}

pub(crate) fn encode_key(key: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in key {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn decode_key(encoded: &str) -> io::Result<Zeroizing<[u8; 32]>> {
    if encoded.len() != 64 || !encoded.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Crush bootstrap key length",
        ));
    }
    let bytes = encoded.as_bytes();
    let mut key = Zeroizing::new([0_u8; 32]);
    for (index, output) in key.iter_mut().enumerate() {
        *output = (decode_nibble(bytes[index * 2])? << 4) | decode_nibble(bytes[index * 2 + 1])?;
    }
    Ok(key)
}

fn decode_nibble(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid hexadecimal Crush bootstrap key",
        )),
    }
}

fn validate_fragment(fragment: u16, fragments: u16) -> io::Result<()> {
    if fragments == 0 || fragments > MAX_FRAGMENTS || fragment >= fragments {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Crush fragment coordinates",
        ));
    }
    Ok(())
}

fn header(kind: PacketKind, sequence: u64, fragment: u16, fragments: u16) -> [u8; HEADER_LEN] {
    let mut bytes = [0_u8; HEADER_LEN];
    bytes[..4].copy_from_slice(MAGIC);
    bytes[4] = kind as u8;
    bytes[5..13].copy_from_slice(&sequence.to_be_bytes());
    bytes[13..15].copy_from_slice(&fragment.to_be_bytes());
    bytes[15..17].copy_from_slice(&fragments.to_be_bytes());
    bytes
}

fn nonce(kind: PacketKind, sequence: u64, fragment: u16) -> [u8; 12] {
    // Retransmissions reuse a nonce only with byte-identical contents.
    let mut bytes = [0_u8; 12];
    bytes[0] = kind as u8;
    bytes[1..9].copy_from_slice(&sequence.to_be_bytes());
    bytes[9..11].copy_from_slice(&fragment.to_be_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_packet_round_trip() {
        let key = [7_u8; 32];
        let crypto = SessionCrypto::new(&key);
        let datagram = crypto.seal(PacketKind::Frame, 42, 2, 4, b"state").unwrap();
        let packet = crypto.open(&datagram).unwrap();
        assert_eq!(packet.kind, PacketKind::Frame);
        assert_eq!(packet.sequence, 42);
        assert_eq!(packet.fragment, 2);
        assert_eq!(packet.fragments, 4);
        assert_eq!(&*packet.payload, b"state");
    }

    #[test]
    fn keepalive_pong_preserves_its_monotonic_sequence() {
        let crypto = SessionCrypto::new(&[3_u8; 32]);
        let datagram = crypto.seal(PacketKind::Pong, 27, 0, 1, &[]).unwrap();
        let packet = crypto.open(&datagram).unwrap();
        assert_eq!(packet.kind, PacketKind::Pong);
        assert_eq!(packet.sequence, 27);
        assert!(packet.payload.is_empty());
    }

    #[test]
    fn authentication_rejects_header_and_payload_changes() {
        let crypto = SessionCrypto::new(&[9_u8; 32]);
        let original = crypto.seal(PacketKind::Input, 8, 0, 1, b"hello").unwrap();
        for index in [4, 8, original.len() - 1] {
            let mut changed = original.clone();
            changed[index] ^= 1;
            assert!(crypto.open(&changed).is_err(), "changed byte {index}");
        }
    }

    #[test]
    fn key_text_round_trips_and_rejects_malformed_values() {
        let key = [0xab; 32];
        assert_eq!(&*decode_key(&encode_key(&key)).unwrap(), &key);
        assert!(decode_key("ab").is_err());
        assert!(decode_key(&"z".repeat(64)).is_err());
    }
}
