//! Shares processing.
use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::{convert::TryInto, ops::RangeInclusive};

use bitvec::prelude::{BitVec, Msb0};
use scrypt::{scrypt, Params};
use serde::Deserialize;
use sha2::{Digest, Sha512};
use xsalsa20poly1305::aead::{generic_array::GenericArray, Aead, KeyInit};
use xsalsa20poly1305::XSalsa20Poly1305;
use zeroize::Zeroize;

use crate::error::BananaError;

/// Allowed range for bits value.
///
/// Bits value is recorded in each share, and must be identical between shares
/// and within this allowed range. Bits value is used to stitch the shares
/// together correctly.
///
/// Currently existing banana split version `V1` sets bits value to `8`.
pub const BIT_RANGE: RangeInclusive<u32> = 3..=20;

/// Individual share data, successfully constructed only if corresponding json
/// contains valid values.
///
/// Constructed from the incoming QR data only. Bits are checked to be within
/// `BIT_RANGE` allowed limits.
#[derive(Debug)]
pub struct Share {
    version: Version,
    title: String,
    required_shares: usize,
    nonce: String,
    bits: u32,
    id: u32,
    content: Vec<u8>,
}

/// Raw share data, as recovered from json.
#[derive(Debug, Deserialize)]
struct ShareJson {
    v: Option<u8>,
    t: String,
    r: usize,
    d: String,
    n: String,
}

/// Version of banana split protocol.
///
/// Currently only `V1` could be explicitly announced in share json.
///
/// No version provided in share json results in `Undefined` variant.
///
/// Other versions are not supported and get rejected on [`Share`] construction.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Version {
    Undefined,
    V1,
}

impl Share {
    /// Construct new `Share` from QR data.
    ///
    /// QR data is provided as decoded QR code in `Vec<u8>` format without QR
    /// header and padding. QR is expected to represent a json String.
    pub fn new(share_qr_data: Vec<u8>) -> Result<Self, BananaError> {
        // transforming into String
        let share_string =
            String::from_utf8(share_qr_data).map_err(|_| BananaError::NotShareString)?;

        // parsing the string with json
        let share_parsed: ShareJson =
            serde_json::from_str(&share_string).map_err(|_| BananaError::JsonParsing)?;

        // determine protocol version
        let version = match share_parsed.v {
            None => Version::Undefined,
            Some(1) => Version::V1,
            Some(a) => return Err(BananaError::VersionNotSupported(a)),
        };

        // process the share data
        let share_chars: Vec<char> = share_parsed.d.chars().collect();

        // first share char is bits info in radix36 format
        let bits = match share_chars.first() {
            Some(a) => match a.to_digit(36) {
                Some(b) => {
                    // checking if bits value is within allowed limits
                    if BIT_RANGE.contains(&b) {
                        b
                    } else {
                        return Err(BananaError::BitsOutOfRange(b));
                    }
                }
                None => return Err(BananaError::ParseBit(*a)),
            },
            None => return Err(BananaError::EmptyShare),
        };

        // remaining share data is the share body;
        // it is processed depending on the version;
        let share_body = match version {
            // content is hex for version `Undefined`
            Version::Undefined => hex::decode(String::from_iter(&share_chars[1..]))
                .map_err(|_| BananaError::UndefinedBodyNotHex)?,

            // content is base64 for version `V1`
            Version::V1 => base64::decode(String::from_iter(&share_chars[1..]).into_bytes())
                .map_err(|_| BananaError::BodyNotBase64)?,
        };

        // maximum possible number of shares, `u32`;
        // bits never exceed 20;
        // `2^bits` with `bits = 20` or below always fits in `u32` limits
        let max = 2u32.pow(bits) - 1;

        // length of identificator piece in `u8` units that should be cut from
        // the beginning of the share_body;
        // could not exceed `4`; in given limits, does not exceed `3`;
        // starting zeroes are removed in length calculation
        let id_length = max.to_be_bytes().iter().skip_while(|x| x == &&0).count();

        // identifier piece (short `Vec<u8>`) and share content (`Vec<u8>`) separated
        let (identifier_piece, content) = match share_body.get(..id_length) {
            Some(a) => (a.to_vec(), share_body[id_length..].to_vec()),
            None => return Err(BananaError::ShareTooShort),
        };

        // current share id, `u32`
        let id = u32::from_be_bytes(
            [
                max.to_be_bytes()[..4 - id_length].to_vec(),
                identifier_piece,
            ]
            .concat()
            .try_into()
            .expect("fixed length of 4"),
        );

        Ok(Share {
            version,
            title: share_parsed.t,
            required_shares: share_parsed.r,
            nonce: share_parsed.n,
            bits,
            id,
            content,
        })
    }

    /// Share title.
    pub fn title(&self) -> String {
        self.title.to_owned()
    }
}

/// Shares collector.
///
/// Shares could be added only one by one.
#[derive(Debug)]
pub enum ShareCollection {
    /// No shares: freshly initiated or emptied.
    Empty,

    /// A set of compatible shares, with fewer shares than the required number.
    InProgress(SetInProgress),

    /// Combined shares data. Could be processed to get the secret.
    Ready(SetCombined),
}

impl ShareCollection {
    /// Initiate new share collecting.
    pub fn new() -> Self {
        Self::Empty
    }

    /// Re-start the share collecting.
    pub fn clear(&mut self) {
        *self = Self::Empty;
    }

    /// Add new share to existing collector.
    ///
    /// If after adding new share the required share number is achieved, shares
    /// get combined.
    pub fn add_share(&mut self, share: Share) -> Result<(), BananaError> {
        // add share
        match self {
            Self::Empty => {
                *self = Self::InProgress(SetInProgress::init(share));
            }
            Self::InProgress(in_progress) => {
                in_progress.add_share(share)?;
            }
            Self::Ready(_) => {}
        }

        // combine if have enough shares
        if let Self::InProgress(in_progress) = self {
            if in_progress.id_set.len() >= in_progress.required_shares {
                let combined = in_progress.combine()?;
                *self = Self::Ready(combined);
            }
        }

        Ok(())
    }
}

impl Default for ShareCollection {
    fn default() -> Self {
        Self::new()
    }
}

/// Incomplete set of compatible shares.
///
/// A share could be added to existing set only if the share and the set have
/// matching:
///
/// - `Version`
/// - title
/// - number of required shares
/// - nonce
/// - bits value
///
/// and:
///
/// - the share is not yet a part of the set
/// - has same content length as other shares in the set
///
/// Otherwise, adding the share would result in an error.
#[derive(Debug)]
pub struct SetInProgress {
    version: Version,
    title: String,
    required_shares: usize,
    nonce: String,
    bits: u32,
    id_set: Vec<u32>,
    content_length: usize,
    content_set: Vec<Vec<u8>>,
}

impl SetInProgress {
    /// New set from a [`Share`].
    fn init(share: Share) -> Self {
        Self {
            version: share.version,
            title: share.title,
            required_shares: share.required_shares,
            nonce: share.nonce,
            bits: share.bits,
            id_set: vec![share.id],
            content_length: share.content.len(),
            content_set: vec![share.content],
        }
    }

    /// Add new [`Share`] to existing set.
    fn add_share(&mut self, new_share: Share) -> Result<(), BananaError> {
        if new_share.version != self.version {
            return Err(BananaError::ShareVersionDifferent);
        } // should have same version

        if new_share.title != self.title {
            return Err(BananaError::ShareTitleDifferent {
                set: self.title(),
                new_share: new_share.title,
            });
        } // ... and same title

        if new_share.required_shares != self.required_shares {
            return Err(BananaError::ShareRequiredSharesDifferent);
        } // ... and same number of required shares

        if new_share.nonce != self.nonce {
            return Err(BananaError::ShareNonceDifferent);
        } // ... and same nonce

        if new_share.bits != self.bits {
            return Err(BananaError::ShareBitsDifferent);
        } // ... and bits

        if self.id_set.contains(&new_share.id) {
            return Err(BananaError::ShareAlreadyInSet);
        } // ... also should be a new share

        if self.content_length != new_share.content.len() {
            return Err(BananaError::ShareContentLengthDifferent);
        } // ... with same content length

        self.id_set.push(new_share.id);
        self.content_set.push(new_share.content);

        Ok(())
    }

    /// Combine `SetInProgress` into [`SetCombined`].
    ///
    /// Function must be applied only if the set is checked elsewhere to have at
    /// least the required number of shares.
    fn combine(&self) -> Result<SetCombined, BananaError> {
        // transpose content set
        // from
        // `Vec[[share1[1], share1[2] ... share1[N]], [share2[1], share2[2] ... share2[N]] ... [shareM[1], shareM[2] ... shareM[N]]]`
        // into
        // `Vec[[share1[1], share2[1] ... shareM[1]], [share1[2], share2[2] ... shareM[2]] ... [share1[N], share2[N] ... shareM[N]]]`
        let mut content_zipped: Vec<Vec<u32>> = Vec::with_capacity(self.content_length);
        for i in 0..self.content_length {
            let mut new: Vec<u32> = Vec::new();
            for j in 0..self.id_set.len() {
                new.push(self.content_set[j][i] as u32)
            }
            content_zipped.push(new);
        }

        // calculate logarithms and exponents in `GF(2^self.bits)`
        let (logs, exps) = generate_logs_and_exps(self.bits);

        // process and collect bit sequence from each element of content_zipped
        let mut result: BitVec<u32, Msb0> = BitVec::new();
        for content_zipped_element in content_zipped.iter() {
            // new element that will be processed; is calculated as `u32`, its value is always below `2^self.bits`;
            let new = lagrange(
                &self.id_set,
                content_zipped_element,
                &logs,
                &exps,
                self.bits,
            )?;

            // transform new element into new bitvec to operate on bits individually
            let new_bitvec: BitVec<u32, Msb0> = BitVec::from_vec(vec![new]);

            // in js code this crate follows, the bits string representation of new element (i.e. without leading zeroes)
            // was padded from left with zeroes so that the string length became multiple of `self.bits` number;
            // since the new element value is always below `2^self.bits`, this procedure effectively means keeping only
            // `self.bits` amount of bits from the element;
            // cut is the starting point after which the bits are retained;
            let cut = (32 - self.bits) as usize;

            // resulting bits are added into collection;
            result.extend_from_bitslice(&new_bitvec[cut..]);
        }

        // the js code this crate follows then calls for cutting all leading false bits
        // up until the first true, which serves as a padding marker,
        // cut padding marker as well, and then collect bytes with some padding on the left if necessary
        let result: BitVec<u8, Msb0> = result.into_iter().skip_while(|x| !*x).skip(1).collect();

        // transform result in its final form, `Vec<u8>`
        let data = result.into_vec();

        // process nonce, so that it is done before asking for a password
        let nonce = match base64::decode(self.nonce.as_bytes()) {
            Ok(a) => a,
            Err(_) => return Err(BananaError::NonceNotBase64),
        };

        // now the set is ready
        Ok(SetCombined {
            data,
            nonce,
            title: self.title.to_owned(),
        })
    }

    /// Current number of shares in set.
    pub fn shares_now(&self) -> usize {
        self.id_set.len()
    }

    /// Required number of shares.
    pub fn shares_required(&self) -> usize {
        self.required_shares
    }

    /// Share set title.
    pub fn title(&self) -> String {
        self.title.to_owned()
    }
}

/// Combined shares data.
#[derive(Debug)]
pub struct SetCombined {
    title: String,
    data: Vec<u8>,
    nonce: Vec<u8>,
}

impl SetCombined {
    /// Recover the secret with user-provided passphrase.
    pub fn recover_with_passphrase(&self, passphrase: &str) -> Result<String, BananaError> {
        // hash title into salt
        let mut hasher = Sha512::new();
        hasher.update(self.title.as_bytes());
        let salt = hasher.finalize();

        // set up the parameters for scrypt;
        // default ones are used
        let params = Params::new(15, 8, 1).expect("static checked params");

        // set up output buffer for scrypt;
        // must allocate here, empty output buffer is rejected
        let mut key: Vec<u8> = [0; 32].to_vec();

        // ... and scrypt them
        scrypt(passphrase.as_bytes(), &salt, &params, &mut key)
            .map_err(|_| BananaError::ScryptFailed)?;

        // set up cipher with key and decrypt secret using nonce
        let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&key[..]));
        match cipher.decrypt(
            GenericArray::from_slice(&self.nonce[..]),
            self.data.as_ref(),
        ) {
            Ok(a) => match String::from_utf8(a) {
                // in case of successful vector-to-string conversion, vector does not get copied:
                // https://doc.rust-lang.org/std/string/struct.String.html#method.from_utf8
                // string ptr same as the one of former vector,
                // string goes into output, no zeroize
                Ok(b) => Ok(b),

                // in case of conversion BananaError, the vector goes into BananaError;
                // should be zeroized
                Err(e) => {
                    let mut cleanup = e.into_bytes();
                    cleanup.zeroize();
                    Err(BananaError::DecodedSecretNotString)
                }
            },
            Err(_) => Err(BananaError::DecodingFailed),
        }
    }

    /// Share set title.
    pub fn title(&self) -> String {
        self.title.to_owned()
    }
}

/// Primitive polynomials in Galois field `GF(2^n)`, for `3 <= n <= 20`.
///
/// Value n is bits value for shares, and is limited by `BIT_RANGE` constants.
/// Primitive polynomial values are taken from
/// <https://github.com/grempe/secrets.js/blob/master/secrets.js#L55>.
///
/// See <https://mathworld.wolfram.com/PrimitivePolynomial.html> for
/// definitions.
#[rustfmt::skip]
const PRIMITIVE_POLYNOMIALS: [u32; 18] = [
    3, // n = 3, or `BIT_RANGE.start`
    3,
    5,
    3,
    3,
    29,
    17,
    9,
    5,
    83,
    27,
    43,
    3,
    45,
    9,
    39,
    39,
    9, // n = 20, or `BIT_RANGE.end`
];

/// Primitive polynomial for given `bits` in `GF(2^bits)`.
///
/// `bits` must be checked elsewhere to be within the acceptable `BIT_RANGE`.
/// Will panic otherwise.
fn primitive_polynomial(bits: u32) -> u32 {
    PRIMITIVE_POLYNOMIALS[bits as usize - 3]
}

/// Generate a table of logarithms and exponents in `GF(2^bits)` for given
/// `bits`.
///
/// `bits` must be checked elsewhere to be within the acceptable `BIT_RANGE`.
/// Will panic otherwise.
///
/// There are total `bits` exponents and `bits` logarithms generated, with
/// values within the field.
///
/// All elements of field do not exceed `2^bits-1` in value and could be
/// recorded with `bits` number of bits (this is quite self-evident, but will be
/// needed later on).
pub(crate) fn generate_logs_and_exps(bits: u32) -> (Vec<Option<u32>>, Vec<u32>) {
    let size = 2u32.pow(bits); // the number of elements in `GF(2^bits)`

    let mut logs: Vec<Option<u32>> = Vec::with_capacity(size as usize);
    for _i in 0..size {
        logs.push(None)
    } // 0th element could not be reached during the cycling and is undefined

    let mut exps: Vec<u32> = Vec::with_capacity(size as usize);

    let mut x = 1;
    let primitive_polynomial = primitive_polynomial(bits);
    for i in 0..size {
        exps.push(x);
        if logs[x as usize].is_none() {
            logs[x as usize] = Some(i)
        } // x = 1 is encountered twice
        x <<= 1; // left shift
        if x >= size {
            x ^= primitive_polynomial; // Bitwise XOR
            x &= size - 1; // Bitwise AND
        }
    }
    (logs, exps)
}

/// Calculate Lagrange interpolation polynomial in `GF(2^bits)`.
///
/// `x` is vector of share identification numbers, and `y` is vector of certain
/// number components from each share data.
///
/// `x` and `y` length are always identical, and do not exceed the maximum
/// number of shares, `2^bits-1`.
///
/// Logs and exps are the vectors of pre-calculated logarithms and exponents,
/// with length `2^bits`;
pub(crate) fn lagrange(
    x: &[u32],
    y: &[u32],
    logs: &[Option<u32>],
    exps: &[u32],
    bits: u32,
) -> Result<u32, BananaError> {
    let mut sum = 0;
    let size = 2u32.pow(bits);
    let len = x.len();

    for i in 0..len {
        match logs.get(y[i] as usize) {
            Some(Some(a)) => {
                let mut product = *a;
                for j in 0..len {
                    if i != j {
                        let p1 = match logs.get(x[j] as usize) {
                            Some(a) => a.expect(
                                "x[j] is never zero, it is share number, numbering starts from 1",
                            ),
                            None => return Err(BananaError::LogOutOfRange(x[j])),
                        };
                        let p2 = match logs.get((x[i]^x[j]) as usize) {
                            Some(a) => a.expect("x[i] and x[j] are never equal for non-equal i and j, through Galois field properties"),
                            None => return Err(BananaError::LogOutOfRange(x[i]^x[j])),
                        };
                        product = ((size - 1) + product + p1 - p2) % (size - 1);
                    }
                }

                // product is always positive and below `2^bits`, exponent is always addressed correctly
                sum ^= exps[product as usize];
            }

            // encountered the only undefined element (through Galois field properties), i.e. tried to calculate `log[0]`
            Some(None) => (),

            // this should not happen, but values of `y` elements are `u8` by decoding, and could in principle exceed `2^bits` number of elements in logs vector
            None => return Err(BananaError::LogOutOfRange(y[i])),
        }
    }
    Ok(sum)
}
