use std::convert::TryInto;
use std::fmt;

use data_encoding::BASE32_NOPAD;
use hmac::digest::generic_array::ArrayLength;
use hmac::digest::{BlockInput, FixedOutput, Input};
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, DEFAULT_ENCODE_SET};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum OTPType {
    HOTP,
    TOTP,
}

impl fmt::Display for OTPType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OTPType::HOTP => write!(f, "hotp"),
            OTPType::TOTP => write!(f, "totp"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum OTPAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl fmt::Display for OTPAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OTPAlgorithm::SHA1 => write!(f, "SHA1"),
            OTPAlgorithm::SHA256 => write!(f, "SHA256"),
            OTPAlgorithm::SHA512 => write!(f, "SHA512"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum OTPDigits {
    Six = 6,
    Eight = 8,
}

impl fmt::Display for OTPDigits {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OTPDigits::Six => write!(f, "6"),
            OTPDigits::Eight => write!(f, "8"),
        }
    }
}

#[derive(Debug)]
pub struct OTPUri {
    pub accountname: String,
    pub algorithm: Option<OTPAlgorithm>,
    pub counter: Option<u64>,
    pub digits: Option<OTPDigits>,
    pub issuer: Option<String>,
    pub otptype: OTPType,
    pub period: Option<u32>,
    pub secret: Vec<u8>,
}

impl OTPUri {
    pub fn new() -> Self {
        OTPUri {
            accountname: "".to_owned(),
            algorithm: None,
            counter: None,
            digits: None,
            issuer: None,
            otptype: OTPType::TOTP,
            period: None,
            secret: Vec::new(),
        }
    }
}

impl fmt::Display for OTPUri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "otpauth://{}/", self.otptype)?;
        if let Some(ref issuer) = self.issuer {
            write!(f, "{}:", utf8_percent_encode(issuer, DEFAULT_ENCODE_SET))?;
        }
        write!(
            f,
            "{}?",
            utf8_percent_encode(&self.accountname, DEFAULT_ENCODE_SET)
        )?;
        if let Some(algorithm) = self.algorithm {
            write!(f, "algorithm={}&", algorithm)?;
        }
        if let Some(counter) = self.counter {
            write!(f, "counter={}&", counter)?;
        }
        if let Some(digits) = self.digits {
            write!(f, "digits={}&", digits)?;
        }
        if let Some(ref issuer) = self.issuer {
            write!(
                f,
                "issuer={}&",
                utf8_percent_encode(issuer, DEFAULT_ENCODE_SET)
            )?;
        }
        if let Some(period) = self.period {
            write!(f, "period={}&", period)?;
        }
        write!(f, "secret={}", BASE32_NOPAD.encode(&self.secret))
    }
}

#[derive(Debug)]
pub struct TOTPGenerator {
    pub algorithm: OTPAlgorithm,
    pub digits: OTPDigits,
    pub period: u32,
    pub secret: Vec<u8>,
}

impl TOTPGenerator {
    pub fn generate(&self, timestamp: u64) -> String {
        let mut hotp_gen = HOTPGenerator {
            algorithm: self.algorithm,
            counter: timestamp / self.period as u64,
            digits: self.digits,
            secret: self.secret.clone(),
        };
        hotp_gen.generate()
    }
}

#[derive(Debug)]
pub struct HOTPGenerator {
    pub algorithm: OTPAlgorithm,
    pub counter: u64,
    pub digits: OTPDigits,
    pub secret: Vec<u8>,
}

impl HOTPGenerator {
    fn calculate<D>(&mut self) -> String
    where
        D: Input + BlockInput + FixedOutput + Default + Clone,
        D::BlockSize: ArrayLength<u8>,
    {
        let mut mac = Hmac::<D>::new_varkey(&self.secret).unwrap();
        mac.input(&self.counter.to_be_bytes());

        self.counter += 1;

        let result = mac.result();
        let digest = result.code();

        let offset: usize = (digest[digest.len() - 1] & 0xf) as usize;

        let b: &[u8; 4] = (&digest[offset..offset + 4]).try_into().unwrap();
        let base = u32::from_be_bytes(*b) & 0x7fff_ffff;

        format!(
            "{:01$}",
            base % (10 as u32).pow(self.digits as u32),
            self.digits as usize
        )
    }

    pub fn generate(&mut self) -> String {
        return match self.algorithm {
            OTPAlgorithm::SHA1 => self.calculate::<Sha1>(),
            OTPAlgorithm::SHA256 => self.calculate::<Sha256>(),
            OTPAlgorithm::SHA512 => self.calculate::<Sha512>(),
        };
    }
}

#[derive(Debug)]
pub enum OTPGenerator {
    TOTPGenerator(TOTPGenerator),
    HOTPGenerator(HOTPGenerator),
}

impl From<OTPUri> for OTPGenerator {
    fn from(uri: OTPUri) -> Self {
        return match uri.otptype {
            OTPType::TOTP => OTPGenerator::TOTPGenerator(TOTPGenerator {
                algorithm: uri.algorithm.unwrap_or(OTPAlgorithm::SHA1),
                digits: uri.digits.unwrap_or(OTPDigits::Six),
                period: uri.period.unwrap_or(30),
                secret: uri.secret.clone(),
            }),
            OTPType::HOTP => OTPGenerator::HOTPGenerator(HOTPGenerator {
                algorithm: uri.algorithm.unwrap_or(OTPAlgorithm::SHA1),
                counter: uri.counter.unwrap(),
                digits: uri.digits.unwrap_or(OTPDigits::Six),
                secret: uri.secret.clone(),
            }),
        };
    }
}

#[cfg(test)]
mod tests {
    use types::{HOTPGenerator, OTPAlgorithm, OTPDigits, TOTPGenerator};

    #[test]
    fn hotp_works() {
        // From https://tools.ietf.org/html/rfc4226#page-32
        let vectors = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        let mut key = HOTPGenerator {
            algorithm: OTPAlgorithm::SHA1,
            counter: 0,
            digits: OTPDigits::Six,
            secret: "12345678901234567890".as_bytes().to_vec(),
        };
        for i in 0..vectors.len() {
            assert_eq!(key.generate(), vectors[i as usize]);
        }
    }

    #[test]
    fn totp_works() {
        // From https://tools.ietf.org/html/rfc6238#appendix-B
        let vectors = [
            (59, "94287082", OTPAlgorithm::SHA1),
            (59, "46119246", OTPAlgorithm::SHA256),
            (59, "90693936", OTPAlgorithm::SHA512),
            (1111111109, "07081804", OTPAlgorithm::SHA1),
            (1111111109, "68084774", OTPAlgorithm::SHA256),
            (1111111109, "25091201", OTPAlgorithm::SHA512),
            (1111111111, "14050471", OTPAlgorithm::SHA1),
            (1111111111, "67062674", OTPAlgorithm::SHA256),
            (1111111111, "99943326", OTPAlgorithm::SHA512),
            (1234567890, "89005924", OTPAlgorithm::SHA1),
            (1234567890, "91819424", OTPAlgorithm::SHA256),
            (1234567890, "93441116", OTPAlgorithm::SHA512),
            (2000000000, "69279037", OTPAlgorithm::SHA1),
            (2000000000, "90698825", OTPAlgorithm::SHA256),
            (2000000000, "38618901", OTPAlgorithm::SHA512),
            (20000000000, "65353130", OTPAlgorithm::SHA1),
            (20000000000, "77737706", OTPAlgorithm::SHA256),
            (20000000000, "47863826", OTPAlgorithm::SHA512),
        ];
        for i in 0..vectors.len() {
            let (timestamp, code, algorithm) = vectors[i];
            let key = TOTPGenerator {
                algorithm: algorithm,
                digits: OTPDigits::Eight,
                period: 30,
                secret: match algorithm {
                    OTPAlgorithm::SHA1 => "12345678901234567890".as_bytes().to_vec(),
                    OTPAlgorithm::SHA256 => "12345678901234567890123456789012".as_bytes().to_vec(),
                    OTPAlgorithm::SHA512 => {
                        "1234567890123456789012345678901234567890123456789012345678901234"
                            .as_bytes()
                            .to_vec()
                    }
                },
            };
            assert_eq!(key.generate(timestamp), code);
        }
    }
}
