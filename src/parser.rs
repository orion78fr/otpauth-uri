use std::str;

use types::{OTPAlgorithm, OTPDigits, OTPLabel, OTPType, OTPUri};

use data_encoding::BASE32_NOPAD;
use nom::types::CompleteStr;
use nom::{digit, IResult};
use percent_encoding::percent_decode;

// NOTE See https://github.com/google/google-authenticator/wiki/Key-Uri-Format

pub fn parse_otpauth_uri(uri: &str) -> Result<OTPUri, String> {
    match otpauth_uri(CompleteStr(uri)) {
        Ok((_, c)) => {
            if c.secret.len() == 0 {
                return Err(String::from("c.secret.len() == 0"));
            }
            if let Some(period) = c.period {
                if period == 0 {
                    return Err(String::from("period == 0"));
                }
            }
            if let OTPType::HOTP = c.otptype {
                if let None = c.counter {
                    return Err(String::from("None = c.counter"));
                }
            }
            Ok(c)
        }
        Err(e) => Err(format!("{:?}", e)),
    }
}

pub fn parse_otpauth_label(label: &str) -> Result<OTPLabel, ()> {
    match otpauth_label(CompleteStr(label)) {
        Ok((_, c)) => Ok(c),
        Err(_) => Err(()),
    }
}

// TODO replace once https://github.com/Geal/nom/issues/776 is resolved
#[inline]
fn rest_complete_s<'a>(input: CompleteStr<'a>) -> IResult<CompleteStr<'a>, CompleteStr<'a>> {
    Ok((CompleteStr(&(input.0)[input.0.len()..]), input))
}

fn to_u32(input: CompleteStr) -> Result<u32, ()> {
    match str::FromStr::from_str(input.0) {
        Ok(i) => Ok(i),
        Err(_) => Err(()),
    }
}

fn to_u64(input: CompleteStr) -> Result<u64, ()> {
    match str::FromStr::from_str(input.0) {
        Ok(i) => Ok(i),
        Err(_) => Err(()),
    }
}

fn from_base32(input: CompleteStr) -> Result<Vec<u8>, ()> {
    match BASE32_NOPAD.decode(input.0.as_bytes()) {
        Ok(i) => Ok(i),
        Err(_) => Err(()),
    }
}

fn from_percent_encoding(input: CompleteStr) -> Result<String, ()> {
    match percent_decode(input.0.as_bytes()).decode_utf8() {
        Ok(i) => Ok(i.to_string()),
        Err(_) => Err(()),
    }
}

named!(otptype<CompleteStr, OTPType>,
       alt!(map!(tag!("hotp"), |_| OTPType::HOTP) | map!(tag!("totp"), |_| OTPType::TOTP)));

named!(otpalgorithm<CompleteStr, OTPAlgorithm>,
       alt!(map!(tag!("SHA1"), |_| OTPAlgorithm::SHA1) | 
            map!(tag!("SHA256"), |_| OTPAlgorithm::SHA256) |
            map!(tag!("SHA512"), |_| OTPAlgorithm::SHA512)));

named!(otpdigits<CompleteStr, OTPDigits>,
       alt!(map!(tag!("6"), |_| OTPDigits::Six) | map!(tag!("8"), |_| OTPDigits::Eight)));

#[derive(Debug)]
enum OTPURIOption {
    Secret(Vec<u8>),
    Issuer(String),
    Algorithm(OTPAlgorithm),
    Digits(OTPDigits),
    Counter(u64),
    Period(u32),
}

named!(otpuri_option<CompleteStr, OTPURIOption>,
    do_parse!(
       option: alt!(
            map!(do_parse!(
                     tag!("secret=") >>
                     secret: map_res!(alt_complete!(take_until!("&") | rest_complete_s), from_base32) >>
                     (secret)
                 ), |b| OTPURIOption::Secret(b)) |
            map!(do_parse!(
                     tag!("issuer=") >>
                     issuer: map_res!(alt_complete!(take_until!("&") | rest_complete_s), from_percent_encoding) >>
                     (issuer)
                 ), |s| OTPURIOption::Issuer(s)) |
            map!(do_parse!(
                     tag!("algorithm=") >>
                     otpalgorithm: otpalgorithm >>
                     (otpalgorithm)
                 ), |s| OTPURIOption::Algorithm(s)) |
            map!(do_parse!(
                     tag!("digits=") >>
                     digits: otpdigits >>
                     (digits)
                 ), |d| OTPURIOption::Digits(d)) |
            map!(do_parse!(
                     tag!("counter=") >>
                     counter: map_res!(digit, to_u64) >>
                     (counter)
                 ), |d| OTPURIOption::Counter(d)) |
            map!(do_parse!(
                     tag!("period=") >>
                     period: map_res!(digit, to_u32) >>
                     (period)
                 ), |d| OTPURIOption::Period(d))
            ) >>
        alt!(tag!("&") | eof!()) >>
        (option)
    )
);

named!(otpauth_label<CompleteStr, OTPLabel>,
    do_parse!(
        issuer: opt!(map_res!(alt!(take_until_and_consume!(":") | take_until_and_consume!("%3A")), from_percent_encoding)) >>
        many0!(tag!("%20")) >>
        accountname: map_res!(alt_complete!(take_until_and_consume!("?") | rest_complete_s), from_percent_encoding) >>
        (OTPLabel { issuer, accountname})
    )
);

named!(otpauth_uri<CompleteStr, OTPUri>,
    do_parse!(
        tag!("otpauth://") >>
        otptype: otptype >>
        tag!("/") >>
        label: otpauth_label >>
        result: fold_many0!( otpuri_option, OTPUri::new(), |mut result: OTPUri, option| {
            match option {
                OTPURIOption::Secret(b) => result.secret = b,
                OTPURIOption::Issuer(s) => result.label.issuer = Some(s),
                OTPURIOption::Algorithm(a) => result.algorithm = Some(a),
                OTPURIOption::Digits(d) => result.digits = Some(d),
                OTPURIOption::Counter(d) => result.counter = Some(d),
                OTPURIOption::Period(d) => result.period = Some(d),
            }
            result
        }) >>
        eof!() >>
        (OTPUri {
            label: OTPLabel{ issuer: result.label.issuer.or(label.issuer), accountname: label.accountname},
            otptype,
            algorithm: result.algorithm,
            counter: result.counter,
            digits: result.digits,
            period: result.period,
            secret: result.secret,
        })
    )
);

#[cfg(test)]
mod tests {
    use nom::types::CompleteStr;
    use parser::{from_base32, from_percent_encoding, parse_otpauth_label, parse_otpauth_uri};
    use types::{OTPAlgorithm, OTPDigits, OTPType};

    #[test]
    fn parse_otpauth_label_works() {
        let label = "Example:alice@google.com";

        let label = parse_otpauth_label(label).unwrap();
        assert_eq!(label.accountname, "alice@google.com");
        assert_eq!(label.issuer, Some("Example".to_string()));
    }

    #[test]
    fn examples_works() {
        let mut url =
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
                .to_string();

        for _i in 0..2 {
            let mut key = parse_otpauth_uri(&url).unwrap();
            assert_eq!(key.otptype, OTPType::TOTP);
            assert_eq!(key.label.accountname, "alice@google.com");
            assert_eq!(key.label.issuer, Some("Example".to_string()));
            assert_eq!(
                key.secret,
                [
                    'H' as u8, 'e' as u8, 'l' as u8, 'l' as u8, 'o' as u8, '!' as u8, 0xDE, 0xAD,
                    0xBE, 0xEF
                ]
            );
            url = key.to_string();
        }

        url = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30".to_string();

        for _i in 0..2 {
            let mut key = parse_otpauth_uri(&url).unwrap();
            assert_eq!(key.otptype, OTPType::TOTP);
            assert_eq!(key.label.accountname, "john.doe@email.com");
            assert_eq!(key.label.issuer, Some("ACME Co".to_string()));
            assert_eq!(key.algorithm, Some(OTPAlgorithm::SHA1));
            assert_eq!(key.period, Some(30));
            assert_eq!(key.digits, Some(OTPDigits::Six));
            url = key.to_string();
        }
    }

    // test vectors from
    // https://github.com/google/google-authenticator/blob/master/mobile/ios/Classes/OTPAuthURLTest.m

    const VALID_SECRET: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const VALID_ACCOUNTNAME: &str = "Léon";

    #[test]
    fn from_base32_works() {
        let base32_secret = "AAAQEAYEAUDAOCAJBIFQYDIOB4";
        let decoded_secret = from_base32(CompleteStr(base32_secret)).unwrap();
        assert_eq!(decoded_secret, VALID_SECRET);
    }

    #[test]
    fn from_percent_encoding_works() {
        let encoded_string = "L%C3%A9on";
        let decoded_string = from_percent_encoding(CompleteStr(encoded_string)).unwrap();
        assert_eq!(decoded_string, VALID_ACCOUNTNAME);
    }

    #[test]
    fn totp_url_works() {
        let mut url = "otpauth://totp/L%C3%A9on?algorithm=SHA256&digits=8&period=45&secret=AAAQEAYEAUDAOCAJBIFQYDIOB4".to_string();
        for _i in 0..2 {
            let key = parse_otpauth_uri(&url).unwrap();
            assert_eq!(key.otptype, OTPType::TOTP);
            assert_eq!(key.label.accountname, VALID_ACCOUNTNAME);
            assert_eq!(key.secret, VALID_SECRET);
            assert_eq!(key.algorithm, Some(OTPAlgorithm::SHA256));
            assert_eq!(key.period, Some(45));
            assert_eq!(key.digits, Some(OTPDigits::Eight));
            url = key.to_string();
        }
    }

    #[test]
    fn hotp_url_works() {
        let mut url = "otpauth://hotp/L%C3%A9on?algorithm=SHA256&digits=8&counter=18446744073709551615&secret=AAAQEAYEAUDAOCAJBIFQYDIOB4".to_string();
        for _i in 0..2 {
            let key = parse_otpauth_uri(&url).unwrap();
            assert_eq!(key.otptype, OTPType::HOTP);
            assert_eq!(key.label.accountname, VALID_ACCOUNTNAME);
            assert_eq!(key.secret, VALID_SECRET);
            assert_eq!(key.algorithm, Some(OTPAlgorithm::SHA256));
            assert_eq!(key.counter, Some(18446744073709551615));
            assert_eq!(key.digits, Some(OTPDigits::Eight));
            url = key.to_string();
        }
    }

    #[test]
    fn bad_url_fails() {
        let bad_urls = [
            // invalid scheme
            "http://foo",
            // invalid type
            "otpauth://foo",
            // missing secret
            "otpauth://totp/bar",
            // invalid period
            "otpauth://totp/bar?secret=AAAQEAYEAUDAOCAJBIFQYDIOB4&period=0",
            // missing counter
            "otpauth://hotp/bar?secret=AAAQEAYEAUDAOCAJBIFQYDIOB4",
            // invalid algorithm
            "otpauth://totp/bar?secret=AAAQEAYEAUDAOCAJBIFQYDIOB4&algorithm=RC4",
            // invalid digits
            "otpauth://totp/bar?secret=AAAQEAYEAUDAOCAJBIFQYDIOB4&digits=2",
        ];
        for i in 0..bad_urls.len() {
            if let Ok(_) = parse_otpauth_uri(bad_urls[i]) {
                panic!("url {} should not parse", bad_urls[i]);
            }
        }
    }
}
