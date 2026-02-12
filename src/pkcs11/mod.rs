///! Vendored from https://github.com/mdelete/rustls-pkcs11
/// Adapted to our need.
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{
        Mechanism, MechanismType,
        eddsa::{EddsaParams, EddsaSignatureScheme},
        rsa::{PkcsMgfType, PkcsPssParams},
    },
    object::{Attribute, AttributeType, CertificateType, KeyType, ObjectClass},
    session::{Session, UserType},
    types::AuthPin,
};
use tracing::{debug, error, info};
use tokio_rustls::rustls::{
    self, OtherError, SignatureAlgorithm, SignatureScheme,
    client::ResolvesClientCert,
    pki_types::CertificateDer,
    sign::{CertifiedKey, Signer, SigningKey},
};
use x509_certificate::X509Certificate;
use std::{
    ffi::OsStr,
    fmt,
    sync::{Arc, Mutex},
};

#[derive(Debug)]
enum PKCS11Error {
    CertificateNotFoundError,
    KeyHandleNotFoundError,
    UnsupportedSignatureSchemeError(SignatureScheme),
    SignError(cryptoki::error::Error),
}

impl std::error::Error for PKCS11Error {}

impl fmt::Display for PKCS11Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PKCS11Error::SignError(err) => write!(f, "{}: {}", self, err),
            PKCS11Error::UnsupportedSignatureSchemeError(scheme) => {
                write!(f, "{}: {:?}", self, scheme)
            }
            _ => write!(f, "{}", self),
        }
    }
}

#[derive(Debug)]
struct PKCS11Signer {
    session: Arc<Mutex<Session>>,
    scheme: SignatureScheme,
}

/// Maps rustls schemes to cryptoki mechanisms
///
/// TLS 1.3 supports:
///   ECDSA_NISTP521_SHA512, ECDSA_NISTP384_SHA384, ECDSA_NISTP256_SHA256
///   RSA_PSS_SHA512, RSA_PSS_SHA384, RSA_PSS_SHA256
///   ED25519
/// TLS 1.2 additionally supports:
///   RSA_PKCS1_SHA384, RSA_PKCS1_SHA256
/// YubiKey (5.1) supports:
///   ECDSA_NISTP384_SHA384, ECDSA_NISTP256_SHA256
///   RSA_PKCS1_SHA384, RSA_PKCS1_SHA256
/// Most HSM do not implement RSA_PSS_*, *_SHA512, and ED25519
///
/// # Errors
///
/// - yields UnsupportedSignatureSchemeError for schemes that are not TLSv1.2 or TLSv1.3
///
impl<'a> TryInto<Mechanism<'a>> for &PKCS11Signer {
    type Error = rustls::Error;

    fn try_into(self) -> Result<Mechanism<'a>, rustls::Error> {
        match self.scheme {
            // 1.2.840.10045.4.3.2
            SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(Mechanism::EcdsaSha256),
            // 1.2.840.10045.4.3.3
            SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(Mechanism::EcdsaSha384),
            // 1.2.840.10045.4.3.4
            SignatureScheme::ECDSA_NISTP521_SHA512 => Ok(Mechanism::EcdsaSha512),
            // 1.2.840.113549.1.1.11
            SignatureScheme::RSA_PKCS1_SHA256 => Ok(Mechanism::Sha256RsaPkcs),
            // 1.2.840.113549.1.1.12
            SignatureScheme::RSA_PKCS1_SHA384 => Ok(Mechanism::Sha384RsaPkcs),
            // 1.2.840.113549.1.1.13
            SignatureScheme::RSA_PKCS1_SHA512 => Ok(Mechanism::Sha512RsaPkcs),
            // 1.2.840.113549.1.1.10 ...
            SignatureScheme::RSA_PSS_SHA256 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA256_RSA_PKCS, // 2.16.840.1.101.3.4.2.1
                    mgf: PkcsMgfType::MGF1_SHA256, // 1.2.840.113549.1.1.8 + 2.16.840.1.101.3.4.2.1
                    s_len: 32.into(),
                };
                Ok(Mechanism::Sha256RsaPkcsPss(params))
            }
            // 1.2.840.113549.1.1.10 ...
            SignatureScheme::RSA_PSS_SHA384 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA384_RSA_PKCS, // 2.16.840.1.101.3.4.2.2
                    mgf: PkcsMgfType::MGF1_SHA384, // 1.2.840.113549.1.1.8 + 2.16.840.1.101.3.4.2.2
                    s_len: 48.into(),
                };
                Ok(Mechanism::Sha384RsaPkcsPss(params))
            }
            // 1.2.840.113549.1.1.10 ...
            SignatureScheme::RSA_PSS_SHA512 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA512_RSA_PKCS, // 2.16.840.1.101.3.4.2.3
                    mgf: PkcsMgfType::MGF1_SHA512, // 1.2.840.113549.1.1.8 + 2.16.840.1.101.3.4.2.3
                    s_len: 64.into(),
                };
                Ok(Mechanism::Sha384RsaPkcsPss(params))
            }
            // TODO: which HSM really supports this?
            SignatureScheme::ED25519 => Ok(Mechanism::Eddsa(EddsaParams::new(
                EddsaSignatureScheme::Ed25519,
            ))),
            unsupported_scheme => Err(rustls::Error::Other(OtherError(Arc::new(
                PKCS11Error::UnsupportedSignatureSchemeError(unsupported_scheme),
            )))),
        }
    }
}

/// Maps rustls schemes to cryptoki keytypes
impl Into<KeyType> for &PKCS11Signer {
    fn into(self) -> KeyType {
        match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => KeyType::EC,
            SignatureScheme::ECDSA_NISTP384_SHA384 => KeyType::EC,
            _ => KeyType::RSA,
        }
    }
}

impl Signer for PKCS11Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let session = self.session.lock().unwrap();

        let key_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::KeyType(self.into()),
        ];

        let key = session
            .find_objects(&key_template)
            .unwrap() // how and when might this fail?
            .into_iter()
            .next()
            .ok_or(rustls::Error::Other(OtherError(Arc::new(
                PKCS11Error::KeyHandleNotFoundError,
            ))))?;

        let mechanism = self.try_into()?;

        let mut signed_message = session.sign(&mechanism, key, message).map_err(|err| {
            rustls::Error::Other(OtherError(Arc::new(PKCS11Error::SignError(err))))
        })?;

        // The signed message comes out of the YubiKey in raw r,s-form for EC signatures, needs to be an ASN.1 sequence.
        // RSA signatures pass unchanged.
        // TODO: how do other HSMs output EC signatures?
        let signed_message = match self.into() {
            KeyType::EC => signed_message.to_asn1_sig().unwrap(),
            _ => signed_message,
        };

        debug!("{:?}({:02x?})", mechanism, signed_message);
        Ok(signed_message)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Debug)]
struct PKCS11SigningKey {
    session: Arc<Mutex<Session>>,
    scheme: SignatureScheme,
}

impl Into<SignatureAlgorithm> for &PKCS11SigningKey {
    fn into(self) -> SignatureAlgorithm {
        match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => SignatureAlgorithm::ECDSA,
            SignatureScheme::ECDSA_NISTP384_SHA384 => SignatureAlgorithm::ECDSA,
            SignatureScheme::RSA_PKCS1_SHA256 => SignatureAlgorithm::RSA,
            SignatureScheme::RSA_PKCS1_SHA384 => SignatureAlgorithm::RSA,
            SignatureScheme::RSA_PSS_SHA256 => SignatureAlgorithm::RSA,
            SignatureScheme::RSA_PSS_SHA384 => SignatureAlgorithm::RSA,
            _ => SignatureAlgorithm::Unknown(0),
        }
    }
}

impl SigningKey for PKCS11SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        debug!(
            "schemes offered: {:?}, scheme supported: {:?}",
            offered, self.scheme
        );
        if offered.contains(&self.scheme) {
            return Some(Box::new(PKCS11Signer {
                session: self.session.clone(),
                scheme: self.scheme,
            }));
        }
        None
    }

    // mandatory trait fn, but seems to be unused
    fn algorithm(&self) -> SignatureAlgorithm {
        debug!("algorithm called!");
        self.into()
    }
}

#[derive(Debug)]
pub struct PKCS11ClientCertResolver {
    chain: Vec<CertificateDer<'static>>,
    signing_key: Arc<PKCS11SigningKey>,
}

impl ResolvesClientCert for PKCS11ClientCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::new(CertifiedKey {
            cert: self.chain.clone(),
            key: self.signing_key.clone(),
            ocsp: None,
        }))
    }

    fn has_certs(&self) -> bool {
        self.chain.len() > 0
    }
}

impl PKCS11ClientCertResolver {
    /// Create a new PKCS11ClientCertResolver.
    ///
    /// # Arguments
    ///
    /// * `pin` - An optional `&str` of the pin that unlocks the device. Set to `None` if device does not need a pin to unlock.
    /// * `path` - Absolute filepath to the PKCS11 library of your device.
    ///
    /// # Examples
    ///
    /// ```
    /// let pin = Some("123456");
    /// let tls = rustls::ClientConfig::builder()
    ///    .with_root_certificates(root_certs)
    ///    .with_client_cert_resolver(Arc::new(
    ///        PKCS11ClientCertResolver::new(pin, "/usr/lib/opensc-pkcs11.so")?
    ///    ));
    /// ```
    ///
    /// # Errors
    ///
    /// Authenticator devices are complicated things. A lot can go wrong along the way.
    /// To alleviate this, most checks happen at instantiation time here, therefore errors
    /// yielded here can have a plethora of reasons:
    ///
    /// - the PKCS11 library could not be loaded under the file path.
    /// - the pin is missing or incorrect.
    /// - the authenticator device is not present or inaccessible.
    /// - the PKCS11 library has problems communicating with the authenticator device.
    /// - the authenticator device cannot read an appropriate certificate from the relevant slot.
    /// - the authenticator device's certificate signature scheme is not supported.
    ///
    pub fn new(pin: Option<&str>, path: &OsStr) -> Result<Self, Box<dyn std::error::Error>> {
        let pkcs11client = Pkcs11::new(path)?;
        pkcs11client.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

        let slot = pkcs11client.get_slots_with_token()?.remove(0); // This only ever shows slot 9a of a YubiKey
        let session = pkcs11client.open_ro_session(slot)?;
        match pin {
            Some(pin) => session.login(UserType::User, Some(&AuthPin::new(pin.into())))?,
            None => session.login(UserType::User, None)?,
        }

        let search_template = vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
        ];
        let handle = session.find_objects(&search_template)?.remove(0);
        let value = session
            .get_attributes(handle, &[AttributeType::Value])?
            .remove(0);

        let (scheme, chain) = parse_certificate(value)?;

        let session = Arc::new(Mutex::new(session));
        let signing_key = Arc::new(PKCS11SigningKey { session, scheme });

        Ok(Self { chain, signing_key })
    }
}

/// helper trait to deal with asn.1
trait ToASN1 {
    fn to_asn1_sig(&mut self) -> Result<Vec<u8>, asn1::WriteError>;
}

/// transforms a raw r,s-form signature to an asn1 sequence
impl ToASN1 for Vec<u8> {
    fn to_asn1_sig(&mut self) -> Result<Vec<u8>, asn1::WriteError> {
        let mut mid = self.len() / 2;

        // if r or s are negative (have the msb set) we need to prepend a null byte before converting to bigint
        if self[0] >> 7 == 1 {
            self.insert(0, 0u8);
            mid += 1; // shift the middle
        }
        if self[mid] >> 7 == 1 {
            self.insert(mid, 0u8);
        }

        asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w: &mut asn1::Writer| {
                let r = asn1::BigInt::new(&self[..mid]);
                w.write_element(&r)?;
                let s = asn1::BigInt::new(&self[mid..]);
                w.write_element(&s)?;
                Ok(())
            }))
        })
    }
}

/// certificate helper
fn parse_certificate(
    value: Attribute,
) -> Result<(SignatureScheme, Vec<CertificateDer<'static>>), Box<dyn std::error::Error>> {
    match value {
        Attribute::Value(cert) => {
            let x509 = X509Certificate::from_der(&cert).unwrap();
            info!(
                "CN: {}, Issuer: {}",
                x509.subject_common_name().unwrap(),
                x509.issuer_common_name().unwrap(),
            );
            debug!(
                "Signature algorithm: {:?}",
                x509.signature_algorithm().unwrap(),
            );
            debug!("Pubkey({:02x})", x509.public_key_data());

            let scheme = match x509.signature_algorithm().unwrap() {
                // TODO: most HSMs do not support RSA_PSS_* and *_SHA512
                // Yubikey 5.7 seemingly does not support ED25519 certificates
                x509_certificate::SignatureAlgorithm::RsaSha256 => {
                    SignatureScheme::RSA_PKCS1_SHA256 // TODO: support both RSA_PSS_SHA256 and RSA_PKCS1_SHA256
                }
                x509_certificate::SignatureAlgorithm::RsaSha384 => {
                    SignatureScheme::RSA_PKCS1_SHA384 // TODO: support both RSA_PSS_SHA384 and RSA_PKCS1_SHA384
                }
                x509_certificate::SignatureAlgorithm::EcdsaSha256 => {
                    SignatureScheme::ECDSA_NISTP256_SHA256
                }
                x509_certificate::SignatureAlgorithm::EcdsaSha384 => {
                    SignatureScheme::ECDSA_NISTP384_SHA384
                }
                unsupported_scheme => {
                    error!("Unsupported scheme: {}", unsupported_scheme);
                    return Err(Box::new(PKCS11Error::UnsupportedSignatureSchemeError(
                        SignatureScheme::Unknown(0),
                    )));
                }
            };

            let certificate_der = CertificateDer::from_slice(&cert).into_owned();
            Ok((scheme, vec![certificate_der]))
        }
        _ => Err(Box::new(PKCS11Error::CertificateNotFoundError)),
    }
}
