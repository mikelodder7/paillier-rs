use crypto_bigint::{Encoding, RandomMod};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use libpaillier::{paillier2048::*, var_bytes_to_uint};

/// Taken from https://github.com/mikelodder7/cunningham_chain/blob/master/findings.md
/// prefix'd with '9' for multibase to work
const TEST_PRIMES: [&str; 4] = [
    "9153739637779647327330155094463476939112913405723627932550795546376536722298275674187199768137486929460478138431076223176750734095693166283451594721829574797878338183845296809008576378039501400850628591798770214582527154641716248943964626446190042367043984306973709604255015629102866732543697075866901827761489",
    "966295144163396665403376179086308918015255210762161712943347745256800426733181435998953954369657699924569095498869393378860769817738689910466139513014839505675023358799693196331874626976637176000078613744447569887988972970496824235261568439949705345174465781244618912962800788579976795988724553365066910412859",
    "937313426856874901938110133384605074194791927500210707276948918975046371522830901596065044944558427864187196889881993164303255749681644627614963632713725183364319410825898054225147061624559894980555489070322738683900143562848200257354774040241218537613789091499134051387344396560066242901217378861764936185029",
    "989884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203768010560056939935696678829394884407208311246423715319737062188883946712432742638151109800623047059726541476042502884419075341171231440736956555270413618581675255342293149119973622969239858152417678164815053566739"
];

/// prefix with 9 any input
fn b10(s: &str) -> Base {
    let (_, bytes) = multibase::decode(s).unwrap();
    Base::from_be_slice(bytes.as_slice())
}

#[cfg_attr(feature = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn encrypt() {
    let res = DecryptionKey::with_primes_unchecked(&b10(TEST_PRIMES[0]), &b10(TEST_PRIMES[1]));
    assert!(res.is_ok());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m = b"this is a test message";
    let res = pk.encrypt(m);
    assert!(res.is_ok());

    let (c, _) = res.unwrap();
    let res = sk.decrypt(&c);
    assert!(res.is_ok());
    let m1 = res.unwrap();
    assert_eq!(m1, m);

    // bad messages
    let nn1 = pk.modulus_squared().as_ref().wrapping_add(&Quad::ONE);
    let nn = pk.modulus_squared().to_be_bytes();
    let nn1_bytes = nn1.to_be_bytes();
    let bad_messages: [&[u8]; 3] = [b"", &nn, &nn1_bytes];

    for b in &bad_messages {
        let res = pk.encrypt(&b);
        assert!(res.is_err());
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn add() {
    let res = DecryptionKey::with_primes_unchecked(&b10(TEST_PRIMES[0]), &b10(TEST_PRIMES[1]));
    assert!(res.is_ok());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let res1 = pk.encrypt(&[7u8]);
    let res2 = pk.encrypt(&[6u8]);
    assert!(res1.is_ok());
    assert!(res2.is_ok());

    let (c1, _) = res1.unwrap();
    let (c2, _) = res2.unwrap();
    let res = pk.add(&c1, &c2);
    assert!(res.is_ok());
    let c3 = res.unwrap();
    let res = sk.decrypt(&c3);
    assert!(res.is_ok());
    let bytes = res.unwrap();
    assert_eq!(bytes.len(), 1);
    assert_eq!(13, bytes[0]);
}

#[cfg_attr(feature = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn mul() {
    let res = DecryptionKey::with_primes_unchecked(&b10(TEST_PRIMES[0]), &b10(TEST_PRIMES[1]));
    assert!(res.is_ok());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m2 = Dual::from_u8(6);

    let res1 = pk.encrypt(&[7u8]);
    assert!(res1.is_ok());

    let (c1, _) = res1.unwrap();
    let res = pk.mul(&c1, &m2);
    assert!(res.is_ok());
    let c2 = res.unwrap();
    let res = sk.decrypt(&c2);
    assert!(res.is_ok());
    let bytes = res.unwrap();
    assert_eq!(bytes.len(), 1);
    assert_eq!(42, bytes[0]);
}

#[cfg_attr(feature = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn serialization() {
    let res = DecryptionKey::with_primes_unchecked(&b10(TEST_PRIMES[2]), &b10(TEST_PRIMES[3]));
    assert!(res.is_ok());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let res = serde_json::to_string(&pk);
    if res.is_err() {
        assert!(false, "{:?}", res.unwrap_err());
    }
    let pk_str = res.unwrap();
    let res = serde_json::from_str::<EncryptionKey>(&pk_str);
    assert!(res.is_ok());
    let pk1 = res.unwrap();
    assert_eq!(pk1.modulus(), pk.modulus());

    let res = serde_json::to_string(&sk);
    assert!(res.is_ok());
    let sk_str = res.unwrap();
    let res = serde_json::from_str::<DecryptionKey>(&sk_str);
    assert!(res.is_ok());
    let sk1 = res.unwrap();
    assert_eq!(sk.u(), sk1.u());
    assert_eq!(sk.totient(), sk1.totient());
    assert_eq!(sk.lambda(), sk1.lambda());
}

#[cfg_attr(feature = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn bytes() {
    let res = DecryptionKey::with_primes_unchecked(&b10(TEST_PRIMES[2]), &b10(TEST_PRIMES[3]));
    assert!(res.is_ok());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let bytes = pk.to_bytes();
    assert_eq!(bytes.len(), 256);
    let pk1 = EncryptionKey::from_bytes(bytes.as_slice()).unwrap();
    assert_eq!(pk1.modulus(), pk.modulus());

    let bytes = sk.to_bytes();
    assert_eq!(bytes.len(), 256);
    let res = DecryptionKey::from_bytes(bytes.as_slice());
    assert!(res.is_ok());
    let sk1 = res.unwrap();
    assert_eq!(sk.u(), sk1.u());
    assert_eq!(sk.totient(), sk1.totient());
    assert_eq!(sk.lambda(), sk1.lambda());
}

#[cfg_attr(feature = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn proof() {
    use k256::elliptic_curve::group::prime::PrimeCurveAffine;

    let res = DecryptionKey::with_primes_unchecked(&b10(TEST_PRIMES[2]), &b10(TEST_PRIMES[3]));
    assert!(res.is_ok());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let ssk = k256::SecretKey::random(&mut rand::rngs::OsRng);
    let spk = ssk.public_key();
    let mut nonce = Vec::new();
    nonce.extend_from_slice(
        k256::AffinePoint::generator()
            .to_encoded_point(true)
            .as_bytes(),
    );
    nonce.extend_from_slice(
        &hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F").unwrap(),
    );
    nonce.extend_from_slice(spk.as_affine().to_encoded_point(true).as_bytes());
    nonce.push(1u8);

    let proof = SquareFreeProof::generate::<sha2::Sha256>(&sk, nonce.as_slice());

    assert!(proof.verify::<sha2::Sha256>(&pk, nonce.as_slice()));

    let mut bytes = proof.to_bytes();
    let res = SquareFreeProof::from_bytes(bytes.as_slice());
    assert!(res.is_ok());
    let proof1 = res.unwrap();
    assert_eq!(proof1.to_bytes(), proof.to_bytes());

    bytes[0] = 128;
    let res = SquareFreeProof::from_bytes(bytes.as_slice());
    assert!(res.is_err());
}

#[cfg_attr(feature = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn all() {
    let res = DecryptionKey::random();
    assert!(res.is_ok());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m = b"this is a test message";
    let res = pk.encrypt(m);
    assert!(res.is_ok());

    let (c, _) = res.unwrap();
    let res = sk.decrypt(&c);
    assert!(res.is_ok());
    let m1 = res.unwrap();
    assert_eq!(m1, m);

    // bad messages
    let nn1 = pk.modulus_squared().as_ref().wrapping_add(&Quad::ONE);
    let nn = pk.modulus_squared().to_be_bytes();
    let nn1_bytes = nn1.to_be_bytes();
    let bad_messages: [&[u8]; 3] = [b"", &nn, &nn1_bytes];

    for b in &bad_messages {
        let res = pk.encrypt(&b);
        assert!(res.is_err());
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn range() {
    use k256::elliptic_curve::Field;
    use rand::SeedableRng;

    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);

    let res = DecryptionKey::with_primes_unchecked(&b10(TEST_PRIMES[0]), &b10(TEST_PRIMES[1]));
    assert!(res.is_ok());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);
    let signing_key = k256::Scalar::random(&mut rng);
    let x = var_bytes_to_uint(&signing_key.to_bytes()).unwrap();
    let r = Dual::random_mod(&mut rng, pk.modulus());
    let range = var_bytes_to_uint(
        &hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").unwrap(),
    )
    .unwrap();

    let cipher_x = pk.encrypt_with_nonce(&x, &r).unwrap();

    let range_proof = RangeProof::prove(
        &pk,
        &range,
        &cipher_x,
        &x,
        &r,
        RangeProofErrorFactor::Bits40,
        &mut rng,
    );
    assert!(range_proof.verify().is_ok());
    assert!(range_proof
        .verify_with_params(&pk, &cipher_x, &range)
        .is_ok());
}
