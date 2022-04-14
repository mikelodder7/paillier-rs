use k256::elliptic_curve::sec1::ToEncodedPoint;
use libpaillier::*;
use unknown_order::BigNumber;

/// Taken from https://github.com/mikelodder7/cunningham_chain/blob/master/findings.md
/// prefix'd with '9' for multibase to work
const TEST_PRIMES: [&str; 4] = [
    "9153739637779647327330155094463476939112913405723627932550795546376536722298275674187199768137486929460478138431076223176750734095693166283451594721829574797878338183845296809008576378039501400850628591798770214582527154641716248943964626446190042367043984306973709604255015629102866732543697075866901827761489",
    "966295144163396665403376179086308918015255210762161712943347745256800426733181435998953954369657699924569095498869393378860769817738689910466139513014839505675023358799693196331874626976637176000078613744447569887988972970496824235261568439949705345174465781244618912962800788579976795988724553365066910412859",
    "937313426856874901938110133384605074194791927500210707276948918975046371522830901596065044944558427864187196889881993164303255749681644627614963632713725183364319410825898054225147061624559894980555489070322738683900143562848200257354774040241218537613789091499134051387344396560066242901217378861764936185029",
    "989884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203768010560056939935696678829394884407208311246423715319737062188883946712432742638151109800623047059726541476042502884419075341171231440736956555270413618581675255342293149119973622969239858152417678164815053566739"
];

/// prefix with 9 any input
fn b10(s: &str) -> BigNumber {
    let (_, bytes) = multibase::decode(s).unwrap();
    BigNumber::from_slice(bytes.as_slice())
}

#[test]
fn encrypt() {
    let res = DecryptionKey::with_safe_primes_unchecked(&b10(TEST_PRIMES[0]), &b10(TEST_PRIMES[1]));
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m = b"this is a test message";
    let res = pk.encrypt(m, None);
    assert!(res.is_some());

    let (c, _) = res.unwrap();
    let res = sk.decrypt(&c);
    assert!(res.is_some());
    let m1 = res.unwrap();
    assert_eq!(m1, m);

    // bad messages
    let nn1: BigNumber = pk.nn() + 1;
    let nn = pk.nn().to_bytes();
    let nn1_bytes = nn1.to_bytes();
    let bad_messages: [&[u8]; 3] = [b"", nn.as_slice(), nn1_bytes.as_slice()];

    for b in &bad_messages {
        let res = pk.encrypt(&b, None);
        assert!(res.is_none());
    }
}

#[test]
fn add() {
    let res = DecryptionKey::with_safe_primes_unchecked(&b10(TEST_PRIMES[0]), &b10(TEST_PRIMES[1]));
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m1 = BigNumber::from(7);
    let m2 = BigNumber::from(6);

    let res1 = pk.encrypt(&m1.to_bytes(), None);
    let res2 = pk.encrypt(&m2.to_bytes(), None);
    assert!(res1.is_some());
    assert!(res2.is_some());

    let (c1, _) = res1.unwrap();
    let (c2, _) = res2.unwrap();
    let res = pk.add(&c1, &c2);
    assert!(res.is_some());
    let c3 = res.unwrap();
    let res = sk.decrypt(&c3);
    assert!(res.is_some());
    let bytes = res.unwrap();
    let m3 = BigNumber::from_slice(bytes);
    assert_eq!(m3, BigNumber::from(13));
}

#[test]
fn mul() {
    let res = DecryptionKey::with_safe_primes_unchecked(&b10(TEST_PRIMES[0]), &b10(TEST_PRIMES[1]));
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m1 = BigNumber::from(7);
    let m2 = BigNumber::from(6);

    let res1 = pk.encrypt(&m1.to_bytes(), None);
    assert!(res1.is_some());

    let (c1, _) = res1.unwrap();
    let res = pk.mul(&c1, &m2);
    assert!(res.is_some());
    let c2 = res.unwrap();
    let res = sk.decrypt(&c2);
    assert!(res.is_some());
    let bytes = res.unwrap();
    let m3 = BigNumber::from_slice(bytes.as_slice());
    assert_eq!(m3, BigNumber::from(42));
}

#[test]
fn serialization() {
    let res = DecryptionKey::with_safe_primes_unchecked(&b10(TEST_PRIMES[2]), &b10(TEST_PRIMES[3]));
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let res = serde_json::to_string(&pk);
    assert!(res.is_ok());
    let pk_str = unicase::Ascii::new(res.unwrap());
    assert_eq!(
        pk_str,
        unicase::Ascii::new(
            r#""1a916b30385e4d342bbcb6e3c56d70c37cb55c6ef50842006081e7e39df0670cf0de00707611839bb84355b43ddc871476fbf251651e391d2811eadb148b7f4aaf79bb770a5262290ba9d8be41b69b03ca5056b702eb02d29ec896eb1274661181b56e4b27979a8a47238c925f91653766fb286d833db1fdb93816d826d60a653bd0d2afa196c95265635108bd32ef63c52310b93bb682498d17d16e257f19503fe9d718418ad7a1834c64f125944818674aaf2c2c0bbb12d13d45bcc70d8db697879fba820fbedde986807ad0f15622d1d9ff7ede7e29b7547c3db9a2b3ca6d3e086a1d258b0b3f8b6e5008e3d8a85e744299240fd2064811aeb5e1db2b299f""#
        )
    );
    let res = serde_json::from_str::<EncryptionKey>(&pk_str);
    assert!(res.is_ok());
    let pk1 = res.unwrap();
    assert_eq!(pk1.n(), pk.n());

    let res = serde_json::to_string(&sk);
    assert!(res.is_ok());
    let sk_str = res.unwrap();

    let res = serde_json::from_str::<DecryptionKey>(&sk_str);
    assert!(res.is_ok());
    let sk1 = res.unwrap();
    assert_eq!(sk.u(), sk1.u());
    assert_eq!(sk.totient(), sk1.totient());
    assert_eq!(sk.lambda(), sk1.lambda());
    assert_eq!(sk.n(), sk1.n());
}

#[test]
fn bytes() {
    let res = DecryptionKey::with_safe_primes_unchecked(&b10(TEST_PRIMES[2]), &b10(TEST_PRIMES[3]));
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let bytes = pk.to_bytes();
    assert_eq!(bytes.len(), 256);
    let pk1 = EncryptionKey::from_bytes(bytes.as_slice()).unwrap();
    assert_eq!(pk1.n(), pk.n());

    let bytes = sk.to_bytes();
    assert_eq!(bytes.len(), 1032);
    let res = DecryptionKey::from_bytes(bytes.as_slice());
    assert!(res.is_ok());
    let sk1 = res.unwrap();
    assert_eq!(sk.u(), sk1.u());
    assert_eq!(sk.totient(), sk1.totient());
    assert_eq!(sk.lambda(), sk1.lambda());
    assert_eq!(sk.n(), sk1.n());
}

#[test]
fn proof() {
    let res = DecryptionKey::with_safe_primes_unchecked(&b10(TEST_PRIMES[2]), &b10(TEST_PRIMES[3]));
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let ssk = k256::SecretKey::random(rand::rngs::OsRng::default());
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

    let res = ProofSquareFree::generate::<sha2::Sha256>(&sk, nonce.as_slice());
    assert!(res.is_some());
    let proof = res.unwrap();

    assert!(proof.verify::<sha2::Sha256>(&pk, nonce.as_slice()));

    let mut bytes = proof.to_bytes();
    let res = ProofSquareFree::from_bytes(bytes.as_slice());
    assert!(res.is_ok());
    let proof1 = res.unwrap();
    assert_eq!(proof1.to_bytes(), proof.to_bytes());

    bytes[0] = bytes[1];
    let res = ProofSquareFree::from_bytes(bytes.as_slice());
    assert!(res.is_err());
}

#[test]
fn all() {
    let res = DecryptionKey::random();
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m = b"this is a test message";
    let res = pk.encrypt(m, None);
    assert!(res.is_some());

    let (c, _) = res.unwrap();
    let res = sk.decrypt(&c);
    assert!(res.is_some());
    let m1 = res.unwrap();
    assert_eq!(m1, m);

    // bad messages
    let nn1: BigNumber = pk.nn() + 1;
    let nn = pk.nn().to_bytes();
    let nn1_bytes = nn1.to_bytes();
    let bad_messages: [&[u8]; 3] = [b"", nn.as_slice(), nn1_bytes.as_slice()];

    for b in &bad_messages {
        let res = pk.encrypt(&b, None);
        assert!(res.is_none());
    }
}
