use unknown_order::BigNumber;

pub fn mod_in(a: &BigNumber, n: &BigNumber) -> bool {
    let lhs = &BigNumber::one() <= a;
    let rhs = a < n;
    lhs & rhs
}
