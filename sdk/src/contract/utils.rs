use alloy::primitives::FixedBytes;

use crate::contract::Core4Mica::G2Point;

impl From<[[u8; 32]; 8]> for G2Point {
    fn from(value: [[u8; 32]; 8]) -> Self {
        let [x0_hi, x0_lo, x1_hi, x1_lo, y0_hi, y0_lo, y1_hi, y1_lo] = value;
        G2Point {
            x_c0_a: FixedBytes::from(x0_hi),
            x_c0_b: FixedBytes::from(x0_lo),
            x_c1_a: FixedBytes::from(x1_hi),
            x_c1_b: FixedBytes::from(x1_lo),
            y_c0_a: FixedBytes::from(y0_hi),
            y_c0_b: FixedBytes::from(y0_lo),
            y_c1_a: FixedBytes::from(y1_hi),
            y_c1_b: FixedBytes::from(y1_lo),
        }
    }
}
