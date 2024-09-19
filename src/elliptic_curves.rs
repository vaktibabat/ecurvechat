use std::ops::Add;

use num_bigint::BigUint;

/// A general point; Can either have coordinates, or be the 'point at infinity' (O)
#[derive(Debug, PartialEq, Clone)]
pub enum Point {
    Coords(BigUint, BigUint),
    O,
}

/// A point (x, y) that lies on an EC
#[derive(Debug, PartialEq, Clone)]
pub struct CurvePoint {
    point: Point,
    curve: Curve,
}

/// An elliptic curve of the form y^2 = x^3 + ax + b
/// We only consider curves over `Z_p`, where p is a prime (i.e. the additive group of integers modulo p)
#[derive(PartialEq, Clone, Debug)]
pub struct Curve {
    a: BigUint,
    b: BigUint,
    p: BigUint,
}

#[derive(Debug)]
pub enum ECError {
    /// Performing operations on points from two different curves is an error
    DifferentCurves,
}

impl Add for CurvePoint {
    type Output = Result<CurvePoint, ECError>;

    fn add(self, rhs: Self) -> Self::Output {
        if self.curve != rhs.curve {
            Err(ECError::DifferentCurves)
        } else {
            let curve = self.curve;

            match (self.point, rhs.point) {
                // If either of the points is the point at infinity,
                // return the other, since the point at infinity is the identity element for point addition
                (Point::O, q) => Ok(CurvePoint { point: q, curve }),
                (p, Point::O) => Ok(CurvePoint { point: p, curve }),
                (Point::Coords(x1, y1), Point::Coords(x2, y2)) => {
                    // If P and Q are the inverse of each other (i.e. the reflection along the X axis)
                    if x1 == x2 && y1 == (&curve.p - &y2) {
                        Ok(CurvePoint {
                            point: Point::O,
                            curve,
                        })
                    } else {
                        // Compute the slope of the line defined by P and Q
                        let lambda = if (&x1, &y1) != (&x2, &y2) {
                            let denom = (&x2 + (&curve.p - &x1)).modinv(&curve.p).unwrap();
                            let nom = (y2 + (&curve.p - &y1)) % &curve.p;

                            (nom * denom) % &curve.p
                        } else {
                            // If they're the same point, lambda is different
                            let denom = (BigUint::from(2u64) * &y1).modinv(&curve.p).unwrap();
                            let nom = (BigUint::from(3u64) * &x1 * &x1 + &curve.a) % &curve.p;

                            (nom * denom) % &curve.p
                        };
                        // The coordinates of the result
                        let x3 =
                            (&lambda * &lambda + (&curve.p - &x1) + (&curve.p - &x2)) % &curve.p;
                        let y3 = ((lambda * (&x1 + (&curve.p - &x3))) % &curve.p
                            + (&curve.p - &y1))
                            % &curve.p;

                        Ok(CurvePoint {
                            point: Point::Coords(x3, y3),
                            curve,
                        })
                    }
                }
            }
        }
    }
}

impl Curve {
    /// Construct a new elliptic curve from its parameters
    pub fn new(a: BigUint, b: BigUint, p: BigUint) -> Curve {
        Curve { a, b, p }
    }

    // Getters
    pub fn p(&self) -> BigUint {
        self.p.clone()
    }

    pub fn a(&self) -> BigUint {
        self.a.clone()
    }

    pub fn b(&self) -> BigUint {
        self.b.clone()
    }

    /// Return a new point w/coordinates (x, y) on the curve
    /// x and y are reduced modulo p
    /// If one of the coordinates is None, the point at infinity is returned
    pub fn gen_point(&self, coords: Option<(&BigUint, &BigUint)>) -> CurvePoint {
        if let Some((x, y)) = coords {
            // Reduce the coordinates modulo p
            let x_red = x % &self.p;
            let y_red = y % &self.p;

            CurvePoint {
                point: Point::Coords(x_red, y_red),
                curve: self.clone(),
            }
        } else {
            CurvePoint {
                point: Point::O,
                curve: self.clone(),
            }
        }
    }
}

impl CurvePoint {
    // Mulitply the point by a scalar k. Multiplication by a scalar
    // is defined by adding the point to itself k times. We do this using the double-and-add algorithm
    // This is done acc. to the pseudocode on Wikipedia; see https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
    pub fn dot(&self, k: &BigUint) -> CurvePoint {
        // The bits of k, from LSB to MSB
        let bits: Vec<bool> = (0..k.bits()).map(|pos| k.bit(pos)).collect();
        let mut res = CurvePoint {
            point: Point::O,
            curve: self.curve.clone(),
        };
        let mut temp = self.clone();

        for bit in bits {
            if bit {
                res = (res + temp.clone()).unwrap();
            }

            temp = (temp.clone() + temp).unwrap();
        }

        res
    }

    // Getters
    pub fn point(&self) -> Point {
        self.point.clone()
    }

    pub fn curve(&self) -> Curve {
        self.curve.clone()
    }
}

impl Point {
    /// Returns the coordinates of the point. If the point is the point at infinity,
    /// `None` is returned instead
    pub fn coords(&self) -> Option<(BigUint, BigUint)> {
        match self {
            Point::Coords(x, y) => Some((x.clone(), y.clone())),
            Point::O => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Curve;
    use super::CurvePoint;

    // These three tests are taken from the cryptopals "Elliptic Curve Addition" challenge
    #[test]
    fn ec_addition_different_point() {
        let curve = Curve::new(497u64.into(), 1768u64.into(), 9739u64.into());
        let a = curve.gen_point(Some((&5274u64.into(), &2841u64.into())));
        let b = curve.gen_point(Some((&8669u64.into(), &740u64.into())));

        assert_eq!(
            (a + b).unwrap(),
            CurvePoint {
                point: crate::elliptic_curves::Point::Coords(1024u64.into(), 4440u64.into()),
                curve: Curve {
                    a: 497u64.into(),
                    b: 1768u64.into(),
                    p: 9739u64.into()
                }
            }
        )
    }

    #[test]
    fn ec_addition_same_point() {
        let curve = Curve::new(497u64.into(), 1768u64.into(), 9739u64.into());
        let a = curve.gen_point(Some((&5274u64.into(), &2841u64.into())));

        assert_eq!(
            (a.clone() + a.clone()).unwrap(),
            CurvePoint {
                point: crate::elliptic_curves::Point::Coords(7284u64.into(), 2107u64.into()),
                curve: Curve {
                    a: 497u64.into(),
                    b: 1768u64.into(),
                    p: 9739u64.into()
                }
            }
        );
    }

    #[test]
    fn three_points_addition() {
        let curve = Curve::new(497u64.into(), 1768u64.into(), 9739u64.into());
        let a = curve.gen_point(Some((&493u64.into(), &5564u64.into())));
        let b = curve.gen_point(Some((&1539u64.into(), &4742u64.into())));
        let c = curve.gen_point(Some((&4403u64.into(), &5202u64.into())));

        assert_eq!(
            (((a.clone() + a).unwrap() + b).unwrap() + c).unwrap(),
            CurvePoint {
                point: crate::elliptic_curves::Point::Coords(4215u64.into(), 2162u64.into()),
                curve: Curve {
                    a: 497u64.into(),
                    b: 1768u64.into(),
                    p: 9739u64.into()
                }
            }
        )
    }

    // Test taken from Cryptohack "Scalar Multiplication" challenge under ECC category
    #[test]
    fn test_dot() {
        let curve = Curve::new(497u64.into(), 1768u64.into(), 9739u64.into());
        let a = curve.gen_point(Some((&5323u64.into(), &5438u64.into())));

        assert_eq!(
            a.dot(&1337u64.into()),
            CurvePoint {
                point: crate::elliptic_curves::Point::Coords(1089u64.into(), 6931u64.into()),
                curve: Curve {
                    a: 497u64.into(),
                    b: 1768u64.into(),
                    p: 9739u64.into()
                }
            }
        )
    }
}
