use std::cmp::max;
use std::fmt;
use std::fmt::Formatter;
use crate::shampoo::VERBOSE;
use std::sync::atomic::Ordering::Relaxed;

// stolen!
pub fn mag_fmt(value: u64) -> String {
    fn scale_num(value: u64, base: u64) -> String {
        let fp = value as f64 / base as f64;
        let rounded = (fp + 0.5f64) as u64;
        if rounded < 10 {
            format!("{:.1}", fp)
        } else {
            format!("{}", rounded)
        }
    }

    if value == 0u64 {
        String::from("0b")
    } else if value > 999_999_999 {
        scale_num(value, 1_000_000_000) + "g"
    } else if value > 999_999 {
        scale_num(value, 1_000_000) + "m"
    } else if value > 999 {
        scale_num(value, 1_000) + "k"
    } else {
        scale_num(value, 1) + "b"
    }
}

#[derive(Debug)]
pub struct Matrix {
    data: Vec<Vec<String>>
}

impl Matrix {
    pub fn new() -> Matrix {
        Matrix { data: vec![vec![]] }
    }

    pub fn add(&mut self, s: &str) {
        let l = self.data.len() - 1;
        self.data[l].push(s.to_string());
    }

    pub fn nl(&mut self) {
        self.data.push(Vec::new());
    }

    pub fn is_empty(&self) -> bool {
        self.data.len() == 1 && self.data[0].len() == 0
    }
}

impl fmt::Display for Matrix {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let cols = self.data
            .iter()
            .map(|row| row.len())
            .max()
            .unwrap();

        let mut widths = vec![0; cols];
        for i in 0..self.data.len() {
            for j in 0..self.data[i].len() {
                widths[j] = max(widths[j], self.data[i][j].len());
            }
        }

        for i in 0..self.data.len() {
            for j in 0..self.data[i].len() {
                let cell = &self.data[i][j];
                write!(f, "{} ", cell)?;

                if widths[j] > cell.len() {
                    for _ in 0..(widths[j] - cell.len()) {
                        write!(f, " ")?;
                    }
                }
            }

            if i < self.data.len() -1 || self.data[i].len() > 0 {
                write!(f, "\n")?;
            }
        }
        Ok(())
    }
}

pub fn puts(txt:String) {
    if VERBOSE.load(Relaxed) {
        println!("{}", txt);
    }
}

#[cfg(test)]
mod test {
    use crate::util::{mag_fmt, Matrix};

    #[test]
    fn test_mag_fmt() {
        assert_eq!("543b", mag_fmt(543));
        assert_eq!("1.0k", mag_fmt(1000));
        assert_eq!("1.2k", mag_fmt(1234));
        assert_eq!("1.3k", mag_fmt(1294));
        assert_eq!("13m", mag_fmt(12944723));
        assert_eq!("1.3m", mag_fmt(1294472));
        assert_eq!("1.0g", mag_fmt(1_000_000_000));

        assert_eq!("10b", mag_fmt(10));
        assert_eq!("10k", mag_fmt(10_000));
        assert_eq!("10m", mag_fmt(10_000_000));
        assert_eq!("10g", mag_fmt(10_000_000_000));

        assert_eq!("1.0b", mag_fmt(1));
        assert_eq!("1.0k", mag_fmt(1000));
        assert_eq!("1.0m", mag_fmt(1000_000));
        assert_eq!("1.0g", mag_fmt(1000_000_000));

        assert_eq!("10m", mag_fmt(9962084));
    }

    #[test]
    fn test_matrix() {
        let mut mat = Matrix::new();
        assert!(mat.is_empty());

        mat.add("hi");
        assert!(!mat.is_empty());

        mat.add("def");
        mat.add("jar");
        mat.nl();
        mat.add("xxxee");
        mat.add(".");

        let str = format!("{}", mat);
        println!("{}", str);
        assert_eq!("hi    def jar \nxxxee .   \n", str);
    }
}
