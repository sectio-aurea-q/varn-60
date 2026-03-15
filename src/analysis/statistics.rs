use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Statistics {
    pub mean: f64,
    pub median: f64,
    pub stddev: f64,
    pub variance: f64,
    pub min: u64,
    pub max: u64,
    pub percentile_5: f64,
    pub percentile_95: f64,
    pub sample_count: usize,
}

impl Statistics {
    pub fn from_samples(samples: &[u64]) -> Self {
        let n = samples.len();
        assert!(n > 0);

        let mut sorted: Vec<u64> = samples.to_vec();
        sorted.sort_unstable();

        // Trim top/bottom 1% outliers
        let trim = std::cmp::max(1, n / 100);
        let trimmed = &sorted[trim..n - trim];

        let sum: f64 = trimmed.iter().map(|&x| x as f64).sum();
        let mean = sum / trimmed.len() as f64;

        let variance: f64 = trimmed.iter()
            .map(|&x| { let d = x as f64 - mean; d * d })
            .sum::<f64>() / (trimmed.len() - 1).max(1) as f64;

        let stddev = variance.sqrt();

        let median = if trimmed.len() % 2 == 0 {
            (trimmed[trimmed.len() / 2 - 1] as f64 + trimmed[trimmed.len() / 2] as f64) / 2.0
        } else {
            trimmed[trimmed.len() / 2] as f64
        };

        Statistics {
            mean,
            median,
            stddev,
            variance,
            min: sorted[0],
            max: sorted[n - 1],
            percentile_5: trimmed[trimmed.len() * 5 / 100] as f64,
            percentile_95: trimmed[std::cmp::min(trimmed.len() * 95 / 100, trimmed.len() - 1)] as f64,
            sample_count: n,
        }
    }
}

pub fn normal_cdf(x: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.2316419 * x.abs());
    let d = 0.3989422804014327;
    let p = d * (-x * x / 2.0).exp();
    let poly = t * (0.319381530 + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))));
    if x >= 0.0 { 1.0 - p * poly } else { p * poly }
}
