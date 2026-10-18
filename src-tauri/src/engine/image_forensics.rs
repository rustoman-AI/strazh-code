use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ImageLayer {
    pub index: u32,
    pub hash: String,
    pub command: String,
    pub layer_type: String,
    pub size_mb: f64,
    pub file_count: u32,
    pub packages: Vec<String>,
    pub cves: Vec<LayerCve>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LayerCve {
    pub cve_id: String,
    pub severity: String,
    pub package: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ImageAnalysis {
    pub image_name: String,
    pub image_tag: String,
    pub total_size_mb: f64,
    pub total_layers: u32,
    pub total_cves: u32,
    pub layers: Vec<ImageLayer>,
}

pub struct ImageForensics;

impl ImageForensics {
    pub fn get_image_layers() -> ImageAnalysis {
        let layers = vec![
            ImageLayer {
                index: 0,
                hash: "sha256:a3ed95caeb02".into(),
                command: "FROM debian:bookworm-slim".into(),
                layer_type: "base".into(),
                size_mb: 74.8,
                file_count: 8_432,
                packages: vec!["libc6:2.36".into(), "libssl3:3.0.11".into(), "zlib1g:1.2.13".into(), "coreutils:9.1".into(), "bash:5.2".into()],
                cves: vec![
                    LayerCve { cve_id: "CVE-2023-4911".into(), severity: "HIGH".into(), package: "libc6:2.36".into() },
                    LayerCve { cve_id: "CVE-2023-5678".into(), severity: "MEDIUM".into(), package: "libssl3:3.0.11".into() },
                ],
            },
            ImageLayer {
                index: 1,
                hash: "sha256:7b4d08708ebc".into(),
                command: "RUN apt-get update && apt-get install -y curl wget ca-certificates gnupg".into(),
                layer_type: "packages".into(),
                size_mb: 42.3,
                file_count: 2_891,
                packages: vec!["curl:7.88.1".into(), "wget:1.21.3".into(), "ca-certificates:20230311".into(), "gnupg:2.2.40".into()],
                cves: vec![
                    LayerCve { cve_id: "CVE-2023-38545".into(), severity: "CRITICAL".into(), package: "curl:7.88.1".into() },
                    LayerCve { cve_id: "CVE-2023-38546".into(), severity: "LOW".into(), package: "curl:7.88.1".into() },
                ],
            },
            ImageLayer {
                index: 2,
                hash: "sha256:c2adabaecedb".into(),
                command: "RUN apt-get install -y nginx=1.24.0-2 && rm -rf /var/lib/apt/lists/*".into(),
                layer_type: "packages".into(),
                size_mb: 18.6,
                file_count: 1_247,
                packages: vec!["nginx:1.24.0".into(), "libpcre2-8-0:10.42".into(), "libgd3:2.3.3".into()],
                cves: vec![
                    LayerCve { cve_id: "CVE-2023-44487".into(), severity: "HIGH".into(), package: "nginx:1.24.0".into() },
                ],
            },
            ImageLayer {
                index: 3,
                hash: "sha256:e1b7d245f3c8".into(),
                command: "RUN pip install flask==3.0.0 gunicorn==21.2.0 requests==2.31.0".into(),
                layer_type: "packages".into(),
                size_mb: 28.1,
                file_count: 3_156,
                packages: vec!["flask:3.0.0".into(), "gunicorn:21.2.0".into(), "requests:2.31.0".into(), "jinja2:3.1.2".into(), "werkzeug:3.0.1".into()],
                cves: vec![
                    LayerCve { cve_id: "CVE-2024-34064".into(), severity: "MEDIUM".into(), package: "jinja2:3.1.2".into() },
                ],
            },
            ImageLayer {
                index: 4,
                hash: "sha256:9f82d4c7a1e5".into(),
                command: "COPY ./app /opt/app".into(),
                layer_type: "application".into(),
                size_mb: 12.4,
                file_count: 847,
                packages: vec![],
                cves: vec![],
            },
            ImageLayer {
                index: 5,
                hash: "sha256:d3f2a8b91c4e".into(),
                command: "COPY nginx.conf /etc/nginx/nginx.conf".into(),
                layer_type: "config".into(),
                size_mb: 0.02,
                file_count: 1,
                packages: vec![],
                cves: vec![],
            },
            ImageLayer {
                index: 6,
                hash: "sha256:b7e9c3d60f12".into(),
                command: "RUN useradd -r appuser && chown -R appuser /opt/app".into(),
                layer_type: "config".into(),
                size_mb: 0.8,
                file_count: 24,
                packages: vec![],
                cves: vec![],
            },
            ImageLayer {
                index: 7,
                hash: "sha256:f4a1b8c25d93".into(),
                command: "CMD [\"gunicorn\", \"--bind\", \"0.0.0.0:8000\", \"app:create_app()\"]".into(),
                layer_type: "config".into(),
                size_mb: 0.0,
                file_count: 0,
                packages: vec![],
                cves: vec![],
            },
        ];

        let total_size: f64 = layers.iter().map(|l| l.size_mb).sum();
        let total_cves: u32 = layers.iter().map(|l| l.cves.len() as u32).sum();

        ImageAnalysis {
            image_name: "corp-registry.io/platform/api-gateway".into(),
            image_tag: "v2.14.3-bookworm".into(),
            total_size_mb: (total_size * 10.0).round() / 10.0,
            total_layers: layers.len() as u32,
            total_cves,
            layers,
        }
    }
}
