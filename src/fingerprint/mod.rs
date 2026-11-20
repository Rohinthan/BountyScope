use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Structured classification categories for passively detected technologies.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum TechCategory {
    /// Web Application Firewall (WAF) or Content Delivery Network (CDN)
    WafCdn,
    /// Web server or reverse proxy infrastructure
    WebServer,
    /// Application framework, library, or language runtime
    Framework,
    /// Content Management System (CMS) or blogging platform
    Cms,
    /// Managed cloud hosting or serverless platform
    HostingPlatform,
}

impl TechCategory {
    /// Returns the static string representation of the category.
    pub fn as_str(&self) -> &'static str {
        match self {
            TechCategory::WafCdn => "WafCdn",
            TechCategory::WebServer => "WebServer",
            TechCategory::Framework => "Framework",
            TechCategory::Cms => "Cms",
            TechCategory::HostingPlatform => "HostingPlatform",
        }
    }
}

impl fmt::Display for TechCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for TechCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "WafCdn" | "waf_cdn" | "waf" | "cdn" => Ok(TechCategory::WafCdn),
            "WebServer" | "web_server" | "server" => Ok(TechCategory::WebServer),
            "Framework" | "framework" => Ok(TechCategory::Framework),
            "Cms" | "cms" => Ok(TechCategory::Cms),
            "HostingPlatform" | "hosting_platform" | "hosting" => Ok(TechCategory::HostingPlatform),
            other => Err(format!("Unknown TechCategory: {other}")),
        }
    }
}

/// A technology component identified through passive response analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DetectedTechnology {
    /// Canonical technology identifier (e.g. Cloudflare, Nginx, Next.js).
    pub name: String,
    /// Technology classification category.
    pub category: TechCategory,
    /// Version string if identifiable from headers or meta tags (e.g. "1.24.0").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Header name, cookie identifier, or HTML marker that triggered detection.
    /// Under no circumstance contains sensitive session cookie values or authorization tokens.
    pub evidence: String,
    /// Target endpoint URL where the evidence was observed.
    pub endpoint: String,
}

/// Passive, zero-network-I/O fingerprinting engine.
///
/// Inspects already-collected HTTP response metadata (status, headers, Set-Cookie names,
/// and HTML body markers) to identify web technologies, frameworks, servers, and WAFs
/// without generating any additional network requests.
pub struct PassiveFingerprinter;

impl PassiveFingerprinter {
    /// Inspects HTTP response attributes and returns deduplicated detected technologies.
    pub fn fingerprint(
        endpoint_url: &str,
        _status_code: u16,
        headers: &[(String, String)],
        body_str: Option<&str>,
    ) -> Vec<DetectedTechnology> {
        let mut detections: Vec<DetectedTechnology> = Vec::new();

        // 1. Extract cookie names (strictly omitting cookie values and attributes)
        let cookie_names = Self::extract_cookie_names(headers);

        // 2. Build header lookup maps for case-insensitive querying
        let mut header_map: HashMap<String, Vec<&str>> = HashMap::new();
        for (k, v) in headers {
            header_map
                .entry(k.to_ascii_lowercase())
                .or_default()
                .push(v.trim());
        }

        // --- WAF / CDN Detection ---

        // Cloudflare: cf-ray, cf-cache-status, __cf_bm cookie, or server: cloudflare
        if header_map.contains_key("cf-ray") {
            detections.push(DetectedTechnology {
                name: "Cloudflare".to_string(),
                category: TechCategory::WafCdn,
                version: None,
                evidence: "Header cf-ray".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        } else if header_map.contains_key("cf-cache-status") {
            detections.push(DetectedTechnology {
                name: "Cloudflare".to_string(),
                category: TechCategory::WafCdn,
                version: None,
                evidence: "Header cf-cache-status".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        } else if cookie_names
            .iter()
            .any(|c| c == "__cf_bm" || c == "cf_clearance")
        {
            detections.push(DetectedTechnology {
                name: "Cloudflare".to_string(),
                category: TechCategory::WafCdn,
                version: None,
                evidence: "Set-Cookie: __cf_bm".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        } else if let Some(servers) = header_map.get("server") {
            if servers
                .iter()
                .any(|s| s.to_ascii_lowercase().contains("cloudflare"))
            {
                detections.push(DetectedTechnology {
                    name: "Cloudflare".to_string(),
                    category: TechCategory::WafCdn,
                    version: None,
                    evidence: "Header server: cloudflare".to_string(),
                    endpoint: endpoint_url.to_string(),
                });
            }
        }

        // AWS CloudFront: x-amz-cf-id, x-amz-cf-pop, or via containing CloudFront
        if header_map.contains_key("x-amz-cf-id") {
            detections.push(DetectedTechnology {
                name: "AWS CloudFront".to_string(),
                category: TechCategory::WafCdn,
                version: None,
                evidence: "Header x-amz-cf-id".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        } else if header_map.contains_key("x-amz-cf-pop") {
            detections.push(DetectedTechnology {
                name: "AWS CloudFront".to_string(),
                category: TechCategory::WafCdn,
                version: None,
                evidence: "Header x-amz-cf-pop".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        } else if let Some(vias) = header_map.get("via") {
            if vias
                .iter()
                .any(|v| v.to_ascii_lowercase().contains("cloudfront"))
            {
                detections.push(DetectedTechnology {
                    name: "AWS CloudFront".to_string(),
                    category: TechCategory::WafCdn,
                    version: None,
                    evidence: "Header via: CloudFront".to_string(),
                    endpoint: endpoint_url.to_string(),
                });
            }
        }

        // Fastly: x-served-by, x-fastly-request-id, or fastly-restarts
        if header_map.contains_key("x-fastly-request-id") {
            detections.push(DetectedTechnology {
                name: "Fastly".to_string(),
                category: TechCategory::WafCdn,
                version: None,
                evidence: "Header x-fastly-request-id".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        } else if header_map.contains_key("x-served-by") {
            detections.push(DetectedTechnology {
                name: "Fastly".to_string(),
                category: TechCategory::WafCdn,
                version: None,
                evidence: "Header x-served-by".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // Akamai: x-akamai-transformed, akamai-grn, or server AkamaiGHost
        if header_map.contains_key("x-akamai-transformed") {
            detections.push(DetectedTechnology {
                name: "Akamai".to_string(),
                category: TechCategory::WafCdn,
                version: None,
                evidence: "Header x-akamai-transformed".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        } else if header_map.contains_key("akamai-grn") {
            detections.push(DetectedTechnology {
                name: "Akamai".to_string(),
                category: TechCategory::WafCdn,
                version: None,
                evidence: "Header akamai-grn".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        } else if let Some(servers) = header_map.get("server") {
            if servers.iter().any(|s| s.contains("AkamaiGHost")) {
                detections.push(DetectedTechnology {
                    name: "Akamai".to_string(),
                    category: TechCategory::WafCdn,
                    version: None,
                    evidence: "Header server: AkamaiGHost".to_string(),
                    endpoint: endpoint_url.to_string(),
                });
            }
        }

        // Imperva / Incapsula: x-iinfo, visid_incap_ cookie, or x-cdn: Incapsula
        if header_map.contains_key("x-iinfo") {
            detections.push(DetectedTechnology {
                name: "Imperva Incapsula".to_string(),
                category: TechCategory::WafCdn,
                version: None,
                evidence: "Header x-iinfo".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        } else if cookie_names
            .iter()
            .any(|c| c.starts_with("visid_incap") || c.starts_with("incap_ses"))
        {
            detections.push(DetectedTechnology {
                name: "Imperva Incapsula".to_string(),
                category: TechCategory::WafCdn,
                version: None,
                evidence: "Set-Cookie: visid_incap_".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // Sucuri: x-sucuri-id or x-sucuri-cache
        if header_map.contains_key("x-sucuri-id") || header_map.contains_key("x-sucuri-cache") {
            detections.push(DetectedTechnology {
                name: "Sucuri".to_string(),
                category: TechCategory::WafCdn,
                version: None,
                evidence: "Header x-sucuri-id".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // --- Web Server / Reverse Proxy Detection ---

        if let Some(servers) = header_map.get("server") {
            for server_header in servers {
                let lower = server_header.to_ascii_lowercase();

                // Nginx
                if lower.contains("nginx") {
                    let version = Self::extract_version(server_header, "nginx/");
                    detections.push(DetectedTechnology {
                        name: "Nginx".to_string(),
                        category: TechCategory::WebServer,
                        version,
                        evidence: format!("Header server: {server_header}"),
                        endpoint: endpoint_url.to_string(),
                    });
                }

                // Apache
                if lower.contains("apache") {
                    let version = Self::extract_version(server_header, "apache/");
                    detections.push(DetectedTechnology {
                        name: "Apache".to_string(),
                        category: TechCategory::WebServer,
                        version,
                        evidence: format!("Header server: {server_header}"),
                        endpoint: endpoint_url.to_string(),
                    });
                }

                // Caddy
                if lower.contains("caddy") {
                    let version = Self::extract_version(server_header, "caddy/");
                    detections.push(DetectedTechnology {
                        name: "Caddy".to_string(),
                        category: TechCategory::WebServer,
                        version,
                        evidence: format!("Header server: {server_header}"),
                        endpoint: endpoint_url.to_string(),
                    });
                }

                // Envoy
                if lower.contains("envoy") {
                    detections.push(DetectedTechnology {
                        name: "Envoy".to_string(),
                        category: TechCategory::WebServer,
                        version: None,
                        evidence: format!("Header server: {server_header}"),
                        endpoint: endpoint_url.to_string(),
                    });
                }

                // Microsoft-IIS
                if lower.contains("microsoft-iis") {
                    let version = Self::extract_version(server_header, "microsoft-iis/");
                    detections.push(DetectedTechnology {
                        name: "Microsoft-IIS".to_string(),
                        category: TechCategory::WebServer,
                        version,
                        evidence: format!("Header server: {server_header}"),
                        endpoint: endpoint_url.to_string(),
                    });
                }

                // OpenResty
                if lower.contains("openresty") {
                    let version = Self::extract_version(server_header, "openresty/");
                    detections.push(DetectedTechnology {
                        name: "OpenResty".to_string(),
                        category: TechCategory::WebServer,
                        version,
                        evidence: format!("Header server: {server_header}"),
                        endpoint: endpoint_url.to_string(),
                    });
                }
            }
        }

        // Envoy additional indicator: x-envoy-upstream-service-time
        if header_map.contains_key("x-envoy-upstream-service-time")
            && !detections.iter().any(|d| d.name == "Envoy")
        {
            detections.push(DetectedTechnology {
                name: "Envoy".to_string(),
                category: TechCategory::WebServer,
                version: None,
                evidence: "Header x-envoy-upstream-service-time".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // --- Hosting Platform Detection ---

        // Vercel: x-vercel-id or x-vercel-cache
        if header_map.contains_key("x-vercel-id") || header_map.contains_key("x-vercel-cache") {
            detections.push(DetectedTechnology {
                name: "Vercel".to_string(),
                category: TechCategory::HostingPlatform,
                version: None,
                evidence: "Header x-vercel-id".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // Netlify: x-nf-request-id
        if header_map.contains_key("x-nf-request-id") {
            detections.push(DetectedTechnology {
                name: "Netlify".to_string(),
                category: TechCategory::HostingPlatform,
                version: None,
                evidence: "Header x-nf-request-id".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // Render: x-render-origin-server
        if header_map.contains_key("x-render-origin-server") {
            detections.push(DetectedTechnology {
                name: "Render".to_string(),
                category: TechCategory::HostingPlatform,
                version: None,
                evidence: "Header x-render-origin-server".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // --- Application Framework & Runtime Detection ---

        // Next.js: x-nextjs-cache, x-nextjs-matched-path, or body indicators
        let mut nextjs_detected = false;
        if header_map.contains_key("x-nextjs-cache") {
            detections.push(DetectedTechnology {
                name: "Next.js".to_string(),
                category: TechCategory::Framework,
                version: None,
                evidence: "Header x-nextjs-cache".to_string(),
                endpoint: endpoint_url.to_string(),
            });
            nextjs_detected = true;
        }

        // Express: x-powered-by containing Express
        if let Some(powered_bys) = header_map.get("x-powered-by") {
            for powered_by in powered_bys {
                let lower = powered_by.to_ascii_lowercase();
                if lower.contains("express") {
                    detections.push(DetectedTechnology {
                        name: "Express".to_string(),
                        category: TechCategory::Framework,
                        version: None,
                        evidence: format!("Header x-powered-by: {powered_by}"),
                        endpoint: endpoint_url.to_string(),
                    });
                }
                if lower.contains("php") {
                    let version = Self::extract_version(powered_by, "php/");
                    detections.push(DetectedTechnology {
                        name: "PHP".to_string(),
                        category: TechCategory::Framework,
                        version,
                        evidence: format!("Header x-powered-by: {powered_by}"),
                        endpoint: endpoint_url.to_string(),
                    });
                }
                if lower.contains("asp.net") {
                    detections.push(DetectedTechnology {
                        name: "ASP.NET".to_string(),
                        category: TechCategory::Framework,
                        version: None,
                        evidence: format!("Header x-powered-by: {powered_by}"),
                        endpoint: endpoint_url.to_string(),
                    });
                }
            }
        }

        // ASP.NET: x-aspnet-version or ASP.NET_SessionId cookie
        if let Some(aspnet_vers) = header_map.get("x-aspnet-version") {
            let version = aspnet_vers.first().map(|v| v.to_string());
            if !detections.iter().any(|d| d.name == "ASP.NET") {
                detections.push(DetectedTechnology {
                    name: "ASP.NET".to_string(),
                    category: TechCategory::Framework,
                    version,
                    evidence: "Header x-aspnet-version".to_string(),
                    endpoint: endpoint_url.to_string(),
                });
            }
        } else if cookie_names
            .iter()
            .any(|c| c.eq_ignore_ascii_case("asp.net_sessionid"))
            && !detections.iter().any(|d| d.name == "ASP.NET")
        {
            detections.push(DetectedTechnology {
                name: "ASP.NET".to_string(),
                category: TechCategory::Framework,
                version: None,
                evidence: "Set-Cookie: ASP.NET_SessionId".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // PHP: PHPSESSID cookie
        if cookie_names.iter().any(|c| c == "PHPSESSID")
            && !detections.iter().any(|d| d.name == "PHP")
        {
            detections.push(DetectedTechnology {
                name: "PHP".to_string(),
                category: TechCategory::Framework,
                version: None,
                evidence: "Set-Cookie: PHPSESSID".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // Django: csrftoken cookie
        if cookie_names.iter().any(|c| c == "csrftoken") {
            detections.push(DetectedTechnology {
                name: "Django".to_string(),
                category: TechCategory::Framework,
                version: None,
                evidence: "Set-Cookie: csrftoken".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // Ruby on Rails: _rails_session or x-rack-cache
        if cookie_names.iter().any(|c| c.contains("_rails_session")) {
            detections.push(DetectedTechnology {
                name: "Ruby on Rails".to_string(),
                category: TechCategory::Framework,
                version: None,
                evidence: "Set-Cookie: _rails_session".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        } else if header_map.contains_key("x-rack-cache") {
            detections.push(DetectedTechnology {
                name: "Ruby on Rails".to_string(),
                category: TechCategory::Framework,
                version: None,
                evidence: "Header x-rack-cache".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // Spring Boot: x-application-context or JSESSIONID cookie
        if header_map.contains_key("x-application-context") {
            detections.push(DetectedTechnology {
                name: "Spring Boot".to_string(),
                category: TechCategory::Framework,
                version: None,
                evidence: "Header x-application-context".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        } else if cookie_names.iter().any(|c| c == "JSESSIONID") {
            detections.push(DetectedTechnology {
                name: "Java / Spring Boot".to_string(),
                category: TechCategory::Framework,
                version: None,
                evidence: "Set-Cookie: JSESSIONID".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // --- HTML Body & Meta Tag Detection ---
        if let Some(body) = body_str {
            // Next.js HTML markers
            if !nextjs_detected
                && (body.contains("/_next/static/") || body.contains("__NEXT_DATA__"))
            {
                detections.push(DetectedTechnology {
                    name: "Next.js".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    evidence: if body.contains("/_next/static/") {
                        "HTML marker: /_next/static/".to_string()
                    } else {
                        "HTML marker: __NEXT_DATA__".to_string()
                    },
                    endpoint: endpoint_url.to_string(),
                });
            }

            // Nuxt HTML markers
            if body.contains("__NUXT__") || body.contains("/_nuxt/") {
                detections.push(DetectedTechnology {
                    name: "Nuxt".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    evidence: if body.contains("__NUXT__") {
                        "HTML marker: __NUXT__".to_string()
                    } else {
                        "HTML marker: /_nuxt/".to_string()
                    },
                    endpoint: endpoint_url.to_string(),
                });
            }

            // WordPress HTML markers & meta generator
            if let Some(wp_version) = Self::extract_meta_generator(body, "WordPress") {
                detections.push(DetectedTechnology {
                    name: "WordPress".to_string(),
                    category: TechCategory::Cms,
                    version: Some(wp_version.clone()),
                    evidence: format!("HTML meta generator: WordPress {wp_version}"),
                    endpoint: endpoint_url.to_string(),
                });
            } else if body.contains("wp-content/") || body.contains("wp-includes/") {
                detections.push(DetectedTechnology {
                    name: "WordPress".to_string(),
                    category: TechCategory::Cms,
                    version: None,
                    evidence: "HTML marker: wp-content/".to_string(),
                    endpoint: endpoint_url.to_string(),
                });
            }
        }

        // WordPress cookie indicator
        if cookie_names
            .iter()
            .any(|c| c.starts_with("wordpress_") || c.starts_with("wp-settings-"))
            && !detections.iter().any(|d| d.name == "WordPress")
        {
            detections.push(DetectedTechnology {
                name: "WordPress".to_string(),
                category: TechCategory::Cms,
                version: None,
                evidence: "Set-Cookie: wordpress_".to_string(),
                endpoint: endpoint_url.to_string(),
            });
        }

        // Deduplicate detections per response by (name, category)
        Self::deduplicate(detections)
    }

    /// Extracts cookie names from `Set-Cookie` headers, strictly omitting values and parameters.
    pub fn extract_cookie_names(headers: &[(String, String)]) -> Vec<String> {
        let mut names = Vec::new();
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                // Set-Cookie syntax: <cookie-name>=<cookie-value>; Domain=...; Path=...
                let first_part = v.split(';').next().unwrap_or("").trim();
                if let Some((name, _)) = first_part.split_once('=') {
                    let trimmed_name = name.trim();
                    if !trimmed_name.is_empty() {
                        names.push(trimmed_name.to_string());
                    }
                } else if !first_part.is_empty() {
                    names.push(first_part.to_string());
                }
            }
        }
        names
    }

    /// Attempts to extract a version substring after a known prefix (e.g., "nginx/1.24.0" -> "1.24.0").
    fn extract_version(header_value: &str, prefix: &str) -> Option<String> {
        let lower = header_value.to_ascii_lowercase();
        if let Some(pos) = lower.find(prefix) {
            let start = pos + prefix.len();
            let remainder = &header_value[start..];
            let version: String = remainder
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == '_')
                .collect();
            if !version.is_empty() && version.chars().any(|c| c.is_ascii_digit()) {
                return Some(version);
            }
        }
        None
    }

    /// Extracts version from `<meta name="generator" content="WordPress 6.4.2">` if present.
    fn extract_meta_generator(html_body: &str, target_system: &str) -> Option<String> {
        let pattern = format!(
            r#"(?i)<meta\s+name=["']generator["']\s+content=["']{}\s*([0-9\.]+)["']"#,
            regex::escape(target_system)
        );
        if let Ok(re) = Regex::new(&pattern) {
            if let Some(caps) = re.captures(html_body) {
                if let Some(m) = caps.get(1) {
                    return Some(m.as_str().trim().to_string());
                }
            }
        }
        None
    }

    /// Deduplicates detected technologies by canonical name and category, preserving version information.
    pub fn deduplicate(detections: Vec<DetectedTechnology>) -> Vec<DetectedTechnology> {
        let mut map: HashMap<(String, TechCategory), DetectedTechnology> = HashMap::new();
        for det in detections {
            let key = (det.name.clone(), det.category);
            map.entry(key)
                .and_modify(|existing| {
                    if existing.version.is_none() && det.version.is_some() {
                        existing.version = det.version.clone();
                    }
                })
                .or_insert(det);
        }

        let mut result: Vec<DetectedTechnology> = map.into_values().collect();
        result.sort_by(|a, b| {
            a.category
                .cmp(&b.category)
                .then_with(|| a.name.cmp(&b.name))
        });
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_detection_headers_and_cookies() {
        let headers = vec![
            ("CF-RAY".to_string(), "8e5f03918a221f00-IAD".to_string()),
            ("Server".to_string(), "cloudflare".to_string()),
        ];
        let detections =
            PassiveFingerprinter::fingerprint("https://example.com", 200, &headers, None);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].name, "Cloudflare");
        assert_eq!(detections[0].category, TechCategory::WafCdn);
        assert_eq!(detections[0].evidence, "Header cf-ray");
    }

    #[test]
    fn test_aws_cloudfront_detection() {
        let headers = vec![
            ("X-Amz-Cf-Id".to_string(), "xyz123==".to_string()),
            (
                "Via".to_string(),
                "1.1 abc.cloudfront.net (CloudFront)".to_string(),
            ),
        ];
        let detections =
            PassiveFingerprinter::fingerprint("https://example.com/api", 200, &headers, None);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].name, "AWS CloudFront");
        assert_eq!(detections[0].category, TechCategory::WafCdn);
    }

    #[test]
    fn test_nginx_and_express_detection_with_version() {
        let headers = vec![
            ("Server".to_string(), "nginx/1.24.0 (Ubuntu)".to_string()),
            ("X-Powered-By".to_string(), "Express".to_string()),
        ];
        let detections =
            PassiveFingerprinter::fingerprint("https://example.com", 200, &headers, None);
        assert_eq!(detections.len(), 2);

        let nginx = detections
            .iter()
            .find(|d| d.name == "Nginx")
            .expect("nginx");
        assert_eq!(nginx.category, TechCategory::WebServer);
        assert_eq!(nginx.version.as_deref(), Some("1.24.0"));

        let express = detections
            .iter()
            .find(|d| d.name == "Express")
            .expect("express");
        assert_eq!(express.category, TechCategory::Framework);
        assert_eq!(express.evidence, "Header x-powered-by: Express");
    }

    #[test]
    fn test_nextjs_html_markers() {
        let html = r#"<!DOCTYPE html><html><head><script id="__NEXT_DATA__" type="application/json">{}</script><script src="/_next/static/chunks/main.js"></script></head><body></body></html>"#;
        let detections =
            PassiveFingerprinter::fingerprint("https://example.com", 200, &[], Some(html));
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].name, "Next.js");
        assert_eq!(detections[0].category, TechCategory::Framework);
    }

    #[test]
    fn test_django_csrftoken_cookie_detection() {
        let headers = vec![(
            "Set-Cookie".to_string(),
            "csrftoken=supersecrettokenvalue12345; Path=/; Domain=.example.com; Secure; SameSite=Lax".to_string(),
        )];
        let detections =
            PassiveFingerprinter::fingerprint("https://example.com/login", 200, &headers, None);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].name, "Django");
        assert_eq!(detections[0].category, TechCategory::Framework);
        assert_eq!(detections[0].evidence, "Set-Cookie: csrftoken");
    }

    #[test]
    fn test_wordpress_html_and_meta_generator() {
        let html = r#"<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /><link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css" /></head></html>"#;
        let detections =
            PassiveFingerprinter::fingerprint("https://example.com", 200, &[], Some(html));
        assert_eq!(detections.len(), 1);
        let wp = &detections[0];
        assert_eq!(wp.name, "WordPress");
        assert_eq!(wp.category, TechCategory::Cms);
        assert_eq!(wp.version.as_deref(), Some("6.4.2"));
        assert!(wp.evidence.contains("WordPress 6.4.2"));
    }

    #[test]
    fn test_raw_cookie_values_never_leaked_into_evidence() {
        let headers = vec![
            (
                "Set-Cookie".to_string(),
                "PHPSESSID=session_secret_value_xyz999; path=/; HttpOnly; Secure".to_string(),
            ),
            (
                "Set-Cookie".to_string(),
                "ASP.NET_SessionId=asp_secret_token_123; path=/; HttpOnly".to_string(),
            ),
            (
                "Set-Cookie".to_string(),
                "csrftoken=django_csrf_secret_abc456; Path=/".to_string(),
            ),
        ];

        let detections =
            PassiveFingerprinter::fingerprint("https://example.com", 200, &headers, None);

        for det in &detections {
            // Confirm raw sensitive values are not in evidence
            assert!(
                !det.evidence.contains("session_secret_value_xyz999"),
                "Leaked PHP session value in evidence: {}",
                det.evidence
            );
            assert!(
                !det.evidence.contains("asp_secret_token_123"),
                "Leaked ASP.NET session value in evidence: {}",
                det.evidence
            );
            assert!(
                !det.evidence.contains("django_csrf_secret_abc456"),
                "Leaked Django CSRF value in evidence: {}",
                det.evidence
            );
        }

        // Verify clean evidence strings
        let php = detections.iter().find(|d| d.name == "PHP").expect("php");
        assert_eq!(php.evidence, "Set-Cookie: PHPSESSID");

        let asp = detections
            .iter()
            .find(|d| d.name == "ASP.NET")
            .expect("asp.net");
        assert_eq!(asp.evidence, "Set-Cookie: ASP.NET_SessionId");

        let django = detections
            .iter()
            .find(|d| d.name == "Django")
            .expect("django");
        assert_eq!(django.evidence, "Set-Cookie: csrftoken");
    }
}
