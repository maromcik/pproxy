# pproxy

pproxy is a lightweight, configurable reverse proxy written in Rust, built on top of Pingora — a high-performance async proxy framework developed by Cloudflare. 

---

## Features

* Reverse proxy with per-host and per-domain configuration
* TLS support with custom certificates
* Header injection and proxy header overrides
* User-Agent, GeoIP, and ISP filtering
* IP-based allow/deny rules
* URL rewrite and redirect rules
* Built-in WAF integration (blocklists + Geo API)
* Optional host monitoring (wake/suspend for machines that do not need to be running at all times)

---

## Configuration Overview

Configuration is defined in a TOML file and loaded at startup.

### Global Settings

```toml
app_log_level = "info"
all_log_level = "warn"
static_files_path = "/opt/systemd/pproxy/static"
```

* `app_log_level`: Logging level for application-specific logs
* `all_log_level`: Global log filtering level
* `static_files_path`: Path to static assets (if used)

---

### Control Interface

```toml
[control]
listen = "0.0.0.0:5050"
```

* Exposes a control/monitor interface (e.g. `/control/<monitor>`)

---

### WAF Configuration

```toml
[waf]
# blocklist_url = "http://..."
geo_cache_file_path = "/opt/systemd/pproxy/geo_cache"
geo_api_url = "https://api.iplocation.net?ip="
```

* `blocklist_url`: Optional external blocklist
* `geo_api_url`: GeoIP lookup endpoint
* `geo_cache_file_path`: Local cache for GeoIP results

---

## Hosts and Servers

### Host Binding

```toml
[hosts."0.0.0.0:443"]
tls = true
```

* Defines a listening address and port
* `tls`: Enables TLS termination

---

### Server Configuration

```toml
[hosts."0.0.0.0:443".servers."example.com"]
upstream = "192.168.0.10:8000"
upstream_tls = false
cert_path = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_path = "/etc/letsencrypt/live/example.com/privkey.pem"
```

* `upstream`: Target backend
* `upstream_tls`: Use HTTPS to upstream
* `cert_path`, `key_path`: TLS certificate files

---

### Request Filtering

```toml
user_agent_blocklist = ["facebook", "scapy"]
geo_fence_country_allowlist = ["SK", "CZ", "GB"]
geo_fence_isp_blocklist = ["Amazon Data Services UK"]
```

* Block requests by User-Agent
* Allow only specific countries
* Block specific ISPs

---

### Headers

#### Response headers

```toml
[hosts."0.0.0.0:443".servers."example.com".headers]
X-Frame-Options = "SAMEORIGIN"
```

#### Proxy headers

```toml
proxy_headers = { "Connection" = "upgrade" }
```

---

### Routing Rules

#### Redirects

```toml
redirect_rules = [
  { pattern = "example.com", new = "new-example.com" }
]
```

#### Rewrites

```toml
rewrite_rules = [
  { pattern = "path", new = "newpath" }
]
```

---

### IP Rules

```toml
ip_rules = [
  { source = "Direct", subnet = "192.168.0.0/21", action = "Allow" },
  { source = "Direct", subnet = "0.0.0.0/0", action = "Deny" }
]
```

* `source`: `Direct` or `Forwarded`
* `action`: `Allow` or `Deny`
* Evaluated in order

---

## Monitoring (Optional)

```toml
[monitors.test]
suspend_timeout = 300
```

```toml
[monitors.test.commands]
check_command = "ping ..."
wake_command = "wakeonlan ..."
suspend_command = "ssh ... suspend"
status_command = "ssh ..."
```

* Automatically suspends inactive upstream machines
* Wakes them on incoming requests
* Accessible via control interface

---

---

## Notes

* TOML tables are used for complex structures like headers
* Inline tables are supported but limited to single-line definitions
* `HashSet` fields are represented as TOML arrays

---
