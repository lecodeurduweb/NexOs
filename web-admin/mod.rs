//! NexOS Authenticated HTTP/1.1 (:80) & TLS 1.3 HTTPS (:443) Web Admin Server.
//!
//! Exposes live kernel telemetry, scheduler tasks, VFS storage, network stats,
//! RBAC user management, service lifecycle control, and AI Core control endpoints.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arch::smp;
use crate::arch::timer;
use crate::drivers::dtb;
use crate::filesystem::vfs;
use crate::klog;
use crate::log::{self, LogLevel};
use crate::memory::{heap, phys};
use crate::network::{self, tcp::TcpState, tls::TlsServerConn};
use crate::scheduler;
use crate::security::{
    self, AuthSession, Role, SecurityError, PERM_AI_ADMIN, PERM_MANAGE_SERVICES,
    PERM_READ_METRICS, PERM_WRITE_VFS,
};
use crate::services::{self, RestartPolicy};

pub fn start() {
    if let Err(e) = services::register_daemon(
        "web-admin",
        "Authenticated HTTP/1.1 (:80) & HTTPS TLS 1.3 (:443) Admin API",
        Some("net-stack"),
        145,
        RestartPolicy::Always,
        0,
        web_admin_worker,
        0,
    ) {
        klog!(LogLevel::Error, "web", "Failed to start web-admin: {}", e);
    }
}

fn web_admin_worker(_: usize) -> ! {
    let http_listener = match network::tcp_listen(80) {
        Some(id) => id,
        None => {
            klog!(LogLevel::Error, "web", "Failed to bind TCP :80");
            scheduler::exit_current();
        }
    };
    let https_listener = network::tcp_listen(443);
    klog!(LogLevel::Info, "web", "HTTP/1.1 Admin server listening on TCP :80");
    if https_listener.is_some() {
        klog!(
            LogLevel::Info,
            "web",
            "HTTPS TLS 1.3 Admin server listening on TCP :443 (TLS_CHACHA20_POLY1305_SHA256 / Ed25519)"
        );
    }

    loop {
        if let Some(sock) = network::tcp_accept(http_listener) {
            handle_http_connection(sock);
        }
        if let Some(hl) = https_listener {
            if let Some(tls_sock) = network::tcp_accept(hl) {
                handle_https_connection(tls_sock);
            }
        }
        services::heartbeat("web-admin");
        scheduler::sleep_ms(10);
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            c => out.push(c),
        }
    }
    out
}

fn url_decode_param(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut raw = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            let val = ((hi << 4) | lo) as u8;
            if val == 0 || val < 0x20 {
                return None;
            }
            raw.push(val);
            i += 3;
        } else if bytes[i] == b'+' {
            raw.push(b' ');
            i += 1;
        } else {
            if bytes[i] == 0 || bytes[i] < 0x20 {
                return None;
            }
            raw.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(raw).ok()
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<String> {
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == key {
                return url_decode_param(v);
            }
        }
    }
    None
}

fn parse_content_length(hdr_str: &str) -> Result<usize, ()> {
    for line in hdr_str.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                return v.trim().parse::<usize>().map_err(|_| ());
            }
        }
    }
    Ok(0)
}

fn handle_http_connection(sock: usize) {
    let mut req_buf = alloc::vec![0u8; 4096];
    let mut total = 0usize;
    let mut hdr_end: Option<usize> = None;

    for _ in 0..35 {
        let n = network::tcp_recv(sock, &mut req_buf[total..]);
        if n > 0 {
            total += n;
            if hdr_end.is_none() {
                if let Some(pos) = req_buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                    hdr_end = Some(pos);
                    if pos >= 2048 {
                        break;
                    }
                    if let Ok(hdr_str) = core::str::from_utf8(&req_buf[..pos]) {
                        if let Ok(cl) = parse_content_length(hdr_str) {
                            if pos + 4 + cl <= total {
                                break;
                            }
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            } else if let Some(pos) = hdr_end {
                if let Ok(hdr_str) = core::str::from_utf8(&req_buf[..pos]) {
                    if let Ok(cl) = parse_content_length(hdr_str) {
                        if pos + 4 + cl <= total {
                            break;
                        }
                    }
                }
            }
            if total >= req_buf.len() {
                break;
            }
        }
        if matches!(
            network::tcp_state(sock),
            None | Some(TcpState::Closed | TcpState::CloseWait)
        ) && total > 0
        {
            break;
        }
        scheduler::sleep_ms(10);
    }

    if total > 0 {
        let resp = process_raw_http(&req_buf[..total], hdr_end, false);
        network::tcp_send(sock, &resp);
        scheduler::sleep_ms(if resp.len() > 4096 { 40 } else { 20 });
    }
    network::tcp_close(sock);
}

fn handle_https_connection(sock: usize) {
    let Some(mut tls) = TlsServerConn::handshake_accept(sock) else {
        network::tcp_close(sock);
        return;
    };

    let mut req_buf = Vec::new();
    let mut hdr_end: Option<usize> = None;

    for _ in 0..8 {
        let Some(chunk) = tls.read_app_data(350) else {
            break;
        };
        req_buf.extend_from_slice(&chunk);
        if hdr_end.is_none() {
            if let Some(pos) = req_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                hdr_end = Some(pos);
                if pos >= 2048 || req_buf.len() > 8192 {
                    break;
                }
                if let Ok(hdr_str) = core::str::from_utf8(&req_buf[..pos]) {
                    if let Ok(cl) = parse_content_length(hdr_str) {
                        if pos + 4 + cl <= req_buf.len() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            } else if req_buf.len() >= 2048 {
                break;
            }
        } else if let Some(pos) = hdr_end {
            if let Ok(hdr_str) = core::str::from_utf8(&req_buf[..pos]) {
                if let Ok(cl) = parse_content_length(hdr_str) {
                    if pos + 4 + cl <= req_buf.len() {
                        break;
                    }
                }
            }
        }
    }

    if !req_buf.is_empty() {
        let resp = process_raw_http(&req_buf, hdr_end, true);
        tls.write_app_data(&resp);
        scheduler::sleep_ms(if resp.len() > 4096 { 40 } else { 15 });
    }
    tls.close();
}

fn process_raw_http(buf: &[u8], hdr_end: Option<usize>, is_tls: bool) -> Vec<u8> {
    let Some(pos) = hdr_end else {
        return if buf.len() >= 2048 {
            http_response(
                "413 Payload Too Large",
                "application/json",
                None,
                b"{\"error\":\"request_too_large\"}\n",
            )
        } else {
            http_response(
                "400 Bad Request",
                "application/json",
                None,
                b"{\"error\":\"incomplete_request\"}\n",
            )
        };
    };

    if pos >= 2048 {
        return http_response(
            "413 Payload Too Large",
            "application/json",
            None,
            b"{\"error\":\"request_too_large\"}\n",
        );
    }

    let Ok(hdr_str) = core::str::from_utf8(&buf[..pos]) else {
        return http_response(
            "400 Bad Request",
            "application/json",
            None,
            b"{\"error\":\"invalid_utf8\"}\n",
        );
    };
    let body = &buf[pos + 4..];
    dispatch_http_request(hdr_str, body, is_tls)
}

fn extract_json_str(body_str: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let idx = body_str.find(&needle)?;
    let rest = &body_str[idx + needle.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    if !after.starts_with('"') {
        return None;
    }
    let mut out = String::new();
    let mut esc = false;
    for ch in after[1..].chars() {
        if esc {
            match ch {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                c => out.push(c),
            }
            esc = false;
        } else if ch == '\\' {
            esc = true;
        } else if ch == '"' {
            return Some(out);
        } else {
            out.push(ch);
        }
    }
    None
}

fn dispatch_http_request(hdr_str: &str, body_bytes: &[u8], is_tls: bool) -> Vec<u8> {
    let mut lines = hdr_str.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let Some(method) = parts.next() else {
        return http_response(
            "400 Bad Request",
            "application/json",
            None,
            b"{\"error\":\"bad_request_line\"}\n",
        );
    };
    let Some(full_path) = parts.next() else {
        return http_response(
            "400 Bad Request",
            "application/json",
            None,
            b"{\"error\":\"missing_target\"}\n",
        );
    };
    let Some(version) = parts.next() else {
        return http_response(
            "400 Bad Request",
            "application/json",
            None,
            b"{\"error\":\"missing_http_version\"}\n",
        );
    };
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return http_response(
            "400 Bad Request",
            "application/json",
            None,
            b"{\"error\":\"unsupported_http_version\"}\n",
        );
    }
    let (path, query) = full_path.split_once('?').unwrap_or((full_path, ""));

    let mut auth_header: Option<&str> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            return http_response(
                "400 Bad Request",
                "application/json",
                None,
                b"{\"error\":\"malformed_header\"}\n",
            );
        };
        if k.eq_ignore_ascii_case("authorization") {
            auth_header = Some(v.trim());
        } else if k.eq_ignore_ascii_case("content-length") {
            match v.trim().parse::<usize>() {
                Ok(len) if len <= 2048 => {}
                Ok(_) => {
                    return http_response(
                        "413 Payload Too Large",
                        "application/json",
                        None,
                        b"{\"error\":\"content_too_large\"}\n",
                    );
                }
                Err(_) => {
                    return http_response(
                        "400 Bad Request",
                        "application/json",
                        None,
                        b"{\"error\":\"invalid_content_length\"}\n",
                    );
                }
            }
        }
    }

    let body_str = core::str::from_utf8(body_bytes).unwrap_or("");

    // Public bootstrap & UI routes (zero kernel telemetry exposed without authentication)
    match (method, path) {
        ("GET", "/") => {
            return http_response("200 OK", "text/html; charset=utf-8", None, DASHBOARD_HTML);
        }
        ("GET", "/api/v1/setup/status") => {
            let body = format!(
                "{{\"needs_setup\":{},\"csprng_seeded\":{},\"csprng_source\":\"{}\"}}\n",
                security::needs_setup(),
                security::csprng::is_seeded(),
                security::csprng::source_name()
            );
            return http_response("200 OK", "application/json", None, body.as_bytes());
        }
        ("POST", "/api/v1/setup") => {
            if !security::needs_setup() {
                return http_response(
                    "409 Conflict",
                    "application/json",
                    None,
                    b"{\"error\":\"setup_locked\"}\n",
                );
            }
            let tok = query_param(query, "token")
                .or_else(|| extract_json_str(body_str, "token"))
                .or_else(|| extract_json_str(body_str, "setup_token"));
            let uname = query_param(query, "username")
                .or_else(|| query_param(query, "user"))
                .or_else(|| extract_json_str(body_str, "username"))
                .or_else(|| extract_json_str(body_str, "user"));
            let pass = query_param(query, "password")
                .or_else(|| query_param(query, "pass"))
                .or_else(|| extract_json_str(body_str, "password"))
                .or_else(|| extract_json_str(body_str, "pass"));
            let (Some(t), Some(u), Some(p)) = (tok, uname, pass) else {
                return http_response(
                    "400 Bad Request",
                    "application/json",
                    None,
                    b"{\"error\":\"missing_token_username_or_password\"}\n",
                );
            };
            return match security::complete_initial_setup_with_token(&t, &u, &p) {
                Ok(()) => {
                    let body = format!(
                        "{{\"status\":\"setup_complete\",\"username\":\"{}\",\"role\":\"admin\"}}\n",
                        json_escape(&u)
                    );
                    http_response("201 Created", "application/json", None, body.as_bytes())
                }
                Err(SecurityError::AlreadyExists) => http_response(
                    "409 Conflict",
                    "application/json",
                    None,
                    b"{\"error\":\"setup_locked\"}\n",
                ),
                Err(SecurityError::InvalidInput) => http_response(
                    "400 Bad Request",
                    "application/json",
                    None,
                    b"{\"error\":\"invalid_username_or_password\"}\n",
                ),
                Err(_) => http_response(
                    "403 Forbidden",
                    "application/json",
                    None,
                    b"{\"error\":\"invalid_setup_token\"}\n",
                ),
            };
        }
        (_, "/api/v1/setup/status") => {
            return http_response(
                "405 Method Not Allowed",
                "application/json",
                Some("Allow: GET\r\n"),
                b"{\"error\":\"method_not_allowed\"}\n",
            );
        }
        (_, "/api/v1/setup") => {
            return http_response(
                "405 Method Not Allowed",
                "application/json",
                Some("Allow: POST\r\n"),
                b"{\"error\":\"method_not_allowed\"}\n",
            );
        }
        _ => {}
    }

    let session: AuthSession = match auth_header.map(security::authenticate_http_header) {
        Some(Ok(s)) => s,
        Some(Err(SecurityError::AccountLocked)) => {
            return http_response(
                "429 Too Many Requests",
                "application/json",
                Some("Retry-After: 2\r\n"),
                b"{\"error\":\"account_locked\"}\n",
            );
        }
        Some(Err(_)) => {
            security::record_http_auth_fail("invalid_authorization");
            return http_response(
                "401 Unauthorized",
                "application/json",
                Some("WWW-Authenticate: Basic realm=\"NexOS Admin\"\r\n"),
                b"{\"error\":\"unauthorized\"}\n",
            );
        }
        None => {
            security::record_http_auth_fail("missing_authorization");
            return http_response(
                "401 Unauthorized",
                "application/json",
                Some("WWW-Authenticate: Basic realm=\"NexOS Admin\"\r\n"),
                b"{\"error\":\"unauthorized\"}\n",
            );
        }
    };

    if security::authorize(&session, PERM_READ_METRICS, "http_read").is_err() {
        return http_response(
            "403 Forbidden",
            "application/json",
            None,
            b"{\"error\":\"forbidden\"}\n",
        );
    }

    match (method, path) {
        // --------------------------------------------------------------------
        // Legacy / Stage 13 Endpoints (preserved verbatim for backward compat)
        // --------------------------------------------------------------------
        ("POST", "/api/login") => {
            let body = format!(
                "{{\"username\":\"{}\",\"role\":\"{}\",\"token\":\"{}\",\"tls\":{}}}\n",
                json_escape(&session.username),
                session.role.as_str(),
                json_escape(&session.token),
                is_tls
            );
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("GET", "/api/metrics") | ("GET", "/api/v1/system") => {
            let ps = phys::stats();
            let hs = heap::stats();
            let ns = network::stats();
            let tasks = scheduler::snapshot();
            let svcs = services::snapshot();
            let dtb_info = dtb::cached();
            let dtb_model = dtb_info.as_ref().map(|d| d.model_str()).unwrap_or("unknown");
            let total_cpus = dtb_info.as_ref().map(|d| d.cpu_count.max(1)).unwrap_or(1);
            let cs = vfs::cache_stats();
            let body = format!(
                concat!(
                    "{{\"board\":\"{}\",\"dtb_model\":\"{}\",\"uptime_ms\":{},\"ticks\":{},\"pa_bits\":{},",
                    "\"online_cpus\":{},\"total_cpus\":{},\"tls\":{},",
                    "\"ram_total_mib\":{},\"ram_free_mib\":{},\"dma32_free_pages\":{},",
                    "\"heap_used_bytes\":{},\"heap_mapped_bytes\":{},\"heap_active_allocs\":{},",
                    "\"cache_hits\":{},\"cache_misses\":{},\"disk_mounted\":{},",
                    "\"net_ip\":\"{}\",\"net_ipv6\":\"{}\",\"net_rx_packets\":{},\"net_tx_packets\":{},",
                    "\"tasks_total\":{},\"ctx_switches\":{},\"services_total\":{},\"auth_user\":\"{}\",\"auth_role\":\"{}\"}}\n"
                ),
                json_escape(crate::arch::boards::active::BOARD_NAME),
                json_escape(dtb_model),
                timer::uptime_ms(),
                timer::ticks(),
                ps.pa_bits,
                smp::online_cpus(),
                total_cpus,
                is_tls,
                (ps.total_frames * phys::PAGE_SIZE) / (1024 * 1024),
                (ps.free_frames * phys::PAGE_SIZE) / (1024 * 1024),
                ps.dma32_free_frames,
                hs.used_bytes,
                hs.mapped_bytes,
                hs.active_allocs,
                cs.map(|c| c.hits).unwrap_or(0),
                cs.map(|c| c.misses).unwrap_or(0),
                vfs::is_disk_mounted(),
                ns.ip,
                ns.link_local_ipv6,
                ns.rx_packets,
                ns.tx_packets,
                tasks.len(),
                scheduler::total_switches(),
                svcs.len(),
                json_escape(&session.username),
                session.role.as_str()
            );
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("GET", "/api/services") | ("GET", "/api/v1/services") => {
            let svcs = services::snapshot();
            let mut body = String::from("{\"services\":[");
            for (i, s) in svcs.iter().enumerate() {
                if i > 0 {
                    body.push(',');
                }
                body.push_str(&format!(
                    "{{\"name\":\"{}\",\"description\":\"{}\",\"state\":\"{:?}\",\"restarts\":{},\"autostart\":{},\"pid\":{}}}",
                    json_escape(&s.name),
                    json_escape(&s.description),
                    s.state,
                    s.restarts,
                    s.autostart,
                    s.task_id.map(|p| format!("{}", p)).unwrap_or_else(|| String::from("null"))
                ));
            }
            body.push_str("]}\n");
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("GET", "/api/logs") => {
            let logs = log::format_recent(25);
            http_response("200 OK", "text/plain; charset=utf-8", None, logs.as_bytes())
        }
        ("POST", "/api/services/restart")
        | ("POST", "/api/v1/services/restart")
        | ("POST", "/api/v1/services/start")
        | ("POST", "/api/v1/services/stop") => {
            if security::authorize(&session, PERM_MANAGE_SERVICES, "web_ctrl_service")
                == Err(SecurityError::PermissionDenied)
            {
                return http_response(
                    "403 Forbidden",
                    "application/json",
                    None,
                    b"{\"error\":\"permission_denied\",\"required\":\"PERM_MANAGE_SERVICES\"}\n",
                );
            }
            let Some(svc_name) = query_param(query, "name").or_else(|| extract_json_str(body_str, "name")) else {
                return http_response(
                    "400 Bad Request",
                    "application/json",
                    None,
                    b"{\"error\":\"invalid_service_name\"}\n",
                );
            };
            if svc_name.is_empty() || svc_name.len() > 48 {
                return http_response(
                    "400 Bad Request",
                    "application/json",
                    None,
                    b"{\"error\":\"invalid_service_name\"}\n",
                );
            }
            let action_res: Result<Option<u64>, &'static str> = if path.ends_with("/start") {
                services::start_service(&svc_name).map(Some)
            } else if path.ends_with("/stop") {
                services::stop_service(&svc_name).map(|()| None)
            } else {
                services::restart_service(&svc_name).map(Some)
            };
            match action_res {
                Ok(Some(new_pid)) => {
                    let body = format!(
                        "{{\"restarted\":\"{}\",\"service\":\"{}\",\"new_pid\":{}}}\n",
                        json_escape(&svc_name),
                        json_escape(&svc_name),
                        new_pid
                    );
                    http_response("200 OK", "application/json", None, body.as_bytes())
                }
                Ok(None) => {
                    let body = format!("{{\"stopped\":\"{}\"}}\n", json_escape(&svc_name));
                    http_response("200 OK", "application/json", None, body.as_bytes())
                }
                Err(e) => {
                    let status = if e == "Service not found" {
                        "404 Not Found"
                    } else {
                        "409 Conflict"
                    };
                    let body = format!("{{\"error\":\"{}\"}}\n", json_escape(e));
                    http_response(status, "application/json", None, body.as_bytes())
                }
            }
        }

        // --------------------------------------------------------------------
        // /api/v1/* Extended Management API
        // --------------------------------------------------------------------
        ("GET", "/api/v1/tasks") => {
            let tasks = scheduler::snapshot();
            let mut body = String::from("{\"tasks\":[");
            for (i, t) in tasks.iter().enumerate() {
                if i > 0 {
                    body.push(',');
                }
                body.push_str(&format!(
                    "{{\"id\":{},\"parent_id\":{},\"name\":\"{}\",\"prio\":{},\"el\":\"{}\",\"state\":\"{:?}\",\"cpu\":{},\"ticks\":{},\"switches\":{}}}",
                    t.id,
                    t.parent_id,
                    json_escape(t.name_str()),
                    t.priority,
                    if t.is_user { "EL0" } else { "EL1" },
                    t.state,
                    t.last_cpu,
                    t.ticks_run,
                    t.switches
                ));
            }
            body.push_str("]}\n");
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("GET", "/api/v1/storage") => {
            let req_path = query_param(query, "path")
                .unwrap_or_else(|| String::from(if vfs::is_disk_mounted() { "/disk" } else { "/ram" }));
            let cs = vfs::cache_stats();
            let entries = vfs::list_dir(&req_path).unwrap_or_default();
            let mut body = format!(
                "{{\"disk_mounted\":{},\"path\":\"{}\",\"cache_hits\":{},\"cache_misses\":{},\"cache_dirty_writes\":{},\"cache_flushes\":{},\"entries\":[",
                vfs::is_disk_mounted(),
                json_escape(&req_path),
                cs.map(|c| c.hits).unwrap_or(0),
                cs.map(|c| c.misses).unwrap_or(0),
                cs.map(|c| c.dirty_writes).unwrap_or(0),
                cs.map(|c| c.flushes).unwrap_or(0),
            );
            for (i, e) in entries.iter().enumerate() {
                if i > 0 {
                    body.push(',');
                }
                body.push_str(&format!(
                    "{{\"name\":\"{}\",\"is_dir\":{},\"size\":{}}}",
                    json_escape(&e.name),
                    e.is_dir,
                    e.size
                ));
            }
            body.push_str("]}\n");
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("GET", "/api/v1/files") => {
            let Some(fpath) = query_param(query, "path") else {
                return http_response(
                    "400 Bad Request",
                    "application/json",
                    None,
                    b"{\"error\":\"missing_path\"}\n",
                );
            };
            match vfs::read_file(&fpath) {
                Ok(data) => http_response("200 OK", "application/octet-stream", None, &data),
                Err(e) => {
                    let status = match e {
                        vfs::VfsError::NotFound => "404 Not Found",
                        _ => "400 Bad Request",
                    };
                    let body = format!("{{\"error\":\"{:?}\"}}\n", e);
                    http_response(status, "application/json", None, body.as_bytes())
                }
            }
        }
        ("POST", "/api/v1/files") => {
            if security::authorize(&session, PERM_WRITE_VFS, "web_write_file")
                == Err(SecurityError::PermissionDenied)
            {
                return http_response(
                    "403 Forbidden",
                    "application/json",
                    None,
                    b"{\"error\":\"permission_denied\",\"required\":\"PERM_WRITE_VFS\"}\n",
                );
            }
            let Some(fpath) = query_param(query, "path") else {
                return http_response(
                    "400 Bad Request",
                    "application/json",
                    None,
                    b"{\"error\":\"missing_path\"}\n",
                );
            };
            match vfs::write_file(&fpath, body_bytes) {
                Ok(()) => {
                    let _ = vfs::sync();
                    let body = format!(
                        "{{\"written\":\"{}\",\"bytes\":{}}}\n",
                        json_escape(&fpath),
                        body_bytes.len()
                    );
                    http_response("200 OK", "application/json", None, body.as_bytes())
                }
                Err(e) => {
                    let body = format!("{{\"error\":\"{:?}\"}}\n", e);
                    http_response("400 Bad Request", "application/json", None, body.as_bytes())
                }
            }
        }
        ("GET", "/api/v1/network") => {
            let ns = network::stats();
            let body = format!(
                "{{\"initialized\":{},\"mac\":\"{}\",\"ip\":\"{}\",\"ipv6\":\"{}\",\"mask\":\"{}\",\"gateway\":\"{}\",\"dns\":\"{}\",\"config_source\":\"{:?}\",\"rx_packets\":{},\"tx_packets\":{},\"rx_bytes\":{},\"tx_bytes\":{}}}\n",
                ns.initialized,
                ns.mac,
                ns.ip,
                ns.link_local_ipv6,
                ns.mask,
                ns.gateway,
                ns.dns,
                ns.config_source,
                ns.rx_packets,
                ns.tx_packets,
                ns.rx_bytes,
                ns.tx_bytes
            );
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("GET", "/api/v1/users") => {
            if security::authorize(&session, PERM_AI_ADMIN, "web_list_users")
                == Err(SecurityError::PermissionDenied)
            {
                return http_response(
                    "403 Forbidden",
                    "application/json",
                    None,
                    b"{\"error\":\"permission_denied\"}\n",
                );
            }
            let users = security::list_users();
            let mut body = String::from("{\"users\":[");
            for (i, u) in users.iter().enumerate() {
                if i > 0 {
                    body.push(',');
                }
                body.push_str(&format!(
                    "{{\"username\":\"{}\",\"role\":\"{}\",\"failed_attempts\":{},\"locked\":{}}}",
                    json_escape(&u.username),
                    u.role.as_str(),
                    u.failed_attempts,
                    u.locked
                ));
            }
            body.push_str("]}\n");
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("POST", "/api/v1/users") => {
            if security::authorize(&session, PERM_AI_ADMIN, "web_create_user")
                == Err(SecurityError::PermissionDenied)
            {
                return http_response(
                    "403 Forbidden",
                    "application/json",
                    None,
                    b"{\"error\":\"permission_denied\"}\n",
                );
            }
            let uname = query_param(query, "user").or_else(|| extract_json_str(body_str, "username"));
            let pass = query_param(query, "pass").or_else(|| extract_json_str(body_str, "password"));
            let role_str = query_param(query, "role")
                .or_else(|| extract_json_str(body_str, "role"))
                .unwrap_or_else(|| String::from("viewer"));
            let role = match role_str.as_str() {
                "admin" => Role::Admin,
                "operator" => Role::Operator,
                "ai-agent" => Role::AiAgent,
                _ => Role::Viewer,
            };
            let (Some(u), Some(p)) = (uname, pass) else {
                return http_response(
                    "400 Bad Request",
                    "application/json",
                    None,
                    b"{\"error\":\"missing_username_or_password\"}\n",
                );
            };
            match security::create_user(&u, &p, role) {
                Ok(()) => {
                    let body = format!(
                        "{{\"created\":\"{}\",\"role\":\"{}\"}}\n",
                        json_escape(&u),
                        role.as_str()
                    );
                    http_response("201 Created", "application/json", None, body.as_bytes())
                }
                Err(e) => {
                    let body = format!("{{\"error\":\"{:?}\"}}\n", e);
                    http_response("400 Bad Request", "application/json", None, body.as_bytes())
                }
            }
        }
        ("DELETE", "/api/v1/users") => {
            if security::authorize(&session, PERM_AI_ADMIN, "web_delete_user")
                == Err(SecurityError::PermissionDenied)
            {
                return http_response(
                    "403 Forbidden",
                    "application/json",
                    None,
                    b"{\"error\":\"permission_denied\"}\n",
                );
            }
            let Some(u) = query_param(query, "user") else {
                return http_response(
                    "400 Bad Request",
                    "application/json",
                    None,
                    b"{\"error\":\"missing_user\"}\n",
                );
            };
            match security::delete_user(&u) {
                Ok(()) => {
                    let body = format!("{{\"deleted\":\"{}\"}}\n", json_escape(&u));
                    http_response("200 OK", "application/json", None, body.as_bytes())
                }
                Err(e) => {
                    let status = match e {
                        SecurityError::NotFound => "404 Not Found",
                        SecurityError::PermissionDenied => "403 Forbidden",
                        _ => "400 Bad Request",
                    };
                    let body = format!("{{\"error\":\"{:?}\"}}\n", e);
                    http_response(status, "application/json", None, body.as_bytes())
                }
            }
        }
        ("GET", "/api/v1/audit") => {
            if security::authorize(&session, PERM_AI_ADMIN, "web_read_audit")
                == Err(SecurityError::PermissionDenied)
            {
                return http_response(
                    "403 Forbidden",
                    "application/json",
                    None,
                    b"{\"error\":\"permission_denied\"}\n",
                );
            }
            let events = security::recent_audit_events();
            let mut body = String::from("{\"events\":[");
            for (i, ev) in events.iter().enumerate() {
                if i > 0 {
                    body.push(',');
                }
                body.push_str(&format!("\"{}\"", json_escape(ev)));
            }
            body.push_str("]}\n");
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("GET", "/api/v1/ai") | ("GET", "/api/v1/ai/status") => {
            let st = crate::ai_core::status();
            let body = format!(
                "{{\"initialized\":{},\"neon_verified\":{},\"model_loaded\":{},\"model_path\":\"{}\",\"vocab_size\":{},\"dim\":{},\"n_layers\":{},\"n_heads\":{},\"max_seq\":{},\"model_ram_bytes\":{},\"active_budget_bytes\":{},\"last_tokens_per_sec_x100\":{},\"total_inferences\":{}}}\n",
                st.initialized,
                st.neon_verified,
                st.model_loaded,
                json_escape(&st.model_path),
                st.vocab_size,
                st.dim,
                st.n_layers,
                st.n_heads,
                st.max_seq,
                st.model_ram_bytes,
                st.active_budget_bytes,
                st.last_tokens_per_sec_x100,
                st.total_inferences
            );
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("GET", "/api/v1/ai/agents") => {
            let body = crate::ai_core::agents::agents_status_json();
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("GET", "/api/v1/ai/history") => {
            let entries = crate::ai_core::agents::history();
            let mut body = String::from("{\"history\":[");
            for (i, entry) in entries.iter().enumerate() {
                if i > 0 {
                    body.push(',');
                }
                body.push_str(&format!(
                    "{{\"agent\":\"{}\",\"summary\":\"{}\"}}",
                    json_escape(entry.agent),
                    json_escape(&entry.summary)
                ));
            }
            body.push_str("]}\n");
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("GET", "/api/v1/ai/memory") => {
            let entries = crate::ai_core::memory::entries();
            let mut body = String::from("{\"memory\":[");
            for (i, entry) in entries.iter().enumerate() {
                if i > 0 { body.push(','); }
                body.push_str(&format!(
                    "{{\"kind\":\"{}\",\"agent\":\"{}\",\"text\":\"{}\"}}",
                    json_escape(&entry.kind),
                    json_escape(&entry.agent),
                    json_escape(&entry.text)
                ));
            }
            body.push_str("]}\n");
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("POST", "/api/v1/ai/repair/request") => {
            if security::authorize(&session, PERM_AI_ADMIN, "web_ai_repair_request")
                == Err(SecurityError::PermissionDenied)
            {
                return http_response("403 Forbidden", "application/json", None,
                    b"{\"error\":\"permission_denied\",\"required\":\"PERM_AI_ADMIN\"}\n");
            }
            let service = query_param(query, "service")
                .or_else(|| extract_json_str(body_str, "service"))
                .unwrap_or_default();
            match crate::ai_core::agents::request_service_restart(&service) {
                Ok(p) => {
                    let body = format!(
                        "{{\"approval_required\":true,\"approval_id\":{},\"approval_token\":\"{}\",\"action\":\"{}\",\"target\":\"{}\",\"expires_ms\":{}}}\n",
                        p.id, json_escape(&p.approval_token), json_escape(&p.action),
                        json_escape(&p.target), p.expires_ms
                    );
                    http_response("202 Accepted", "application/json", None, body.as_bytes())
                }
                Err(e) => http_response("400 Bad Request", "application/json", None,
                    format!("{{\"error\":\"{}\"}}\n", json_escape(e)).as_bytes())
            }
        }
        ("POST", "/api/v1/ai/repair/approve") => {
            if security::authorize(&session, PERM_AI_ADMIN, "web_ai_repair_approve")
                == Err(SecurityError::PermissionDenied)
            {
                return http_response("403 Forbidden", "application/json", None,
                    b"{\"error\":\"permission_denied\",\"required\":\"PERM_AI_ADMIN\"}\n");
            }
            let id = query_param(query, "id").and_then(|v| v.parse::<u64>().ok())
                .or_else(|| extract_json_str(body_str, "id").and_then(|v| v.parse::<u64>().ok()));
            let token = query_param(query, "token")
                .or_else(|| extract_json_str(body_str, "token"));
            let (Some(id), Some(token)) = (id, token) else {
                return http_response("400 Bad Request", "application/json", None,
                    b"{\"error\":\"missing_approval_id_or_token\"}\n");
            };
            match crate::ai_core::agents::approve_and_restart(id, &token) {
                Ok((pid, target)) => {
                    let verified = crate::ai_core::agents::verify_repair(&target);
                    let body = format!(
                        "{{\"restarted_pid\":{},\"verified\":{}}}\n",
                        pid, verified
                    );
                    http_response("200 OK", "application/json", None, body.as_bytes())
                }
                Err(e) => http_response("400 Bad Request", "application/json", None,
                    format!("{{\"error\":\"{}\"}}\n", json_escape(e)).as_bytes())
            }
        }
        ("POST", "/api/v1/ai/chat") => {
            let prompt = query_param(query, "prompt")
                .or_else(|| extract_json_str(body_str, "prompt"))
                .unwrap_or_default();
            if prompt.is_empty() || prompt.len() > 1024 {
                return http_response(
                    "400 Bad Request",
                    "application/json",
                    None,
                    b"{\"error\":\"invalid_prompt\"}\n",
                );
            }
            let observation = crate::ai_core::agents::diagnose(&prompt);
            let body = format!(
                "{{\"mode\":\"deterministic_diagnostic\",\"agent\":\"{}\",\"observation\":\"{}\",\"prompt\":\"{}\",\"llm_required_for_natural_language\":true}}\n",
                json_escape(observation.agent),
                json_escape(&observation.summary),
                json_escape(&prompt)
            );
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("POST", "/api/v1/ai/diagnose") => {
            let prompt = query_param(query, "prompt")
                .or_else(|| extract_json_str(body_str, "prompt"))
                .unwrap_or_else(|| String::from("diagnose system"));
            let observation = crate::ai_core::agents::diagnose(&prompt);
            let body = format!(
                "{{\"agent\":\"{}\",\"observation\":\"{}\",\"sensitive_action\":\"none\",\"approval_required\":false}}\n",
                json_escape(observation.agent),
                json_escape(&observation.summary)
            );
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("POST", "/api/v1/ai/load") => {
            if security::authorize(&session, PERM_AI_ADMIN, "web_ai_load")
                == Err(SecurityError::PermissionDenied)
            {
                return http_response(
                    "403 Forbidden",
                    "application/json",
                    None,
                    b"{\"error\":\"permission_denied\",\"required\":\"PERM_AI_ADMIN\"}\n",
                );
            }
            let path_arg = query_param(query, "path")
                .or_else(|| extract_json_str(body_str, "path"))
                .unwrap_or_else(|| String::from("/disk/MODEL.NXM"));
            match crate::ai_core::load_from_vfs(&path_arg) {
                Ok(info) => {
                    let body = format!("{{\"loaded\":true,\"info\":\"{}\"}}\n", json_escape(&info));
                    http_response("200 OK", "application/json", None, body.as_bytes())
                }
                Err(e) => {
                    let body = format!("{{\"loaded\":false,\"error\":\"{}\"}}\n", json_escape(&e));
                    http_response("400 Bad Request", "application/json", None, body.as_bytes())
                }
            }
        }
        ("POST", "/api/v1/ai/unload") => {
            if security::authorize(&session, PERM_AI_ADMIN, "web_ai_unload")
                == Err(SecurityError::PermissionDenied)
            {
                return http_response(
                    "403 Forbidden",
                    "application/json",
                    None,
                    b"{\"error\":\"permission_denied\",\"required\":\"PERM_AI_ADMIN\"}\n",
                );
            }
            let had = crate::ai_core::unload();
            let body = format!("{{\"unloaded\":true,\"was_loaded\":{}}}\n", had);
            http_response("200 OK", "application/json", None, body.as_bytes())
        }
        ("POST", "/api/v1/ai/infer") => {
            let prompt = query_param(query, "prompt")
                .or_else(|| extract_json_str(body_str, "prompt"))
                .unwrap_or_else(|| String::from("nexos status"));
            let max_tokens = query_param(query, "max_tokens")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(24)
                .clamp(1, 64);
            let temp_x100 = query_param(query, "temp_x100")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            match crate::ai_core::infer(&prompt, max_tokens, temp_x100, 1) {
                Ok(res) => {
                    let body = format!(
                        "{{\"prompt\":\"{}\",\"output\":\"{}\",\"prompt_tokens\":{},\"generated_tokens\":{},\"elapsed_us\":{},\"elapsed_ms\":{},\"tokens_per_sec_x100\":{},\"aborted\":{}}}\n",
                        json_escape(&prompt),
                        json_escape(&res.output),
                        res.prompt_tokens,
                        res.generated_tokens,
                        res.elapsed_us,
                        res.elapsed_ms,
                        res.tokens_per_sec_x100,
                        res.aborted
                    );
                    http_response("200 OK", "application/json", None, body.as_bytes())
                }
                Err(e) => {
                    let body = format!("{{\"error\":\"{}\"}}\n", json_escape(e));
                    http_response("409 Conflict", "application/json", None, body.as_bytes())
                }
            }
        }
        ("POST", "/api/v1/ai/bench") => {
            let max_tokens = query_param(query, "max_tokens")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(16)
                .clamp(4, 32);
            match crate::ai_core::benchmark(max_tokens) {
                Ok(res) => {
                    let body = format!(
                        "{{\"kernel\":\"NEON_Q8_0\",\"generated_tokens\":{},\"elapsed_us\":{},\"elapsed_ms\":{},\"tokens_per_sec_x100\":{},\"output\":\"{}\"}}\n",
                        res.generated_tokens,
                        res.elapsed_us,
                        res.elapsed_ms,
                        res.tokens_per_sec_x100,
                        json_escape(&res.output)
                    );
                    http_response("200 OK", "application/json", None, body.as_bytes())
                }
                Err(e) => {
                    let body = format!("{{\"error\":\"{}\"}}\n", json_escape(e));
                    http_response("409 Conflict", "application/json", None, body.as_bytes())
                }
            }
        }
        (_, "/api/login" | "/api/services/restart" | "/api/v1/services/restart" | "/api/v1/services/start" | "/api/v1/services/stop" | "/api/v1/ai/load" | "/api/v1/ai/unload" | "/api/v1/ai/infer" | "/api/v1/ai/bench" | "/api/v1/ai/chat" | "/api/v1/ai/diagnose" | "/api/v1/ai/repair/request" | "/api/v1/ai/repair/approve") => {
            http_response(
                "405 Method Not Allowed",
                "application/json",
                Some("Allow: POST\r\n"),
                b"{\"error\":\"method_not_allowed\"}\n",
            )
        }
        (_, "/api/metrics" | "/api/services" | "/api/logs" | "/api/v1/system" | "/api/v1/tasks" | "/api/v1/storage" | "/api/v1/network" | "/api/v1/services" | "/api/v1/audit" | "/api/v1/ai" | "/api/v1/ai/status" | "/api/v1/ai/agents" | "/api/v1/ai/history" | "/api/v1/ai/memory") => {
            http_response(
                "405 Method Not Allowed",
                "application/json",
                Some("Allow: GET\r\n"),
                b"{\"error\":\"method_not_allowed\"}\n",
            )
        }
        _ => http_response(
            "404 Not Found",
            "application/json",
            None,
            b"{\"error\":\"not_found\"}\n",
        ),
    }
}

fn http_response(
    status: &str,
    content_type: &str,
    extra_hdrs: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let hdr = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
        status,
        content_type,
        body.len(),
        extra_hdrs.unwrap_or("")
    );
    let mut out = Vec::with_capacity(hdr.len() + body.len());
    out.extend_from_slice(hdr.as_bytes());
    out.extend_from_slice(body);
    out
}

const DASHBOARD_HTML: &[u8] = br#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexOS Headless Server Admin</title>
<style>
:root{--bg:#0b0f14;--card:#121922;--card2:#16202b;--bd:#233041;--fg:#e6edf3;--mut:#8b9bb0;--acc:#38bdf8;--ok:#34d399;--warn:#fbbf24;--bad:#f87171}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}
.wrap{max-width:1180px;margin:0 auto;padding:18px}
.top{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px;border-bottom:1px solid var(--bd);padding-bottom:12px;margin-bottom:16px}
.brand{font-size:18px;font-weight:700;letter-spacing:.4px}.sub{color:var(--mut);font-size:12px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:16px;margin-bottom:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin-bottom:14px}
.kpi{background:var(--card2);border:1px solid var(--bd);border-radius:8px;padding:12px}
.kpi .lbl{color:var(--mut);font-size:11px;text-transform:uppercase}.kpi .val{font-size:18px;font-weight:700;margin-top:4px}
.tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px}
.tab{background:var(--card);color:var(--mut);border:1px solid var(--bd);border-radius:6px;padding:7px 12px;cursor:pointer;font:inherit}
.tab.active{background:#1b2838;color:var(--acc);border-color:var(--acc)}
button,input,select,textarea{font:inherit;color:var(--fg);background:#0d131a;border:1px solid var(--bd);border-radius:6px;padding:7px 10px}
button{cursor:pointer;background:#192736}.btn-acc{background:#0e4a6b;border-color:var(--acc)}.btn-bad{background:#4c1d1d;border-color:var(--bad)}
button:hover{filter:brightness(1.12)}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{border-bottom:1px solid var(--bd);padding:8px 6px;text-align:left}th{color:var(--mut);font-weight:600}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px;border:1px solid var(--bd)}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.mut{color:var(--mut)}.hide{display:none}
pre{background:#090d12;border:1px solid var(--bd);border-radius:6px;padding:10px;overflow:auto;max-height:300px;margin:8px 0 0}
.auth-box{max-width:440px;margin:48px auto}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div><div class="brand">NexOS Headless Server Admin</div><div class="sub" id="hdr-sub">Standalone ARM64 Server OS Console</div></div>
    <div class="row hide" id="hdr-ctrls">
      <span class="tag" id="hdr-user">-</span>
      <button onclick="refreshAll()">Refresh</button>
      <button onclick="logout()">Sign Out</button>
    </div>
  </div>

  <div id="setup-view" class="card auth-box hide">
    <h3>First-Boot Administrator Provisioning</h3>
    <p class="mut">No administrator account exists. Enter the one-time setup token printed on the UART serial console.</p>
    <div class="row"><input id="st-tok" placeholder="UART setup token (24 hex)" style="width:100%"></div>
    <div class="row"><input id="st-user" placeholder="Admin username" value="admin" style="width:100%"></div>
    <div class="row"><input id="st-pass" type="password" placeholder="Password (min 8 chars)" style="width:100%"></div>
    <button class="btn-acc" onclick="submitSetup()" style="width:100%">Create Administrator</button>
    <div id="st-msg" class="sub" style="margin-top:8px"></div>
  </div>

  <div id="login-view" class="card auth-box hide">
    <h3>Administrator Login</h3>
    <div class="row"><input id="lg-user" placeholder="Username" style="width:100%"></div>
    <div class="row"><input id="lg-pass" type="password" placeholder="Password" style="width:100%"></div>
    <button class="btn-acc" onclick="submitLogin()" style="width:100%">Authenticate</button>
    <div id="lg-msg" class="sub" style="margin-top:8px"></div>
  </div>

  <div id="dash-view" class="hide">
    <div class="grid" id="kpis"></div>
    <div class="tabs">
      <button class="tab active" onclick="showTab('svc',this)">Services</button>
      <button class="tab" onclick="showTab('tasks',this)">Tasks</button>
      <button class="tab" onclick="showTab('vfs',this)">Storage &amp; Files</button>
      <button class="tab" onclick="showTab('net',this)">Network</button>
      <button class="tab" onclick="showTab('ai',this)">AI Core</button>
      <button class="tab" onclick="showTab('users',this)">Users &amp; Audit</button>
      <button class="tab" onclick="showTab('logs',this)">Kernel Logs</button>
    </div>

    <div id="tab-svc" class="card">
      <table><thead><tr><th>Service</th><th>State</th><th>PID</th><th>Restarts</th><th>Description</th><th>Actions</th></tr></thead><tbody id="svc-body"></tbody></table>
    </div>
    <div id="tab-tasks" class="card hide">
      <table><thead><tr><th>PID</th><th>Name</th><th>EL</th><th>Prio</th><th>State</th><th>CPU</th><th>Ticks</th><th>Switches</th></tr></thead><tbody id="task-body"></tbody></table>
    </div>
    <div id="tab-vfs" class="card hide">
      <div class="row"><input id="vfs-path" value="/disk" style="min-width:220px"><button class="btn-acc" onclick="loadVfs()">List</button><span id="vfs-stat" class="mut"></span></div>
      <table><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Action</th></tr></thead><tbody id="vfs-body"></tbody></table>
      <div class="row" style="margin-top:12px"><input id="wr-path" placeholder="/ram/note.txt" style="min-width:220px"><button onclick="writeVfs()">Write File</button></div>
      <textarea id="vfs-content" rows="4" style="width:100%" placeholder="File contents preview or editor"></textarea>
    </div>
    <div id="tab-net" class="card hide"><pre id="net-pre"></pre></div>
    <div id="tab-ai" class="card hide">
      <div class="row">
        <input id="ai-mpath" value="/disk/MODEL.NXM" style="min-width:200px">
        <button class="btn-acc" onclick="aiLoad()">Load Model</button>
        <button onclick="aiUnload()">Unload</button>
        <button onclick="aiBench()">Benchmark NEON Q8_0</button>
      </div>
      <div class="row"><input id="ai-prompt" value="nexos status" style="flex:1"><button class="btn-acc" onclick="aiInfer()">Run Inference</button></div>
      <pre id="ai-pre"></pre>
    </div>
    <div id="tab-users" class="card hide">
      <div class="row">
        <input id="u-name" placeholder="username"><input id="u-pass" type="password" placeholder="password (>=8)">
        <select id="u-role"><option>viewer</option><option>operator</option><option>ai-agent</option><option>admin</option></select>
        <button class="btn-acc" onclick="createUser()">Create User</button>
      </div>
      <table><thead><tr><th>User</th><th>Role</th><th>Fails</th><th>Locked</th><th>Action</th></tr></thead><tbody id="usr-body"></tbody></table>
      <h4>Security Audit Events</h4><pre id="audit-pre"></pre>
    </div>
    <div id="tab-logs" class="card hide"><pre id="logs-pre"></pre></div>
  </div>
</div>
<script>
const S=sessionStorage;let curTab='svc';
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function hdr(){const t=S.getItem('nx_tok');return t?{'Authorization':'Bearer '+t}:{};}
async function api(u,opt={}){opt.headers=Object.assign({},hdr(),opt.headers||{});const r=await fetch(u,opt);if(r.status===401){logout();throw new Error('401');}return r;}
async function init(){
  const r=await fetch('/api/v1/setup/status');const st=await r.json();
  if(st.needs_setup){document.getElementById('setup-view').classList.remove('hide');return;}
  if(S.getItem('nx_tok')){showDash();}else{document.getElementById('login-view').classList.remove('hide');}
}
async function submitSetup(){
  const body=JSON.stringify({token:document.getElementById('st-tok').value.trim(),username:document.getElementById('st-user').value.trim(),password:document.getElementById('st-pass').value});
  const r=await fetch('/api/v1/setup',{method:'POST',headers:{'Content-Type':'application/json'},body});
  const j=await r.json();const m=document.getElementById('st-msg');
  if(r.ok){m.textContent='Admin created. Please log in.';document.getElementById('setup-view').classList.add('hide');document.getElementById('login-view').classList.remove('hide');}
  else{m.textContent='Error: '+(j.error||r.status);}
}
async function submitLogin(){
  const u=document.getElementById('lg-user').value.trim(),p=document.getElementById('lg-pass').value;
  const r=await fetch('/api/login',{method:'POST',headers:{'Authorization':'Basic '+btoa(u+':'+p)}});
  const m=document.getElementById('lg-msg');
  if(r.ok){const j=await r.json();S.setItem('nx_tok',j.token);S.setItem('nx_usr',j.username+' ('+j.role+')');showDash();}
  else{m.textContent='Authentication failed ('+r.status+')';}
}
function logout(){S.removeItem('nx_tok');S.removeItem('nx_usr');document.getElementById('dash-view').classList.add('hide');document.getElementById('hdr-ctrls').classList.add('hide');document.getElementById('login-view').classList.remove('hide');}
function showDash(){
  document.getElementById('setup-view').classList.add('hide');document.getElementById('login-view').classList.add('hide');
  document.getElementById('dash-view').classList.remove('hide');document.getElementById('hdr-ctrls').classList.remove('hide');
  document.getElementById('hdr-user').textContent=S.getItem('nx_usr')||'authenticated';
  refreshAll();setInterval(()=>{if(S.getItem('nx_tok'))refreshAll();},5000);
}
function showTab(t,btn){
  curTab=t;document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));btn.classList.add('active');
  ['svc','tasks','vfs','net','ai','users','logs'].forEach(id=>document.getElementById('tab-'+id).classList.toggle('hide',id!==t));
  refreshAll();
}
async function refreshAll(){
  if(!S.getItem('nx_tok'))return;
  const sys=await(await api('/api/v1/system')).json();
  document.getElementById('hdr-sub').textContent=sys.board+' | '+sys.dtb_model+(sys.tls?' | TLS 1.3':' | HTTP');
  document.getElementById('kpis').innerHTML=[
    ['Uptime',Math.floor(sys.uptime_ms/1000)+' s'],
    ['CPUs',sys.online_cpus+'/'+sys.total_cpus+' online'],
    ['Physical RAM',sys.ram_free_mib+'/'+sys.ram_total_mib+' MiB free'],
    ['Kernel Heap',Math.round(sys.heap_used_bytes/1024)+' / '+Math.round(sys.heap_mapped_bytes/1024)+' KiB'],
    ['Network',sys.net_ip+' (RX '+sys.net_rx_packets+' / TX '+sys.net_tx_packets+')'],
    ['Tasks / CtxSw',sys.tasks_total+' / '+sys.ctx_switches]
  ].map(k=>`<div class="kpi"><div class="lbl">${esc(k[0])}</div><div class="val">${esc(k[1])}</div></div>`).join('');
  if(curTab==='svc'){
    const d=await(await api('/api/v1/services')).json();
    document.getElementById('svc-body').innerHTML=d.services.map(s=>`<tr><td>${esc(s.name)}</td><td class="${s.state==='Running'?'ok':'warn'}">${esc(s.state)}</td><td>${s.pid??'-'}</td><td>${s.restarts}</td><td>${esc(s.description)}</td><td><button onclick="svcAct('start','${esc(s.name)}')">Start</button> <button onclick="svcAct('restart','${esc(s.name)}')">Restart</button> <button class="btn-bad" onclick="svcAct('stop','${esc(s.name)}')">Stop</button></td></tr>`).join('');
  }else if(curTab==='tasks'){
    const d=await(await api('/api/v1/tasks')).json();
    document.getElementById('task-body').innerHTML=d.tasks.map(t=>`<tr><td>${t.id}</td><td>${esc(t.name)}</td><td>${esc(t.el)}</td><td>${t.prio}</td><td>${esc(t.state)}</td><td>${t.cpu}</td><td>${t.ticks}</td><td>${t.switches}</td></tr>`).join('');
  }else if(curTab==='vfs'){await loadVfs();}
  else if(curTab==='net'){document.getElementById('net-pre').textContent=JSON.stringify(await(await api('/api/v1/network')).json(),null,2);}
  else if(curTab==='ai'){document.getElementById('ai-pre').textContent=JSON.stringify(await(await api('/api/v1/ai')).json(),null,2);}
  else if(curTab==='users'){
    const ru=await api('/api/v1/users');
    if(ru.ok){const u=await ru.json();document.getElementById('usr-body').innerHTML=u.users.map(x=>`<tr><td>${esc(x.username)}</td><td>${esc(x.role)}</td><td>${x.failed_attempts}</td><td>${x.locked}</td><td><button class="btn-bad" onclick="delUser('${esc(x.username)}')">Delete</button></td></tr>`).join('');}
    const ra=await api('/api/v1/audit');
    if(ra.ok){const a=await ra.json();document.getElementById('audit-pre').textContent=a.events.join('\n');}
  }else if(curTab==='logs'){document.getElementById('logs-pre').textContent=await(await api('/api/logs')).text();}
}
async function svcAct(op,n){await api('/api/v1/services/'+op+'?name='+encodeURIComponent(n),{method:'POST'});refreshAll();}
async function loadVfs(){
  const p=document.getElementById('vfs-path').value.trim()||'/';
  const d=await(await api('/api/v1/storage?path='+encodeURIComponent(p))).json();
  document.getElementById('vfs-stat').textContent='disk_mounted='+d.disk_mounted+' hits='+d.cache_hits+' misses='+d.cache_misses;
  const sep=p==='/'?'':p;
  document.getElementById('vfs-body').innerHTML=d.entries.map(e=>`<tr><td>${esc(e.name)}</td><td>${e.is_dir?'DIR':'FILE'}</td><td>${e.size}</td><td>${e.is_dir?`<button onclick="document.getElementById('vfs-path').value='${esc(sep+'/'+e.name)}';loadVfs()">Open</button>`:`<button onclick="readVfs('${esc(sep+'/'+e.name)}')">Read</button>`}</td></tr>`).join('');
}
async function readVfs(p){document.getElementById('wr-path').value=p;document.getElementById('vfs-content').value=await(await api('/api/v1/files?path='+encodeURIComponent(p))).text();}
async function writeVfs(){const p=document.getElementById('wr-path').value.trim();await api('/api/v1/files?path='+encodeURIComponent(p),{method:'POST',body:document.getElementById('vfs-content').value});loadVfs();}
async function aiLoad(){const p=document.getElementById('ai-mpath').value.trim();document.getElementById('ai-pre').textContent=await(await api('/api/v1/ai/load?path='+encodeURIComponent(p),{method:'POST'})).text();}
async function aiUnload(){document.getElementById('ai-pre').textContent=await(await api('/api/v1/ai/unload',{method:'POST'})).text();}
async function aiBench(){document.getElementById('ai-pre').textContent=await(await api('/api/v1/ai/bench',{method:'POST'})).text();}
async function aiInfer(){const pr=document.getElementById('ai-prompt').value;document.getElementById('ai-pre').textContent=await(await api('/api/v1/ai/infer?prompt='+encodeURIComponent(pr),{method:'POST'})).text();}
async function createUser(){
  const u=document.getElementById('u-name').value.trim(),p=document.getElementById('u-pass').value,r=document.getElementById('u-role').value;
  await api('/api/v1/users?user='+encodeURIComponent(u)+'&pass='+encodeURIComponent(p)+'&role='+encodeURIComponent(r),{method:'POST'});refreshAll();
}
async function delUser(u){await api('/api/v1/users?user='+encodeURIComponent(u),{method:'DELETE'});refreshAll();}
init();
</script>
</body>
</html>
"#;
