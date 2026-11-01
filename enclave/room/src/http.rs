//! A small HTTPS POST for the room. `wasi-http-client` writes a body in one call, and the worker
//! traps on any `blocking-write-and-flush` over 4,096 bytes, which a real prompt passes.
use darkroom_core::Error;
use wasi::http::outgoing_handler;
use wasi::http::types::{Fields, Method, OutgoingBody, OutgoingRequest, RequestOptions, Scheme};
use wasi::io::streams::StreamError;

const MAX_WRITE_BYTES: usize = 4096;
const READ_BYTES: u64 = 65536;
const CONNECT_TIMEOUT_NANOS: u64 = 15_000_000_000;

fn split_url(url: &str) -> Result<(Scheme, &str, &str), Error> {
    let (scheme, rest) = url.split_once("://").ok_or("url has no scheme")?;
    let scheme = match scheme {
        "https" => Scheme::Https,
        "http" => Scheme::Http,
        other => return Err(format!("unsupported scheme {other}").into()),
    };
    Ok(match rest.find('/') {
        Some(slash) => (scheme, &rest[..slash], &rest[slash..]),
        None => (scheme, rest, "/"),
    })
}

/// Returns the status and body.
pub fn post(url: &str, headers: &[(&str, String)], body: &[u8]) -> Result<(u16, Vec<u8>), Error> {
    let (scheme, authority, path) = split_url(url)?;
    let fields = Fields::new();
    fields.append(&"content-type".to_string(), &b"application/json".to_vec()).map_err(|e| format!("{e:?}"))?;
    for (name, value) in headers {
        fields.append(&name.to_lowercase(), &value.as_bytes().to_vec()).map_err(|e| format!("{e:?}"))?;
    }

    let request = OutgoingRequest::new(fields);
    request.set_method(&Method::Post).map_err(|()| "set method")?;
    request.set_scheme(Some(&scheme)).map_err(|()| "set scheme")?;
    request.set_authority(Some(authority)).map_err(|()| "set authority")?;
    request.set_path_with_query(Some(path)).map_err(|()| "set path")?;

    let outgoing = request.body().map_err(|()| "open body")?;
    let options = RequestOptions::new();
    options.set_connect_timeout(Some(CONNECT_TIMEOUT_NANOS)).map_err(|()| "set timeout")?;
    // Sent before the body is written: a large body fills the buffer and blocks until the
    // request is running and draining it.
    let pending = outgoing_handler::handle(request, Some(options))?;

    let stream = outgoing.write().map_err(|()| "open body stream")?;
    for chunk in body.chunks(MAX_WRITE_BYTES) {
        stream.blocking_write_and_flush(chunk)?;
    }
    drop(stream);
    OutgoingBody::finish(outgoing, None)?;

    pending.subscribe().block();
    let response = pending.get().ok_or("no response")?.map_err(|()| "response taken")??;
    drop(pending);

    let status = response.status();
    let incoming = response.consume().map_err(|()| "open response")?;
    let stream = incoming.stream().map_err(|()| "open response stream")?;
    let mut bytes = vec![];
    loop {
        match stream.blocking_read(READ_BYTES) {
            Ok(chunk) => bytes.extend(chunk),
            Err(StreamError::Closed) => break,
            Err(error) => return Err(format!("read failed: {error:?}").into()),
        }
    }
    Ok((status, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_urls() {
        let (_, host, path) = split_url("https://api.anthropic.com/v1/messages").unwrap();
        assert_eq!((host, path), ("api.anthropic.com", "/v1/messages"));
        let (_, host, path) = split_url("http://127.0.0.1:18099").unwrap();
        assert_eq!((host, path), ("127.0.0.1:18099", "/"));
        assert!(split_url("nope").is_err());
        assert!(split_url("ftp://x/y").is_err());
    }
}
