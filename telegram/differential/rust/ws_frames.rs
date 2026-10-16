use std::io::{self, BufRead, Cursor, Read, Write};

use tungstenite::{
    protocol::{Role, WebSocket, WebSocketConfig},
    Message,
};

const MAX_MESSAGE: usize = 4 * 1024 * 1024;

struct ChunkedIo {
    input: Cursor<Vec<u8>>,
    max_read: usize,
}

impl Read for ChunkedIo {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let length = output.len().min(self.max_read);
        self.input.read(&mut output[..length])
    }
}

impl Write for ChunkedIo {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() % 2 != 0 {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).ok_or(())?;
            let low = (pair[1] as char).to_digit(16).ok_or(())?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn run_case(line: &str) -> String {
    let mut fields = line.splitn(3, '\t');
    let case_id = fields.next().unwrap_or("");
    let chunk = fields
        .next()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0);
    let wire = fields.next().and_then(|value| decode_hex(value).ok());
    let (Some(chunk), Some(wire)) = (chunk, wire) else {
        return format!("{case_id}\tERR");
    };

    let config = WebSocketConfig {
        write_buffer_size: 16 * 1024,
        max_write_buffer_size: MAX_MESSAGE + 16 * 1024,
        max_frame_size: Some(MAX_MESSAGE),
        max_message_size: Some(MAX_MESSAGE),
        ..WebSocketConfig::default()
    };
    let stream = ChunkedIo {
        input: Cursor::new(wire),
        max_read: chunk,
    };
    let mut websocket = WebSocket::from_raw_socket(stream, Role::Client, Some(config));
    let mut messages = Vec::new();
    loop {
        match websocket.read() {
            Ok(Message::Binary(data)) => messages.push(format!("B:{}", encode_hex(&data))),
            Ok(Message::Text(data)) => messages.push(format!("T:{}", encode_hex(data.as_bytes()))),
            Ok(Message::Ping(_) | Message::Pong(_)) => {}
            Ok(Message::Close(_)) => {
                return format!("{case_id}\tOK\t{}", messages.join(";"));
            }
            Ok(Message::Frame(_)) | Err(_) => return format!("{case_id}\tERR"),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().lines() {
        let line = line?;
        println!("{}", run_case(&line));
    }
    Ok(())
}
