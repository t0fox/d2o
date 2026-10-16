use std::io::{self, BufRead};

use z2kow_tg_transparent::crypto::{ProtoTag, make_cipher};
use z2kow_tg_transparent::splitter::MsgSplitter;

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex-поле имеет нечётную длину".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).ok_or("неверный hex")?;
            let low = (pair[1] as char).to_digit(16).ok_or("неверный hex")?;
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

fn run_case(line: &str) -> Result<String, String> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() != 5 {
        return Err("ожидалось пять полей".into());
    }
    let proto = match fields[1] {
        "abridged" => ProtoTag::Abridged,
        "intermediate" => ProtoTag::Intermediate,
        "padded-intermediate" => ProtoTag::PaddedIntermediate,
        _ => return Err("неизвестный протокол".into()),
    };
    let key = decode_hex(fields[2])?;
    let iv = decode_hex(fields[3])?;
    if key.len() != 32 || iv.len() != 16 {
        return Err("неверный размер AES key/IV".into());
    }

    let mut cipher = make_cipher(&key, &iv);
    let mut splitter = MsgSplitter::new(proto);
    let mut packets = Vec::new();
    for chunk in fields[4].split(';') {
        let mut plaintext = decode_hex(chunk)?;
        packets.extend(splitter.split_and_encrypt(&mut plaintext, &mut cipher));
        if splitter.error().is_some() {
            break;
        }
    }
    let status = if splitter.error().is_some() {
        "TOO_LARGE"
    } else {
        packets.extend(splitter.flush());
        "OK"
    };
    let encoded = packets
        .iter()
        .map(|packet| encode_hex(packet))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!("{}\t{}\t{}", fields[0], status, encoded))
}

fn main() {
    for (line_number, line) in io::stdin().lock().lines().enumerate() {
        let line = line.unwrap_or_else(|error| panic!("stdin line {}: {error}", line_number + 1));
        let result = run_case(&line)
            .unwrap_or_else(|error| panic!("scenario {}: {error}", line_number + 1));
        println!("{result}");
    }
}
