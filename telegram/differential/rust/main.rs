use std::io::{self, BufRead};

use cipher::StreamCipher;
use z2kow_tg_transparent::crypto::{
    ProtoTag, generate_client_handshake, generate_relay_init, make_cipher,
    parse_handshake,
};
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

fn parse_proto(name: &str) -> Result<ProtoTag, String> {
    match name {
        "abridged" => Ok(ProtoTag::Abridged),
        "intermediate" => Ok(ProtoTag::Intermediate),
        "padded-intermediate" => Ok(ProtoTag::PaddedIntermediate),
        _ => Err("неизвестный протокол".into()),
    }
}

fn proto_name(proto: ProtoTag) -> &'static str {
    match proto {
        ProtoTag::Abridged => "abridged",
        ProtoTag::Intermediate => "intermediate",
        ProtoTag::PaddedIntermediate => "padded-intermediate",
    }
}

fn generate_handshake_case(line: &str) -> Result<String, String> {
    let fields: Vec<&str> = line.split('\t').collect();
    match fields.first().copied() {
        Some("secret") if fields.len() == 5 => {
            let proto = parse_proto(fields[2])?;
            let signed_dc = fields[3]
                .parse::<i16>()
                .map_err(|_| "неверный DC index".to_owned())?;
            let secret = decode_hex(fields[4])?;
            let (handshake, _, _) = generate_client_handshake(&secret, signed_dc, proto);
            let parsed = parse_handshake(&handshake, &secret)
                .ok_or_else(|| "Rust не распознал созданный secret handshake".to_owned())?;
            if parsed.proto != proto
                || parsed.dc_id != u32::from(signed_dc.unsigned_abs())
                || parsed.is_media != signed_dc.is_negative()
            {
                return Err("Rust изменил поля secret handshake".into());
            }

            let mut wrong_secret = secret.clone();
            if wrong_secret.is_empty() {
                wrong_secret.push(1);
            } else {
                wrong_secret[0] ^= 1;
            }
            if parse_handshake(&handshake, &wrong_secret).is_some() {
                return Err("Rust принял handshake с неверным secret".into());
            }

            Ok(format!(
                "secret\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                fields[1],
                proto_name(parsed.proto),
                parsed.dc_id,
                u8::from(parsed.is_media),
                encode_hex(&parsed.prekey_and_iv),
                encode_hex(&handshake),
                encode_hex(&wrong_secret),
            ))
        }
        Some("direct") if fields.len() == 4 => {
            let proto = parse_proto(fields[2])?;
            let signed_dc = fields[3]
                .parse::<i16>()
                .map_err(|_| "неверный DC index".to_owned())?;
            let handshake = generate_relay_init(proto, signed_dc);
            let mut plaintext = handshake;
            make_cipher(&handshake[8..40], &handshake[40..56])
                .apply_keystream(&mut plaintext);
            let parsed_proto = &plaintext[56..60];
            let parsed_dc = i16::from_le_bytes([plaintext[60], plaintext[61]]);
            if parsed_proto != proto.as_bytes() || parsed_dc != signed_dc {
                return Err("Rust создал неверный direct handshake".into());
            }

            Ok(format!(
                "direct\t{}\t{}\t{}\t{}\t{}\t{}",
                fields[1],
                proto_name(proto),
                u32::from(signed_dc.unsigned_abs()),
                u8::from(signed_dc.is_negative()),
                encode_hex(&handshake[8..56]),
                encode_hex(&handshake),
            ))
        }
        _ => Err("неверная строка запроса handshake".into()),
    }
}

fn run_splitter() {
    for (line_number, line) in io::stdin().lock().lines().enumerate() {
        let line = line.unwrap_or_else(|error| panic!("stdin line {}: {error}", line_number + 1));
        let result = run_case(&line)
            .unwrap_or_else(|error| panic!("scenario {}: {error}", line_number + 1));
        println!("{result}");
    }
}

fn run_handshake_generation() {
    for (line_number, line) in io::stdin().lock().lines().enumerate() {
        let line = line.unwrap_or_else(|error| panic!("stdin line {}: {error}", line_number + 1));
        let result = generate_handshake_case(&line)
            .unwrap_or_else(|error| panic!("scenario {}: {error}", line_number + 1));
        println!("{result}");
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--generate-handshakes") {
        run_handshake_generation();
    } else {
        run_splitter();
    }
}
