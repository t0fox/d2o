use std::io::{self, BufRead};
use std::net::IpAddr;

use z2kow_tg_transparent::dc_map::{
    lookup_endpoint, DcEndpoint, DcMapStore, DcSnapshot, RouteLookupError,
};

fn number<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    text.parse()
        .map_err(|_| "неверное числовое поле".to_owned())
}

fn flag(text: &str) -> Result<bool, String> {
    match text {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("флаг должен быть 0 или 1".to_owned()),
    }
}

fn endpoint(text: &str) -> Result<DcEndpoint, String> {
    let fields: Vec<&str> = text.split(',').collect();
    if fields.len() != 8 {
        return Err("неверное число полей dcOption".to_owned());
    }
    let address: IpAddr = fields[1]
        .parse()
        .map_err(|_| "неверный адрес dcOption".to_owned())?;
    Ok(DcEndpoint {
        id: number(fields[0])?,
        address,
        port: number(fields[2])?,
        ipv6: address.is_ipv6(),
        media_only: flag(fields[3])?,
        tcpo_only: flag(fields[4])?,
        cdn: flag(fields[5])?,
        is_static: flag(fields[6])?,
        this_port_only: flag(fields[7])?,
        secret: None,
        last_seen: 1,
    })
}

fn error_name(error: RouteLookupError) -> &'static str {
    match error {
        RouteLookupError::AddressNotListed => "not-listed",
        RouteLookupError::PortNotAllowed => "port",
        RouteLookupError::MediaFlagMismatch => "media",
        RouteLookupError::DcMismatch => "dc",
        RouteLookupError::CdnEndpoint => "cdn",
        RouteLookupError::Ambiguous => "ambiguous",
    }
}

fn run_line(line: &str) -> Result<String, String> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() != 7 {
        return Err("ожидалось семь полей".to_owned());
    }
    let address: IpAddr = fields[2]
        .parse()
        .map_err(|_| "неверный целевой адрес".to_owned())?;
    let port: u16 = number(fields[3])?;
    let media_hint = flag(fields[4])?;
    let dc_hint = match number::<u32>(fields[5])? {
        0 => None,
        dc => Some(dc),
    };

    let route = match fields[1] {
        "builtin" if fields[6].is_empty() => {
            DcMapStore::without_cache("unused").resolve(address, port, media_hint, dc_hint)
        }
        "official" => {
            let endpoints = fields[6]
                .split('/')
                .map(endpoint)
                .collect::<Result<Vec<_>, _>>()?;
            let snapshot = DcSnapshot {
                schema_version: 1,
                fetched_at: 1,
                config_date: 1,
                config_expires: 2,
                this_dc: 2,
                endpoints,
            };
            lookup_endpoint(&snapshot, address, port, media_hint, dc_hint)
        }
        _ => return Err("неверный источник карты DC".to_owned()),
    };

    match route {
        Ok(route) => Ok(format!(
            "{}\tOK\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            fields[0],
            route.id,
            route.address,
            route.port,
            u8::from(route.media_only),
            u8::from(route.tcpo_only),
            u8::from(route.cdn),
            u8::from(route.is_static),
            u8::from(route.this_port_only),
        )),
        Err(error) => Ok(format!("{}\t{}", fields[0], error_name(error))),
    }
}

fn main() {
    for (line_number, line) in io::stdin().lock().lines().enumerate() {
        let line =
            line.unwrap_or_else(|error| panic!("чтение строки {}: {error}", line_number + 1));
        let result =
            run_line(&line).unwrap_or_else(|error| panic!("сценарий {}: {error}", line_number + 1));
        println!("{result}");
    }
}
