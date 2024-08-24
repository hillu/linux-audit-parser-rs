use std::env;
use std::fs;
use std::io::prelude::*;
use std::io::BufReader;
use std::iter::FromIterator;
use std::path::Path;
use std::string::String;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let field_def_file = "src/audit-specs/fields/field-dictionary.csv";
    let msgtype_def_file = "src/audit-specs/messages/message-dictionary.csv";
    let const_file = Path::new(&out_dir).join("const.rs");
    let msgtype_file = Path::new(&out_dir).join("message_type_impl.rs");

    let constants: Vec<(String, String)> = BufReader::new(fs::File::open(msgtype_def_file)?)
        .lines()
        .skip(1) // skip over header
        .map(|line| {
            line.unwrap()
                .split(',')
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
        })
        .map(|fields| {
            (
                fields[0].strip_prefix("AUDIT_").unwrap().to_string(),
                fields[1].clone(),
            )
        })
        .collect();

    let fields: Vec<(String, String)> = BufReader::new(fs::File::open(field_def_file)?)
        .lines()
        .skip(3) // skip over heder and regex describing a* mess
        .map(|line| {
            line.unwrap()
                .split(',')
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
        })
        .map(|fields| (fields[0].clone(), fields[1].clone()))
        .collect();

    let mut template = Vec::new();
    fs::File::open("src/const.rs.in")?.read_to_end(&mut template)?;
    let template = String::from_utf8(template)?;

    let buf = template
        .replace(
            "/* @EVENT_CONST@ */",
            &String::from_iter(
                constants
                    .iter()
                    .map(|(name, value)| format!(r#"("{name}", {value}), "#)),
            ),
        )
        .replace(
            "/* @FIELD_TYPES@ */",
            &String::from_iter(
                fields
                    .iter()
                    .filter(|(_, typ)| typ == "encoded" || typ.starts_with("numeric"))
                    .map(|(name, typ)| match typ.as_str() {
                        "numeric hexadecimal" => format!(r#"("{name}", FieldType::NumericHex),"#),
                        "numeric decimal" => format!(r#"("{name}", FieldType::NumericDec),"#),
                        "numeric octal" => format!(r#"("{name}", FieldType::NumericOct),"#),
                        "numeric" => format!(r#"("{name}", FieldType::Numeric),"#),
                        "encoded" => format!(r#"("{name}", FieldType::Encoded),"#),
                        _ => format!(r#"("{name}", FieldType::Invalid),"#),
                    }),
            ),
        )
        .into_bytes();
    fs::write(const_file, buf)?;

    let mut template = Vec::new();
    fs::File::open("src/message_type_impl.rs.in")?.read_to_end(&mut template)?;
    let template = String::from_utf8(template)?;
    let buf = template.replace(
        "/* @MSG_TYPE_CONST@ */",
        &String::from_iter(
            constants
                .iter()
                .map(|(name, value)| format!("pub const {name}: Self = Self({value});\n",)),
        ),
    );

    fs::write(msgtype_file, buf)?;

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=const.rs.in");
    println!("cargo:rerun-if-changed={msgtype_def_file}");
    println!("cargo:rerun-if-changed={field_def_file}");

    Ok(())
}
