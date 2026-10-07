use age::secrecy::SecretString;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

pub fn export_handoff(case_dir: &Path, out: &Path, password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("password must be at least 8 characters".into());
    }
    let mut archive = vec![];
    {
        let mut builder = tar::Builder::new(&mut archive);
        for name in ["events.duckdb", "catalog.sqlite"] {
            let path = case_dir.join(name);
            if path.exists() {
                builder.append_path_with_name(&path, name).map_err(|err| err.to_string())?;
            }
        }
        builder.finish().map_err(|err| err.to_string())?;
    }
    let encryptor = age::Encryptor::with_user_passphrase(SecretString::from(password.to_string()));
    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted).map_err(|err| err.to_string())?;
    writer.write_all(&archive).map_err(|err| err.to_string())?;
    writer.finish().map_err(|err| err.to_string())?;
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    fs::write(out, encrypted).map_err(|err| err.to_string())?;
    Ok(())
}

pub fn open_handoff(file: &Path, out_dir: &Path, password: &str) -> Result<(), String> {
    let encrypted = fs::read(file).map_err(|err| err.to_string())?;
    let decryptor = age::Decryptor::new(&encrypted[..]).map_err(|err| err.to_string())?;
    let identity = age::scrypt::Identity::new(SecretString::from(password.to_string()));
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| "password rejected".to_string())?;
    let mut archive = vec![];
    reader.read_to_end(&mut archive).map_err(|err| err.to_string())?;
    fs::create_dir_all(out_dir).map_err(|err| err.to_string())?;
    tar::Archive::new(archive.as_slice()).unpack(out_dir).map_err(|err| err.to_string())?;
    Ok(())
}
