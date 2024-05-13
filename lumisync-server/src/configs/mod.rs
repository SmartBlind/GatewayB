use std::{env, io};
use std::path::PathBuf;

pub mod settings;
pub mod storage;

pub fn normalize_path(path: &str) -> io::Result<PathBuf> {
    let path_buf = PathBuf::from(path);

    Ok(if path_buf.is_absolute() {
        path_buf.clone()
    } else {
        env::current_dir()?
            .as_path()
            .join(&path_buf)
    })
}