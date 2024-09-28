use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Error, Result};
use futures::{stream, StreamExt};
use tokio::{io::AsyncReadExt, join};

#[tokio::main]
async fn main() -> Result<()> {
    // Create a discovery socket
    let mut socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    // Broadcast target
    let target = "255.255.255.255:12345";
    let target: SocketAddr = target.parse()?;

    // Send a discovery message
    let buf = b"DISCOVER";
    socket.send_to(buf, &target).await?;

    // Now hash the whole documents folder
    let temp = std::env::var("TEMP")?;
    let temp = Path::new(&temp);
    let documents = temp
        .parent()
        .context("Cannot get parent")?
        .parent()
        .context("Cannot get parent")?
        .parent()
        .context("Cannot get parent")?
        .join("Documents");
    println!("Hashing {}", documents.display());
    let path = documents;
    let hash = hash_folder(path.clone()).await.map_err(|e| {
        eprintln!("Error hashing folder: {}", e);
        e
    })?;
    println!("Hash of {:?} is {:x}", path, hash);

    Ok(())
}

pub async fn hash_folder(path: PathBuf) -> Result<u64> {
    // if it's a file, hash it
    if path.is_file() {
        return hash_file(path).await;
    }

    // if it's a directory, hash all files in it
    let mut entries = vec![];
    let mut read_dir = tokio::fs::read_dir(path).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.path());
    let mut handles = vec![];
    for entry in entries {
        let entry = entry.path();
        let handle = tokio::task::spawn(hash_folder(entry));
        handles.push(handle);
    }

    // wait for all the handles
    let results = stream::iter(handles)
        .buffered(100)
        .collect::<Vec<_>>()
        .await;
    let mut hasher = blake3::Hasher::new();
    for result in results {
        let hash = result??;
        hasher.update(&hash.to_le_bytes());
    }

    let hash = hasher.finalize();
    Ok(u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap()))
}

pub async fn hash_file(path: PathBuf) -> Result<u64> {
    // using blake3 and tokio::fs
    let mut hasher = blake3::Hasher::new();
    let mut file = tokio::fs::File::open(path).await?;
    let mut buf = [0; 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    Ok(u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap()))
}

pub fn hash<S: AsRef<str>>(s: S) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(s.as_ref().as_bytes());
    let hash = hasher.finalize();
    u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap())
}
