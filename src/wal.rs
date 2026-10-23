use crate::sha256::{sha256, Hash256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAGIC_BYTES: &[u8; 4] = b"MLOG";
const VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    pub index: u64,
    pub timestamp: u64,
    pub payload: Vec<u8>,
    pub checksum: Hash256,
}

pub struct WriteAheadLog {
    file: File,
    path: PathBuf,
    total_records: u64,
}

impl WriteAheadLog {
    pub fn open(path: impl AsRef<Path>) -> io::Result<(Self, Vec<LogRecord>)> {
        let p = path.as_ref().to_path_buf();
        let exists = p.exists();

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&p)?;

        let mut records = Vec::new();

        if exists && file.metadata()?.len() >= 5 {
            // Verify header
            let mut magic = [0u8; 4];
            file.read_exact(&mut magic)?;
            if &magic != MAGIC_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid WAL magic bytes",
                ));
            }
            let mut ver = [0u8; 1];
            file.read_exact(&mut ver)?;
            if ver[0] != VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unsupported WAL version",
                ));
            }

            // Replay records with zero-corruption torn write recovery
            loop {
                let record_start_offset = file.stream_position()?;

                let mut index_buf = [0u8; 8];
                match file.read_exact(&mut index_buf) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                }
                let index = u64::from_be_bytes(index_buf);

                let mut ts_buf = [0u8; 8];
                if let Err(e) = file.read_exact(&mut ts_buf) {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        file.set_len(record_start_offset)?;
                        file.seek(SeekFrom::Start(record_start_offset))?;
                        break;
                    }
                    return Err(e);
                }
                let timestamp = u64::from_be_bytes(ts_buf);

                let mut len_buf = [0u8; 4];
                if let Err(e) = file.read_exact(&mut len_buf) {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        file.set_len(record_start_offset)?;
                        file.seek(SeekFrom::Start(record_start_offset))?;
                        break;
                    }
                    return Err(e);
                }
                let payload_len = u32::from_be_bytes(len_buf) as usize;

                let mut payload = vec![0u8; payload_len];
                if let Err(e) = file.read_exact(&mut payload) {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        file.set_len(record_start_offset)?;
                        file.seek(SeekFrom::Start(record_start_offset))?;
                        break;
                    }
                    return Err(e);
                }

                let mut checksum = [0u8; 32];
                if let Err(e) = file.read_exact(&mut checksum) {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        file.set_len(record_start_offset)?;
                        file.seek(SeekFrom::Start(record_start_offset))?;
                        break;
                    }
                    return Err(e);
                }

                // Verify checksum
                let mut check_preimage = Vec::with_capacity(16 + payload_len);
                check_preimage.extend_from_slice(&index_buf);
                check_preimage.extend_from_slice(&ts_buf);
                check_preimage.extend_from_slice(&payload);
                if sha256(&check_preimage) != checksum {
                    let current_pos = file.stream_position()?;
                    let file_len = file.metadata()?.len();
                    if current_pos >= file_len {
                        // Trailing torn record caused by crash during mid-write: truncate and heal
                        file.set_len(record_start_offset)?;
                        file.seek(SeekFrom::Start(record_start_offset))?;
                        break;
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Corrupt record at index {}", index),
                    ));
                }

                records.push(LogRecord {
                    index,
                    timestamp,
                    payload,
                    checksum,
                });
            }
        } else {
            // Write initial header
            file.seek(SeekFrom::Start(0))?;
            file.write_all(MAGIC_BYTES)?;
            file.write_all(&[VERSION])?;
            file.flush()?;
        }

        let total_records = records.len() as u64;
        Ok((
            Self {
                file,
                path: p,
                total_records,
            },
            records,
        ))
    }

    pub fn append(&mut self, payload: &[u8]) -> io::Result<LogRecord> {
        self.file.seek(SeekFrom::End(0))?;

        let index = self.total_records;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let index_bytes = index.to_be_bytes();
        let ts_bytes = timestamp.to_be_bytes();
        let len_bytes = (payload.len() as u32).to_be_bytes();

        let mut check_preimage = Vec::with_capacity(16 + payload.len());
        check_preimage.extend_from_slice(&index_bytes);
        check_preimage.extend_from_slice(&ts_bytes);
        check_preimage.extend_from_slice(payload);
        let checksum = sha256(&check_preimage);

        self.file.write_all(&index_bytes)?;
        self.file.write_all(&ts_bytes)?;
        self.file.write_all(&len_bytes)?;
        self.file.write_all(payload)?;
        self.file.write_all(&checksum)?;
        self.file.flush()?;

        self.total_records += 1;

        Ok(LogRecord {
            index,
            timestamp,
            payload: payload.to_vec(),
            checksum,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wal_torn_write_auto_recovery() {
        let temp_dir = std::env::temp_dir().join(format!("wal_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let wal_path = temp_dir.join("test.wal");

        // 1. Write 2 clean records
        {
            let (mut wal, _) = WriteAheadLog::open(&wal_path).unwrap();
            wal.append(b"committed transaction 1").unwrap();
            wal.append(b"committed transaction 2").unwrap();
        }

        // 2. Simulate torn write by appending 7 garbage bytes (partial record from mid-crash)
        {
            let mut file = OpenOptions::new().append(true).open(&wal_path).unwrap();
            file.write_all(&[0x00, 0x00, 0x00, 0x02, 0x12, 0x34, 0x56]).unwrap();
            file.flush().unwrap();
        }

        // 3. Open WAL: should detect the torn trailing record, truncate it, and recover the 2 committed records
        {
            let (mut wal, records) = WriteAheadLog::open(&wal_path).expect("WAL open should heal torn write");
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].payload, b"committed transaction 1");
            assert_eq!(records[1].payload, b"committed transaction 2");

            // Verify WAL can append new records normally after recovery
            let rec3 = wal.append(b"committed transaction 3").unwrap();
            assert_eq!(rec3.index, 2);
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
