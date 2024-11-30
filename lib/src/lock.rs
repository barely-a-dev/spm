use std::fs::{self, File, OpenOptions};
use std::io::{Error, ErrorKind, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use nix::fcntl::{Flock, FlockArg};

pub struct Lock {
    _file: File,
    path: PathBuf,
}

impl Lock {
    pub fn new(lock_type: &str) -> Result<Self, Error> {
        Self::new_with_timeout(lock_type, Duration::from_secs(10))
    }

    pub fn new_with_timeout(lock_type: &str, timeout: Duration) -> Result<Self, Error> {
        let lockfile = PathBuf::from(format!("/var/lib/spm/spm-{}.lock", lock_type));

        let par = PathBuf::from("/var/lib/spm");
        if !par.exists()
        {
            fs::create_dir_all("/var/lib/spm")?;
        }
        
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&lockfile)?;

        let start = Instant::now();
        loop {
            match Flock::lock(file.try_clone().unwrap(), FlockArg::LockExclusiveNonblock) {
                Ok(_) => {
                    write!(file, "{}", std::process::id())?;
                    file.sync_all()?;
                    return Ok(Lock { _file: file, path: lockfile });
                }
                Err((_, nix::errno::Errno::EAGAIN)) => {
                    if start.elapsed() > timeout {
                        return Err(Error::new(ErrorKind::TimedOut, "Failed to acquire lock"));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err((_, e)) => return Err(Error::new(ErrorKind::Other, e.to_string())),
            }
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
