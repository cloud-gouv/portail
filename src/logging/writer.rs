use std::{
    fs::{File, OpenOptions},
    path::PathBuf,
    sync::{Arc, Mutex},
};

/// File writer that can be atomically replaced.
#[derive(Debug, Clone)]
pub struct SharedFileWriter {
    file: Arc<Mutex<File>>,
    open_options: OpenOptions,
    pub path: PathBuf,
}

impl SharedFileWriter {
    pub fn new(path: PathBuf, open_options: OpenOptions) -> std::io::Result<Self> {
        let file = Arc::new(Mutex::new(open_options.open(&path)?));
        Ok(Self {
            path,
            file,
            open_options,
        })
    }

    pub fn reopen(&self) -> std::io::Result<()> {
        let new_file = self.open_options.open(&self.path)?;
        let mut guard = self.file.lock().unwrap();
        *guard = new_file;
        Ok(())
    }
}

impl std::io::Write for SharedFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.lock().unwrap().flush()
    }
}
