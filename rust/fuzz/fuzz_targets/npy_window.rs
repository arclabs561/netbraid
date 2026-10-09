#![no_main]

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use netbraid::adapters::npy::{
    project_npy_row_window, project_npy_vector_window, NpyRowWindowOptions, NpyVectorWindowOptions,
};

fuzz_target!(|input: &[u8]| {
    // The adapter reads from a path, so stage the input as a regular file.
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(input).expect("write fuzz input");
    file.flush().expect("flush fuzz input");
    let _ = project_npy_row_window(file.path(), &NpyRowWindowOptions::default());
    let _ = project_npy_vector_window(file.path(), &NpyVectorWindowOptions::default());
});
