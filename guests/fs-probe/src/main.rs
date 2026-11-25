//! Filesystem probe: tries to read and write under the guest paths the example
//! policies map host directories onto, plus a few paths no policy grants.

use std::fs;
use std::io::Write;

fn main() {
    println!("fs-probe: what can this guest reach?");

    // `storage.readonly` in the policies maps a host directory onto /models.
    report(
        "read  /models/weights.txt",
        read_file("/models/weights.txt"),
    );
    report(
        "write /models/tampered.txt",
        write_file("/models/tampered.txt"),
    );

    // `storage.mount` maps a host directory onto /data (read-write).
    report("write /data/report.txt", write_file("/data/report.txt"));
    report("read  /data/report.txt", read_file("/data/report.txt"));
    report("list  /data", list_dir("/data"));

    // Never granted by any policy: the host filesystem is not reachable.
    report("read  /etc/passwd", read_file("/etc/passwd"));
    report(
        "read  /data/../../etc/passwd",
        read_file("/data/../../etc/passwd"),
    );
    report("list  /", list_dir("/"));
}

fn write_file(path: &str) -> std::io::Result<String> {
    let body = "written by the guest\n";
    let mut file = fs::File::create(path)?;
    file.write_all(body.as_bytes())?;

    Ok(format!("{} bytes", body.len()))
}

fn read_file(path: &str) -> std::io::Result<String> {
    let body = fs::read_to_string(path)?;
    let first_line = body.lines().next().unwrap_or_default();

    Ok(format!("{first_line:?}"))
}

fn list_dir(path: &str) -> std::io::Result<String> {
    let mut names: Vec<String> = fs::read_dir(path)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();

    Ok(format!("[{}]", names.join(", ")))
}

fn report(label: &str, outcome: std::io::Result<String>) {
    match outcome {
        Ok(detail) => println!("  ALLOWED  {label} -> {detail}"),
        Err(err) => println!("  DENIED   {label} -> {:?}: {err}", err.kind()),
    }
}
