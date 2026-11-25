//! Environment probe: prints the argv and environment the host handed over,
//! i.e. what the policy's `arguments` and `[env]` sections produce.

fn main() {
    println!("env-probe: what did the host hand over?");

    let args: Vec<String> = std::env::args().collect();
    println!("  argv = {args:?}");

    let mut env: Vec<(String, String)> = std::env::vars().collect();
    env.sort();
    if env.is_empty() {
        println!("  env  = (empty)");
    }
    for (key, value) in env {
        println!("  env  {key}={value}");
    }
}
