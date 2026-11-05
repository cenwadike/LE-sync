use nssa::program::Program;

fn main() {
    let mut args = std::env::args().skip(1);
    let flag = args.next().unwrap_or_default();
    let path = args.next().unwrap_or_default();
    if flag != "--program-path" || path.is_empty() || args.next().is_some() {
        eprintln!("usage: run_eth_attest --program-path <guest-binary>");
        std::process::exit(2);
    }

    let bytes = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("failed to read guest binary at `{path}`: {err}"));
    let program = Program::new(bytes.into())
        .unwrap_or_else(|err| panic!("failed to parse guest program: {err}"));
    let id: Vec<u8> = program.id().iter().flat_map(|word| word.to_le_bytes()).collect();
    println!("eth_attest program id: {}", hex::encode(id));
}
