fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/slouching/v1/handshake.proto");
    prost_build::compile_protos(&["proto/slouching/v1/handshake.proto"], &["proto"])?;
    Ok(())
}
