fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        winresource::WindowsResource::new().compile()?;
    }
    Ok(())
}
