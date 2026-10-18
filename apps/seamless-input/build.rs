fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let version = env!("CARGO_PKG_VERSION");
        let mut resource = winresource::WindowsResource::new();
        resource
            .set("ProductName", "Control Shift F12")
            .set("FileDescription", "Control Shift F12")
            .set("OriginalFilename", "seamless-input.exe")
            .set("ProductVersion", version)
            .set("FileVersion", version);
        resource.compile().expect("compile Windows VERSIONINFO");
    }
}
