fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource
            .set("ProductName", "Control Shift F12")
            .set("FileDescription", "Control Shift F12")
            .set("OriginalFilename", "seamless-input.exe");
        resource.compile().expect("compile Windows VERSIONINFO");
    }
}
