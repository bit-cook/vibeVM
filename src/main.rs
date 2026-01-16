use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::{
    NSArray, NSData, NSDate, NSDefaultRunLoopMode, NSError, NSFileHandle, NSRunLoop, NSString,
    NSUInteger, NSURL,
};
use objc2_virtualization::{
    VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment, VZDiskImageSynchronizationMode,
    VZEFIBootLoader, VZEFIVariableStore, VZEFIVariableStoreInitializationOptions,
    VZFileHandleSerialPortAttachment, VZGenericMachineIdentifier, VZGenericPlatformConfiguration,
    VZNATNetworkDeviceAttachment, VZSharedDirectory, VZSingleDirectoryShare,
    VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceSerialPortConfiguration,
    VZVirtioEntropyDeviceConfiguration, VZVirtioFileSystemDeviceConfiguration,
    VZVirtioNetworkDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
};

const DEBIAN_DISK_URL: &str =
    "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-nocloud-arm64.qcow2";
const PROVISION_SCRIPT: &str = include_str!("../provisioning/provision.sh");

const DISK_SIZE_GB: u64 = 10;
const CPU_COUNT: usize = 4;
const RAM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const START_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct VmPaths {
    project_root: PathBuf,
    project_name: String,
    cache_dir: PathBuf,
    guest_mise_cache: PathBuf,
    instance_dir: PathBuf,
    downloaded_qcow2: PathBuf,
    base_raw: PathBuf,
    configured_raw: PathBuf,
    instance_raw: PathBuf,
    efi_variable_store: PathBuf,
    cargo_registry: PathBuf,
}

impl VmPaths {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let project_root = env::current_dir()?;
        let project_name = project_root
            .file_name()
            .ok_or("Project directory has no name")?
            .to_string_lossy()
            .into_owned();

        let home = env::var("HOME").map(PathBuf::from)?;
        let cache_home = env::var("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".cache"));
        let cache_dir = cache_home.join("vibetron");
        let guest_mise_cache = cache_dir.join(".guest-mise-cache");
        let instance_dir = project_root.join(".vibetron");

        let downloaded_image = cache_dir.join("downloaded.qcow2");
        let base_raw = cache_dir.join("base.raw");
        let configured_base = cache_dir.join("configured_base.raw");
        let instance_disk = instance_dir.join("instance.raw");
        let efi_variable_store = instance_dir.join("efi-variable-store");
        let cargo_registry = home.join(".cargo/registry");

        Ok(Self {
            project_root,
            project_name,
            cache_dir,
            guest_mise_cache,
            instance_dir,
            downloaded_qcow2: downloaded_image,
            base_raw,
            configured_raw: configured_base,
            instance_raw: instance_disk,
            efi_variable_store,
            cargo_registry,
        })
    }
}

#[derive(PartialEq, Eq)]
enum WaitResult {
    Timeout,
    Found,
}

struct OutputMonitor {
    buffer: Mutex<String>,
    condvar: Condvar,
}

impl OutputMonitor {
    fn new() -> Self {
        Self {
            buffer: Mutex::new(String::new()),
            condvar: Condvar::new(),
        }
    }

    fn push(&self, bytes: &[u8]) {
        let mut buf = self.buffer.lock().unwrap();
        buf.push_str(&String::from_utf8_lossy(bytes));
        self.condvar.notify_all();
    }

    fn wait_for(&self, needle: &str, timeout: Duration) -> WaitResult {
        let result = self
            .condvar
            .wait_timeout_while(self.buffer.lock().unwrap(), timeout, |buf| {
                if let Some((_, remaining)) = buf.split_once(needle) {
                    *buf = remaining.to_string();
                    false
                } else {
                    true
                }
            });

        if result.unwrap().1.timed_out() {
            WaitResult::Timeout
        } else {
            WaitResult::Found
        }
    }
}

struct SerialContext {
    output_monitor: Arc<OutputMonitor>,
    input_tx: mpsc::Sender<Vec<u8>>,
    stdout_thread: thread::JoinHandle<()>,
    writer_thread: thread::JoinHandle<()>,
    stdin_thread: thread::JoinHandle<()>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths = VmPaths::new()?;

    prepare_directories(&paths)?;
    download_base_image(&paths)?;
    convert_to_raw(&paths)?;

    ensure_configured_base(&paths)?;

    ensure_instance_disk(&paths)?;

    let config = create_vm_configuration(&paths, &paths.instance_raw)?;
    run_vm(config, Some(""))
}

fn prepare_directories(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(&paths.cache_dir)?;
    fs::create_dir_all(&paths.guest_mise_cache)?;
    fs::create_dir_all(&paths.instance_dir)?;
    fs::create_dir_all(&paths.cargo_registry)?;
    Ok(())
}

fn download_base_image(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    if paths.downloaded_qcow2.exists() {
        println!(
            "Reusing cached base image at {}",
            paths.downloaded_qcow2.display()
        );
    } else {
        println!("Downloading Debian cloud image...");
        let status = Command::new("curl")
            .args([
                "-L",
                "-f",
                DEBIAN_DISK_URL,
                "-o",
                paths.downloaded_qcow2.to_string_lossy().as_ref(),
            ])
            .status()?;

        if !status.success() {
            return Err("Failed to download Ubuntu cloud image".into());
        }
    }

    if !validate_image(&paths.downloaded_qcow2, "cached base image") {
        println!("Cached base image invalid, redownloading...");
        fs::remove_file(&paths.downloaded_qcow2).ok();
        let status = Command::new("curl")
            .args([
                "-L",
                "-f",
                DEBIAN_DISK_URL,
                "-o",
                paths.downloaded_qcow2.to_string_lossy().as_ref(),
            ])
            .status()?;

        if !status.success() {
            return Err("Failed to download Ubuntu cloud image".into());
        }
    }

    Ok(())
}

fn convert_to_raw(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    if paths.base_raw.exists() {
        if validate_image(&paths.base_raw, "cached base raw") {
            println!(
                "Reusing converted base image at {}",
                paths.base_raw.display()
            );
            return Ok(());
        }
        println!("Cached base image invalid, regenerating...");
        fs::remove_file(&paths.base_raw).ok();
    }

    println!("Converting source image to raw...");
    let status = Command::new("qemu-img")
        .args([
            "convert",
            "-O",
            "raw",
            paths.downloaded_qcow2.to_string_lossy().as_ref(),
            paths.base_raw.to_string_lossy().as_ref(),
        ])
        .status()?;

    if !status.success() {
        return Err("Failed to convert qcow2 image to raw".into());
    }

    validate_image(&paths.base_raw, "converted base raw")
        .then_some(())
        .ok_or_else(|| io::Error::other("Converted base image failed validation"))?;

    resize_file(&paths.base_raw, DISK_SIZE_GB)?;
    Ok(())
}

fn ensure_configured_base(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    if paths.configured_raw.exists() {
        println!(
            "Using cached configured base at {}",
            paths.configured_raw.display()
        );
        return Ok(());
    }

    println!("Preparing configured base image...");
    clone_sparse(&paths.base_raw, &paths.configured_raw)?;
    resize_file(&paths.configured_raw, DISK_SIZE_GB)?;

    let config = create_vm_configuration(paths, &paths.configured_raw)?;
    run_vm(config, Some(&format_provision_script(&paths.project_name)))?;

    Ok(())
}

fn ensure_instance_disk(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    if paths.instance_raw.exists() {
        if validate_image(&paths.instance_raw, "instance raw") {
            println!(
                "Using existing instance disk at {}",
                paths.instance_raw.display()
            );
            return Ok(());
        }
        println!("Instance disk invalid, recreating...");
        fs::remove_file(&paths.instance_raw).ok();
    }

    println!("Creating instance disk from configured base image...");
    clone_sparse(&paths.configured_raw, &paths.instance_raw)?;
    resize_file(&paths.instance_raw, DISK_SIZE_GB)?;
    Ok(())
}

fn create_vm_configuration(
    paths: &VmPaths,
    disk_path: &Path,
) -> Result<(Retained<VZVirtualMachineConfiguration>, SerialContext), Box<dyn std::error::Error>> {
    unsafe {
        let platform =
            VZGenericPlatformConfiguration::init(VZGenericPlatformConfiguration::alloc());

        let boot_loader = VZEFIBootLoader::init(VZEFIBootLoader::alloc());
        let variable_store = load_efi_variable_store(paths)?;
        boot_loader.setVariableStore(Some(&variable_store));

        let config = VZVirtualMachineConfiguration::new();
        config.setPlatform(&platform);
        config.setBootLoader(Some(&boot_loader));
        config.setCPUCount(CPU_COUNT as NSUInteger);
        config.setMemorySize(RAM_BYTES);

        let disk_attachment = create_disk_attachment(disk_path, false)?;
        let disk_device = VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &disk_attachment,
        );

        let storage_devices: Retained<NSArray<_>> =
            NSArray::from_retained_slice(&[Retained::into_super(disk_device)]);

        config.setStorageDevices(&storage_devices);

        let nat_attachment = VZNATNetworkDeviceAttachment::new();
        let network_device = VZVirtioNetworkDeviceConfiguration::new();
        network_device.setAttachment(Some(&nat_attachment));
        let network_devices: Retained<NSArray<_>> =
            NSArray::from_retained_slice(&[Retained::into_super(network_device)]);
        config.setNetworkDevices(&network_devices);

        let entropy_device = VZVirtioEntropyDeviceConfiguration::new();
        let entropy_devices: Retained<NSArray<_>> =
            NSArray::from_retained_slice(&[Retained::into_super(entropy_device)]);
        config.setEntropyDevices(&entropy_devices);

        let directory_shares = [
            ("cargo_registry", &paths.cargo_registry, true),
            ("mise_cache", &paths.guest_mise_cache, false),
            ("current_dir", &paths.project_root, false),
        ];

        let mut share_devices: Vec<Retained<_>> = Vec::new();
        for (tag, path, read_only) in directory_shares {
            let device = create_directory_share(tag, path, read_only)?;
            share_devices.push(Retained::into_super(device));
        }

        let share_devices: Retained<NSArray<_>> = NSArray::from_retained_slice(&share_devices);
        config.setDirectorySharingDevices(&share_devices);

        let (serial_read_handle, serial_write_handle, serial_ctx) = setup_serial_pipes()?;

        let serial_attach =
            VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                VZFileHandleSerialPortAttachment::alloc(),
                Some(&serial_read_handle),
                Some(&serial_write_handle),
            );
        let serial_port = VZVirtioConsoleDeviceSerialPortConfiguration::new();
        serial_port.setAttachment(Some(&serial_attach));

        let serial_ports: Retained<NSArray<_>> =
            NSArray::from_retained_slice(&[Retained::into_super(serial_port)]);
        config.setSerialPorts(&serial_ports);

        config.validateWithError().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid VM configuration: {:?}", e.localizedDescription()),
            )
        })?;

        Ok((config, serial_ctx))
    }
}

fn load_efi_variable_store(
    paths: &VmPaths,
) -> Result<Retained<VZEFIVariableStore>, Box<dyn std::error::Error>> {
    unsafe {
        let url = nsurl_from_path(&paths.efi_variable_store)?;
        let options = VZEFIVariableStoreInitializationOptions::AllowOverwrite;
        let store = VZEFIVariableStore::initCreatingVariableStoreAtURL_options_error(
            VZEFIVariableStore::alloc(),
            &url,
            options,
        )
        .map_err(|e| {
            Box::<dyn std::error::Error>::from(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to create EFI variable store at {}: {:?}",
                    paths.efi_variable_store.display(),
                    e.localizedDescription()
                ),
            ))
        })?;
        Ok(store)
    }
}

fn start_script_thread(
    script: &str,
    output_monitor: Arc<OutputMonitor>,
    input_tx: mpsc::Sender<Vec<u8>>,
) -> thread::JoinHandle<()> {
    let script = script.to_string();
    thread::spawn(move || {
        if WaitResult::Timeout == output_monitor.wait_for("login: ", Duration::from_secs(120)) {
            eprintln!("Timed out waiting for system login prompt; not sending script.");
            return;
        }

        let do_write = |payload: &str| {
            if let Err(e) = input_tx.send(payload.as_bytes().to_vec()) {
                eprintln!("Failed to write payload to VM serial: {}", e);
            }
        };

        do_write("root\n");

        if WaitResult::Timeout == output_monitor.wait_for("~#", Duration::from_secs(120)) {
            eprintln!("Timed out waiting for root shell; not sending script");
            return;
        }
        let path = "provisioning_script.sh";
        do_write(&format!(
            "cat >{path} <<'EOF'\n{script}EOF\nchmod +x {path}\n{path}\n"
        ));
    })
}

fn format_provision_script(project_name: &str) -> String {
    PROVISION_SCRIPT.replace("{project_name}", project_name)
}

fn setup_serial_pipes() -> Result<
    (
        Retained<NSFileHandle>,
        Retained<NSFileHandle>,
        SerialContext,
    ),
    Box<dyn std::error::Error>,
> {
    // UnixStream pairs give us bidirectional pipes without libc::pipe.
    let (to_guest_host, to_guest_vm) = UnixStream::pair()?;
    let (from_guest_vm, from_guest_host) = UnixStream::pair()?;

    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>();
    let writer_thread = thread::spawn(move || {
        let mut writer = to_guest_host;
        for chunk in input_rx {
            if writer.write_all(&chunk).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    let output_monitor = Arc::new(OutputMonitor::new());
    let output_monitor_clone = Arc::clone(&output_monitor);
    let stdout_thread = thread::spawn(move || {
        let mut stdout = io::stdout();
        let mut reader = from_guest_host;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let bytes = &buf[..n];
                    let _ = stdout.write_all(bytes);
                    let _ = stdout.flush();
                    output_monitor_clone.push(bytes);
                }
                Err(e) => {
                    eprintln!("Failed to read serial output: {}", e);
                    break;
                }
            }
        }
    });

    let stdin_thread = start_stdin_forwarder(input_tx.clone());

    let ns_read_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        NSFileHandle::alloc(),
        to_guest_vm.into_raw_fd(),
        true,
    );

    let ns_write_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        NSFileHandle::alloc(),
        from_guest_vm.into_raw_fd(),
        true,
    );

    let ctx = SerialContext {
        stdin_thread,
        stdout_thread,
        writer_thread,
        output_monitor,
        input_tx,
    };

    Ok((ns_read_handle, ns_write_handle, ctx))
}

fn start_stdin_forwarder(target_tx: mpsc::Sender<Vec<u8>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut input = io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match input.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if target_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
}

fn create_disk_attachment(
    path: &Path,
    read_only: bool,
) -> Result<Retained<VZDiskImageStorageDeviceAttachment>, Box<dyn std::error::Error>> {
    unsafe {
        let url = nsurl_from_path(path)?;
        VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
            VZDiskImageStorageDeviceAttachment::alloc(),
            &url,
            read_only,
            VZDiskImageCachingMode::Automatic,
            VZDiskImageSynchronizationMode::Full,
        )
        .map_err(|e| format!("Failed to attach disk {}: {:?}", path.display(), e).into())
    }
}

fn create_directory_share(
    tag: &str,
    path: &Path,
    read_only: bool,
) -> Result<Retained<VZVirtioFileSystemDeviceConfiguration>, Box<dyn std::error::Error>> {
    unsafe {
        let ns_tag = NSString::from_str(tag);
        VZVirtioFileSystemDeviceConfiguration::validateTag_error(&ns_tag).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid virtiofs tag {}: {:?}", tag, e),
            )
        })?;

        let url = nsurl_from_path(path)?;
        let shared_directory =
            VZSharedDirectory::initWithURL_readOnly(VZSharedDirectory::alloc(), &url, read_only);
        let single_share = VZSingleDirectoryShare::initWithDirectory(
            VZSingleDirectoryShare::alloc(),
            &shared_directory,
        );

        let device = VZVirtioFileSystemDeviceConfiguration::initWithTag(
            VZVirtioFileSystemDeviceConfiguration::alloc(),
            &ns_tag,
        );
        device.setShare(Some(&single_share));
        Ok(device)
    }
}

fn run_vm(
    config: (Retained<VZVirtualMachineConfiguration>, SerialContext),
    login_script: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting VM with Apple Virtualization Framework...");

    let queue = DispatchQueue::main();
    let (config, serial_ctx) = config;
    let vm = unsafe {
        VZVirtualMachine::initWithConfiguration_queue(VZVirtualMachine::alloc(), &config, queue)
    };

    let initial_state = unsafe { vm.state() };
    println!(
        "[start] canStart={} initial_state={:?}",
        unsafe { vm.canStart() },
        initial_state
    );

    let (tx, rx) = mpsc::channel::<Result<(), String>>();

    let completion_handler = RcBlock::new(move |error: *mut NSError| {
        if error.is_null() {
            let _ = tx.send(Ok(()));
        } else {
            let err = unsafe { &*error };
            let desc = err.localizedDescription();
            let _ = tx.send(Err(format!("{:?}", desc)));
        }
    });

    unsafe {
        vm.startWithCompletionHandler(&completion_handler);
    }

    let script_thread = login_script.map(|s| {
        start_script_thread(
            s,
            Arc::clone(&serial_ctx.output_monitor),
            serial_ctx.input_tx.clone(),
        )
    });

    let start_deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < start_deadline {
        unsafe {
            NSRunLoop::mainRunLoop().runMode_beforeDate(
                NSDefaultRunLoopMode,
                &NSDate::dateWithTimeIntervalSinceNow(0.1),
            )
        };

        match rx.try_recv() {
            Ok(result) => {
                result.map_err(|e| format!("Failed to start VM: {}", e))?;
                break;
            }
            Err(mpsc::TryRecvError::Empty) => continue,
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err("VM start channel disconnected".into());
            }
        }
    }

    if Instant::now() >= start_deadline {
        return Err("Timed out waiting for VM to start".into());
    }

    println!("VM started. Console attached to STDIN/STDOUT.");
    let raw_guard = enable_raw_mode(io::stdin().as_raw_fd())?;

    let mut last_state = None;
    loop {
        unsafe {
            NSRunLoop::mainRunLoop().runMode_beforeDate(
                NSDefaultRunLoopMode,
                &NSDate::dateWithTimeIntervalSinceNow(0.2),
            )
        };

        let state = unsafe { vm.state() };
        if last_state != Some(state) {
            println!("[state] {:?}", state);
            last_state = Some(state);
        }
        if state != objc2_virtualization::VZVirtualMachineState::Running {
            println!("VM stopped with state: {:?}", state);
            break;
        }
    }

    //`std::process::exit(0)` will terminate immediately, killing all threads. No destructors run.

    drop(raw_guard);
    if let Some(handle) = script_thread {
        let _ = handle.join();
    }
    dbg!("0");
    drop(serial_ctx.input_tx);
    let _ = serial_ctx.writer_thread.join();
    dbg!("1");
    let _ = serial_ctx.stdout_thread.join();
    dbg!("2");
    let _ = serial_ctx.stdin_thread.join();
    dbg!("3");
    Ok(())
}

fn nsurl_from_path(path: &Path) -> Result<Retained<NSURL>, Box<dyn std::error::Error>> {
    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let ns_path = NSString::from_str(
        abs_path
            .to_str()
            .ok_or("Non-UTF8 path encountered while building NSURL")?,
    );
    Ok(NSURL::fileURLWithPath(&ns_path))
}

fn resize_file(path: &Path, size_gb: u64) -> Result<(), Box<dyn std::error::Error>> {
    let size_bytes = size_gb * 1024 * 1024 * 1024;
    let file = fs::OpenOptions::new().write(true).open(path)?;
    file.set_len(size_bytes)?;
    Ok(())
}

fn validate_image(path: &Path, label: &str) -> bool {
    let output = Command::new("qemu-img")
        .args(["info", path.to_string_lossy().as_ref()])
        .output();
    match output {
        Ok(out) if out.status.success() => true,
        _ => {
            eprintln!("Validation failed for {} at {}", label, path.display());
            false
        }
    }
}

fn clone_sparse(src: &Path, dst: &Path) -> io::Result<()> {
    let c_src = CString::new(src.as_os_str().as_bytes())?;
    let c_dst = CString::new(dst.as_os_str().as_bytes())?;

    let rc = unsafe { libc::clonefile(c_src.as_ptr(), c_dst.as_ptr(), 0) };
    if rc == 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        fs::remove_file(dst).ok();
    }

    match fs::copy(src, dst) {
        Ok(_) => Ok(()),
        Err(copy_err) => Err(copy_err),
    }
}

fn enable_raw_mode(fd: i32) -> io::Result<RawModeGuard> {
    let mut attributes: libc::termios = unsafe { std::mem::zeroed() };

    if unsafe { libc::tcgetattr(fd, &mut attributes) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let original = attributes;

    attributes.c_iflag &= !(libc::ICRNL as libc::tcflag_t);
    attributes.c_lflag &= !((libc::ICANON | libc::ECHO) as libc::tcflag_t);

    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &attributes) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(RawModeGuard { fd, original })
}

struct RawModeGuard {
    fd: i32,
    original: libc::termios,
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}
