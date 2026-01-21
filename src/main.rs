use std::env;

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::{
    NSArray, NSDate, NSDefaultRunLoopMode, NSError, NSFileHandle, NSRunLoop, NSString, NSUInteger,
    NSURL,
};
use objc2_virtualization::{
    VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment, VZDiskImageSynchronizationMode,
    VZEFIBootLoader, VZEFIVariableStore, VZEFIVariableStoreInitializationOptions,
    VZFileHandleSerialPortAttachment, VZGenericPlatformConfiguration, VZNATNetworkDeviceAttachment,
    VZSharedDirectory, VZSingleDirectoryShare, VZVirtioBlockDeviceConfiguration,
    VZVirtioConsoleDeviceSerialPortConfiguration, VZVirtioEntropyDeviceConfiguration,
    VZVirtioFileSystemDeviceConfiguration, VZVirtioNetworkDeviceConfiguration, VZVirtualMachine,
    VZVirtualMachineConfiguration,
};

const DEBIAN_DISK_URL: &str =
    "https://cloud.debian.org/images/cloud/trixie/20260112-2355/debian-13-nocloud-arm64-20260112-2355.tar.xz";
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
    base_compressed: PathBuf,
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
        let cache_dir = cache_home.join("vibe");
        let guest_mise_cache = cache_dir.join(".guest-mise-cache");
        let instance_dir = project_root.join(".vibe");

        let basename_compressed = DEBIAN_DISK_URL.rsplit('/').next().unwrap();
        let base_compressed = cache_dir.join(basename_compressed);

        let basename = basename_compressed.trim_end_matches(".tar.xz");
        let base_raw = cache_dir.join(format!("{}.raw", basename));

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
            base_compressed,
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

#[derive(Default)]
pub struct OutputMonitor {
    buffer: Mutex<String>,
    condvar: Condvar,
}

impl OutputMonitor {
    fn new() -> Self {
        Default::default()
    }

    fn push(&self, bytes: &[u8]) {
        self.buffer
            .lock()
            .unwrap()
            .push_str(&String::from_utf8_lossy(bytes));
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

pub enum VmInput {
    Bytes(Vec<u8>),
    Shutdown,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths = VmPaths::new()?;

    prepare_directories(&paths)?;
    ensure_base_image(&paths)?;
    ensure_configured_base(&paths)?;
    ensure_instance_disk(&paths)?;

    run_vm(
        &paths,
        &paths.instance_raw,
        vec![
            LoginActions::WaitFor("login: ".to_string()),
            LoginActions::Type("root\n".to_string()),
        ],
    )
}

fn prepare_directories(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(&paths.cache_dir)?;
    fs::create_dir_all(&paths.guest_mise_cache)?;
    fs::create_dir_all(&paths.instance_dir)?;
    fs::create_dir_all(&paths.cargo_registry)?;
    Ok(())
}

fn ensure_base_image(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    if paths.base_raw.exists() {
        println!("Using configured image at {}", paths.base_raw.display());
        return Ok(());
    }

    println!("Downloading Debian base image...");
    let status = Command::new("curl")
        .args([
            "--compressed",
            "--location",
            "--fail",
            "-o",
            &paths.base_compressed.to_string_lossy(),
            DEBIAN_DISK_URL,
        ])
        .status()?;

    if !status.success() {
        return Err("Failed to download Debian base image".into());
    }

    println!("Decompressing Debian base image...");
    let status = Command::new("tar")
        .args(["-xOf", &paths.base_compressed.to_string_lossy(), "disk.raw"])
        .stdout(std::fs::File::create(&paths.base_raw).unwrap())
        .status()?;

    if !status.success() {
        return Err("Failed to decompress Debian base image".into());
    }

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
    fs::copy(&paths.base_raw, &paths.configured_raw)?;
    resize(&paths.configured_raw, DISK_SIZE_GB)?;

    run_vm(
        paths,
        &paths.configured_raw,
        vec![
            LoginActions::WaitFor("login: ".to_string()),
            LoginActions::Type("root\n".to_string()),
            LoginActions::WaitFor("~#".to_string()),
            LoginActions::Type({
                let path = "provision.sh";
                let script = PROVISION_SCRIPT;
                format!("cat >{path} <<'PROVISIONING_EOF'\n{script}PROVISIONING_EOF\nsh {path}\n")
            }),
        ],
    )?;

    Ok(())
}

fn ensure_instance_disk(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    if paths.instance_raw.exists() {
        return Ok(());
    }

    println!("Creating instance disk from configured base image...");
    fs::copy(&paths.configured_raw, &paths.instance_raw)?;
    resize(&paths.instance_raw, DISK_SIZE_GB)?;
    Ok(())
}

pub struct IoContext {
    pub input_tx: Sender<VmInput>,
    shutdown_flag: Arc<AtomicBool>,
    wakeup_write: OwnedFd,
    stdin_thread: thread::JoinHandle<()>,
    mux_thread: thread::JoinHandle<()>,
    stdout_thread: thread::JoinHandle<()>,
}

pub fn create_pipe() -> (OwnedFd, OwnedFd) {
    let (read_stream, write_stream) = UnixStream::pair().expect("Failed to create socket pair");
    (read_stream.into(), write_stream.into())
}

pub fn spawn_vm_io(
    output_monitor: Arc<OutputMonitor>,
    vm_output_fd: OwnedFd,
    vm_input_fd: OwnedFd,
) -> IoContext {
    let (input_tx, input_rx): (Sender<VmInput>, Receiver<VmInput>) = mpsc::channel();
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let flag_clone = shutdown_flag.clone();

    let (wakeup_read, wakeup_write) = create_pipe();

    // Copies from stdin to the VM; uses poll so we can break the loop and exit the thread when it's time to shutdown.
    let stdin_thread = thread::spawn({
        let input_tx = input_tx.clone();
        move || {
            let stdin_fd = libc::STDIN_FILENO;
            let mut buf = [0u8; 64];

            loop {
                let mut fds = [
                    libc::pollfd {
                        fd: stdin_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: wakeup_read.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];

                let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
                if ret <= 0 {
                    break;
                }

                if fds[1].revents & libc::POLLIN != 0 {
                    break;
                }

                if fds[0].revents & libc::POLLIN != 0 {
                    let n = unsafe { libc::read(stdin_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                    if n <= 0 {
                        break;
                    }
                    if flag_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    if input_tx
                        .send(VmInput::Bytes(buf[..n as usize].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    let mux_thread = thread::spawn(move || {
        let mut vm_writer = std::fs::File::from(vm_input_fd);
        loop {
            match input_rx.recv() {
                Ok(VmInput::Bytes(data)) => {
                    if vm_writer.write_all(&data).is_err() {
                        break;
                    }
                }
                Ok(VmInput::Shutdown) => break,
                Err(_) => break,
            }
        }
    });

    let stdout_thread = thread::spawn(move || {
        let mut vm_reader = std::fs::File::from(vm_output_fd);

        let mut buf = [0u8; 1024];
        loop {
            match vm_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    // TODO: Ideally, we could lock for the entire lifetime of the thread, but I'm not sure how to interrupt the thread because the virtualization framework doesn't close the file descriptor when the VM shuts down.
                    // so we'll just leak this thread =(
                    let mut stdout = std::io::stdout().lock();
                    let bytes = &buf[..n];
                    if stdout.write_all(bytes).is_err() {
                        break;
                    }
                    let _ = stdout.flush();
                    output_monitor.push(bytes);
                }
                Err(_) => break,
            }
        }
    });

    IoContext {
        input_tx,
        shutdown_flag,
        wakeup_write,
        stdin_thread,
        mux_thread,
        stdout_thread,
    }
}

impl IoContext {
    pub fn shutdown(self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        let _ = self.input_tx.send(VmInput::Shutdown);
        unsafe { libc::write(self.wakeup_write.as_raw_fd(), b"x".as_ptr() as *const _, 1) };
        let _ = self.stdin_thread.join();
        let _ = self.mux_thread.join();

        // Leak this thread because I can't figure out how to interrupt it.
        drop(self.stdout_thread);
    }
}

fn create_vm_configuration(
    paths: &VmPaths,
    disk_path: &Path,
    vm_reads_from_fd: OwnedFd,
    vm_writes_to_fd: OwnedFd,
) -> Result<Retained<VZVirtualMachineConfiguration>, Box<dyn std::error::Error>> {
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

        let ns_read_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
            NSFileHandle::alloc(),
            vm_reads_from_fd.into_raw_fd(),
            true,
        );

        let ns_write_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
            NSFileHandle::alloc(),
            vm_writes_to_fd.into_raw_fd(),
            true,
        );

        let serial_attach =
            VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                VZFileHandleSerialPortAttachment::alloc(),
                Some(&ns_read_handle),
                Some(&ns_write_handle),
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

        Ok(config)
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

fn spawn_login_actions_thread(
    login_actions: Vec<LoginActions>,
    output_monitor: Arc<OutputMonitor>,
    input_tx: mpsc::Sender<VmInput>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for a in login_actions {
            match a {
                LoginActions::WaitFor(text) => {
                    if WaitResult::Timeout
                        == output_monitor.wait_for(&text, Duration::from_secs(120))
                    {
                        eprintln!("Login action timed out waiting for '{}'", &text);
                        return;
                    }
                }
                LoginActions::Type(text) => {
                    input_tx
                        .send(VmInput::Bytes(text.into_bytes().to_vec()))
                        .unwrap();
                }
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

enum LoginActions {
    WaitFor(String),
    Type(String),
}

fn run_vm(
    paths: &VmPaths,
    disk_path: &Path,
    login_actions: Vec<LoginActions>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (vm_reads_from, we_write_to) = create_pipe();
    let (we_read_from, vm_writes_to) = create_pipe();

    let config = create_vm_configuration(paths, disk_path, vm_reads_from, vm_writes_to)?;

    println!("Starting VM");

    let queue = DispatchQueue::main();

    let vm = unsafe {
        VZVirtualMachine::initWithConfiguration_queue(VZVirtualMachine::alloc(), &config, queue)
    };

    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    let completion_handler = RcBlock::new(move |error: *mut NSError| {
        if error.is_null() {
            let _ = tx.send(Ok(()));
        } else {
            let err = unsafe { &*error };
            let _ = tx.send(Err(format!("{:?}", err.localizedDescription())));
        }
    });

    unsafe {
        vm.startWithCompletionHandler(&completion_handler);
    }

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

    println!("VM started, attaching console to STDIN/STDOUT.");

    let output_monitor = Arc::new(OutputMonitor::new());
    let io_ctx = spawn_vm_io(output_monitor.clone(), we_read_from, we_write_to);

    let login_actions_thread = spawn_login_actions_thread(
        login_actions,
        output_monitor.clone(),
        io_ctx.input_tx.clone(),
    );

    let _raw_guard = enable_raw_mode(io::stdin().as_raw_fd())?;

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
            //eprintln!("[state] {:?}", state);
            last_state = Some(state);
        }
        if state != objc2_virtualization::VZVirtualMachineState::Running {
            //eprintln!("VM stopped with state: {:?}", state);
            break;
        }
    }

    let _ = login_actions_thread.join();

    io_ctx.shutdown();

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

fn resize(path: &Path, size_gb: u64) -> Result<(), Box<dyn std::error::Error>> {
    let size_bytes = size_gb * 1024 * 1024 * 1024;
    let file = fs::OpenOptions::new().write(true).open(path)?;
    file.set_len(size_bytes)?;
    Ok(())
}

fn enable_raw_mode(fd: i32) -> io::Result<RawModeGuard> {
    let mut attributes: libc::termios = unsafe { std::mem::zeroed() };

    if unsafe { libc::tcgetattr(fd, &mut attributes) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let original = attributes;

    // Disable translation of carriage return to newline on input
    attributes.c_iflag &= !(libc::ICRNL);
    // Disable canonical mode (line buffering), echo, and signal generation
    attributes.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
    attributes.c_cc[libc::VMIN] = 0;
    attributes.c_cc[libc::VTIME] = 1;

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
