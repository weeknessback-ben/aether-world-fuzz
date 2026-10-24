//! The native execution backend.
//!
//! Two execution modes, selected per target:
//!
//! * **Fork server.** The target is exec'd once; its AETHER runtime then forks
//!   a fresh child per test case on request. This skips `execve` and the
//!   dynamic loader on every run, which is where most of the per-execution
//!   cost of a naive fuzzer goes.
//! * **Plain exec.** One `execve` per run. Slower, but it works for targets
//!   that take their input as a path argument and for binaries with no AETHER
//!   runtime linked in.
//!
//! The fork server is attempted first when configured and falls back to plain
//! exec if the handshake does not complete, so a target built without the
//! runtime still runs - it just runs more slowly.
//!
//! Input and output are delivered through files rather than pipes. The engine
//! keeps its own descriptor for each file; the child holds a `dup` of it, so
//! the two share one file *description* and therefore one offset. Rewinding
//! and truncating on the engine side before signalling a fork is what makes a
//! single pre-exec'd child see fresh input on every round.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::limits::{LimitReport, ProcessLimits};
use super::shm::{self, CoverageShm};
use super::{classify, ExecOutcome, Executor, ExecutorCapabilities};
use crate::config::{InputMode, Instrumentation, TargetConfig};
use crate::error::{Error, Result};
use crate::scope::{ScopePolicy, ScopeRequest};

/// Fork server control/status descriptors in the child. Must match
/// `AETHER_FORKSRV_CTL_FD` / `AETHER_FORKSRV_ST_FD` in `runtime/aether_rt.h`.
const FORKSRV_CTL_FD: RawFd = 198;
const FORKSRV_ST_FD: RawFd = 199;
/// Handshake word, `"AETH"`.
const FS_HELLO: u32 = 0x4145_5448;
/// How long to wait for the handshake before falling back to plain exec.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(2000);
/// Headroom added to a target's own deadline when waiting for the fork
/// server's status word, so a timeout is attributed to the target rather than
/// to a slow pipe.
const STATUS_GRACE: Duration = Duration::from_millis(500);

/// Everything the executor needs about one target, resolved and validated.
#[derive(Debug, Clone)]
pub struct TargetSpec {
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub working_dir: Option<PathBuf>,
    pub input_mode: InputMode,
    pub timeout: Duration,
    pub limits: ProcessLimits,
    pub instrumented: bool,
    pub use_fork_server: bool,
    pub cmplog: bool,
    pub max_log_bytes: usize,
    /// True when the binary links a sanitizer runtime. Changes how memory is
    /// bounded, because a sanitizer's shadow mapping is incompatible with
    /// `RLIMIT_AS`.
    pub sanitizer_build: bool,
    /// Memory budget in megabytes, kept separately from `limits` so it can be
    /// handed to the sanitizer when `RLIMIT_AS` is unusable.
    pub memory_limit_mb: u64,
}

impl TargetSpec {
    /// Build a spec from configuration, checking scope and the binary itself.
    /// This is the only constructor, so there is no path to an executor that
    /// skipped the scope check.
    pub fn from_config(
        cfg: &TargetConfig,
        scope: &ScopePolicy,
        max_log_bytes: usize,
    ) -> Result<Self> {
        cfg.validate()?;

        let binary = resolve_binary(&cfg.binary)?;
        scope.authorize_target(&ScopeRequest::LocalExecution {
            binary: binary.display().to_string(),
        })?;

        let instrumented = matches!(cfg.instrumentation, Instrumentation::AetherNative);
        let sanitizer_build = detect_sanitizer_build(&binary);
        let limits = if sanitizer_build {
            ProcessLimits::for_sanitizer_build(cfg.memory_limit_mb)
        } else {
            ProcessLimits::from_config(cfg.memory_limit_mb)
        };
        Ok(TargetSpec {
            binary,
            args: cfg.args.clone(),
            env: cfg
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            working_dir: cfg.working_dir.clone(),
            input_mode: cfg.input_mode,
            timeout: Duration::from_millis(cfg.timeout_ms),
            limits,
            sanitizer_build,
            memory_limit_mb: cfg.memory_limit_mb,
            instrumented,
            // The fork server delivers input by rewinding stdin, so it is only
            // usable in stdin mode.
            use_fork_server: cfg.use_fork_server
                && instrumented
                && cfg.input_mode == InputMode::Stdin,
            cmplog: instrumented,
            max_log_bytes,
        })
    }

    /// A spec for an alternative binary (sanitizer oracle, differential peer)
    /// that keeps every other setting. Used by the evidence engine.
    pub fn with_binary(&self, binary: &Path) -> Result<Self> {
        let mut s = self.clone();
        s.binary = resolve_binary(binary)?;
        // The replacement is a different build, so its sanitizer status and
        // therefore its memory-limit strategy must be re-detected.
        s.sanitizer_build = detect_sanitizer_build(&s.binary);
        s.limits = if s.sanitizer_build {
            ProcessLimits::for_sanitizer_build(s.memory_limit_mb)
        } else {
            ProcessLimits::from_config(s.memory_limit_mb)
        };
        Ok(s)
    }
}

/// Resolve and check a target binary before anything tries to run it.
fn resolve_binary(path: &Path) -> Result<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| Error::io(path, e))?
            .join(path)
    };
    let meta = std::fs::metadata(&abs).map_err(|_| {
        Error::target(
            "binary",
            format!("{} does not exist or is not readable", abs.display()),
        )
    })?;
    if !meta.is_file() {
        return Err(Error::target(
            "binary",
            format!("{} is not a file", abs.display()),
        ));
    }
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o111 == 0 {
        return Err(Error::target(
            "binary",
            format!("{} is not executable", abs.display()),
        ));
    }
    Ok(abs)
}

/// Does this binary link a sanitizer runtime?
///
/// Detected by looking for the runtime's init symbols in the file's bytes.
/// A dynamically linked sanitizer build names `libasan.so` in its dynamic
/// section; a statically linked one carries `__asan_init` directly. Reading
/// the file is enough - there is no need to run it, which matters because
/// this decides how the very first run is bounded.
fn detect_sanitizer_build(path: &Path) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"__asan_init",
        b"libasan.so",
        b"__ubsan_handle",
        b"libubsan.so",
        b"__msan_init",
        b"__tsan_init",
    ];
    // Sanitizer markers live in the dynamic/symbol tables; a few megabytes is
    // ample, and capping the read keeps this cheap for a large binary.
    const MAX_SCAN: usize = 8 * 1024 * 1024;
    let Ok(f) = File::open(path) else {
        return false;
    };
    let mut buf = Vec::new();
    if Read::take(f, MAX_SCAN as u64)
        .read_to_end(&mut buf)
        .is_err()
    {
        return false;
    }
    NEEDLES.iter().any(|n| contains_subslice(&buf, n))
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// State of a live fork server.
struct ForkServer {
    child: Child,
    ctl_write: File,
    st_read: File,
}

impl ForkServer {
    /// Ask for a fork and read back the child's pid.
    fn request_fork(&mut self) -> Result<i32> {
        self.ctl_write
            .write_all(&0u32.to_ne_bytes())
            .map_err(|e| Error::exec("fork server", format!("control pipe write failed: {e}")))?;
        let mut buf = [0u8; 4];
        read_exact_timeout(self.st_read.as_raw_fd(), &mut buf, HANDSHAKE_TIMEOUT)
            .map_err(|e| Error::exec("fork server", format!("no child pid reported: {e}")))?;
        Ok(i32::from_ne_bytes(buf))
    }

    /// Read the wait status, with a deadline. Returns `None` on timeout, in
    /// which case the caller kills the child and reads again.
    fn read_status(&mut self, timeout: Duration) -> Result<Option<i32>> {
        let mut buf = [0u8; 4];
        match read_exact_timeout(self.st_read.as_raw_fd(), &mut buf, timeout) {
            Ok(()) => Ok(Some(i32::from_ne_bytes(buf))),
            Err(ReadTimeout::TimedOut) => Ok(None),
            Err(ReadTimeout::Failed(e)) => Err(Error::exec(
                "fork server",
                format!("status pipe read failed: {e}"),
            )),
        }
    }
}

impl Drop for ForkServer {
    fn drop(&mut self) {
        // Closing the control pipe makes the fork server exit its loop.
        let _ = self.ctl_write.write_all(&[]);
        let pid = self.child.id() as i32;
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let _ = self.child.wait();
    }
}

/// The native backend.
pub struct NativeExecutor {
    spec: TargetSpec,
    shm: Option<CoverageShm>,
    caps: ExecutorCapabilities,
    limit_report: LimitReport,

    /// Backing file for the test case, shared with the child.
    input_file: File,
    input_path: PathBuf,
    /// Captured stdout/stderr, shared with the child in fork-server mode.
    out_file: File,
    out_path: PathBuf,
    err_file: File,
    err_path: PathBuf,

    fork_server: Option<ForkServer>,
    /// Set once the fork server has failed, so we stop retrying it.
    fork_server_unavailable: bool,
    exec_count: u64,
    scratch: PathBuf,
}

impl NativeExecutor {
    pub fn new(spec: TargetSpec, scratch_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(scratch_dir).map_err(|e| Error::io(scratch_dir, e))?;

        let tag = format!("{}-{}", std::process::id(), crate::ids::mint_suffix());
        let input_path = scratch_dir.join(format!("input-{tag}.bin"));
        let out_path = scratch_dir.join(format!("stdout-{tag}.log"));
        let err_path = scratch_dir.join(format!("stderr-{tag}.log"));

        let input_file = new_rw_file(&input_path)?;
        let out_file = new_rw_file(&out_path)?;
        let err_file = new_rw_file(&err_path)?;

        let shm = if spec.instrumented {
            Some(CoverageShm::create(&format!("cov-{tag}"))?)
        } else {
            None
        };

        let mut limit_report = spec.limits.probe();
        if spec.sanitizer_build {
            let rss = if spec.memory_limit_mb > 0 {
                spec.memory_limit_mb
            } else {
                2048
            };
            limit_report.memory_limit_substituted = Some(format!(
                "RLIMIT_AS not applied to this sanitizer build (its shadow mapping needs \
                 ~20 TiB of address space); memory bounded by ASAN_OPTIONS \
                 hard_rss_limit_mb={rss} instead"
            ));
        }
        let mut limitations = limit_report.unenforced.clone();
        if let Some(note) = &limit_report.memory_limit_substituted {
            limitations.push(note.clone());
        }
        if !spec.instrumented {
            limitations.push(
                "target is not instrumented: no edge coverage and no comparison log".to_string(),
            );
        }

        let caps = ExecutorCapabilities {
            backend: "aether-native".to_string(),
            edge_coverage: spec.instrumented,
            comparison_log: spec.instrumented && spec.cmplog,
            // Detected from a real report at classification time, not assumed.
            sanitizer_oracle: true,
            fork_server: false, // set after the handshake succeeds
            memory_limit: limit_report.memory_limit_enforced,
            limitations,
        };

        let mut exec = NativeExecutor {
            spec,
            shm,
            caps,
            limit_report,
            input_file,
            input_path,
            out_file,
            out_path,
            err_file,
            err_path,
            fork_server: None,
            fork_server_unavailable: false,
            exec_count: 0,
            scratch: scratch_dir.to_path_buf(),
        };

        if exec.spec.use_fork_server {
            match exec.start_fork_server() {
                Ok(fs) => {
                    exec.fork_server = Some(fs);
                    exec.caps.fork_server = true;
                }
                Err(e) => {
                    // Not fatal: fall back to exec-per-run and say so.
                    exec.fork_server_unavailable = true;
                    exec.caps.limitations.push(format!(
                        "fork server unavailable, falling back to exec-per-run: {e}"
                    ));
                }
            }
        }
        Ok(exec)
    }

    pub fn limit_report(&self) -> &LimitReport {
        &self.limit_report
    }

    pub fn shm_guard_count(&self) -> Option<u32> {
        self.shm.as_ref().map(|s| s.guard_count())
    }

    /// Exec the target once with the fork-server descriptors wired up and
    /// wait for its handshake word.
    fn start_fork_server(&mut self) -> Result<ForkServer> {
        let (ctl_r, ctl_w) = pipe()?;
        let (st_r, st_w) = pipe()?;

        let mut cmd = Command::new(&self.spec.binary);
        self.apply_common_command_setup(&mut cmd)?;
        cmd.env("AETHER_FORKSRV", "1");

        cmd.stdin(Stdio::from(self.input_file.try_clone()?));
        cmd.stdout(Stdio::from(self.out_file.try_clone()?));
        cmd.stderr(Stdio::from(self.err_file.try_clone()?));

        let limits = self.spec.limits;
        // Runs in the child between fork and exec: async-signal-safe only.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(ctl_r, FORKSRV_CTL_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(st_w, FORKSRV_ST_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // The duplicates must survive exec.
                libc::fcntl(FORKSRV_CTL_FD, libc::F_SETFD, 0);
                libc::fcntl(FORKSRV_ST_FD, libc::F_SETFD, 0);
                libc::close(ctl_r);
                libc::close(ctl_w);
                libc::close(st_r);
                libc::close(st_w);
                limits.apply_in_child();
                Ok(())
            });
        }

        let child = cmd.spawn().map_err(|e| {
            Error::exec(
                "fork server",
                format!("could not start {}: {e}", self.spec.binary.display()),
            )
        })?;

        // Close the child's ends so a dead fork server shows up as EOF here
        // rather than as an indefinite block.
        close_fd(ctl_r);
        close_fd(st_w);

        let ctl_write = unsafe { File::from_raw_fd(ctl_w) };
        let st_read = unsafe { File::from_raw_fd(st_r) };
        #[allow(unused_mut)]
        let mut fs = ForkServer {
            child,
            ctl_write,
            st_read,
        };

        let mut hello = [0u8; 4];
        match read_exact_timeout(fs.st_read.as_raw_fd(), &mut hello, HANDSHAKE_TIMEOUT) {
            Ok(()) => {}
            Err(e) => {
                return Err(Error::exec(
                    "fork server",
                    format!(
                        "no handshake from {} ({e}); the binary is probably not linked \
                         against the AETHER runtime",
                        self.spec.binary.display()
                    ),
                ))
            }
        }
        let word = u32::from_ne_bytes(hello);
        if word != FS_HELLO {
            return Err(Error::exec(
                "fork server",
                format!("handshake word {word:#x} != expected {FS_HELLO:#x}"),
            ));
        }
        Ok(fs)
    }

    /// Environment, arguments and working directory shared by both modes.
    ///
    /// `env_clear` is deliberate: the target sees only what AETHER chose, so a
    /// variable in the operator's shell cannot silently change what is tested.
    fn apply_common_command_setup(&self, cmd: &mut Command) -> Result<()> {
        cmd.env_clear();
        // A minimal, predictable environment. No PATH: the binary is already
        // resolved to an absolute path, and a target that needs PATH to find a
        // helper should be given it explicitly in target.env.
        cmd.env("LC_ALL", "C");
        cmd.env("LANG", "C");
        for (k, v) in &self.spec.env {
            cmd.env(k, v);
        }
        // Sanitizer options are set by the engine, never from configuration:
        // `TargetConfig::validate` refuses them in `target.env` precisely so
        // that a config file cannot disable the crash oracle. Here the engine
        // turns the oracle *up* and supplies the RSS bound that replaces the
        // address-space limit a sanitizer build cannot tolerate.
        if self.spec.sanitizer_build {
            let rss = if self.spec.memory_limit_mb > 0 {
                self.spec.memory_limit_mb
            } else {
                2048
            };
            let opts = format!(
                "abort_on_error=1:handle_segv=1:handle_abort=1:detect_leaks=0:\
                 hard_rss_limit_mb={rss}:log_to_syslog=0:exitcode=86"
            );
            cmd.env("ASAN_OPTIONS", &opts);
            cmd.env(
                "UBSAN_OPTIONS",
                "print_stacktrace=1:halt_on_error=1:exitcode=86",
            );
            cmd.env("MSAN_OPTIONS", &opts);
        }
        if let Some(shm) = &self.shm {
            cmd.env("AETHER_SHM_PATH", shm.path());
            if self.spec.cmplog {
                cmd.env("AETHER_CMPLOG", "1");
            }
        }
        if let Some(dir) = &self.spec.working_dir {
            cmd.current_dir(dir);
        } else {
            cmd.current_dir(&self.scratch);
        }
        Ok(())
    }

    /// Write the test case and rewind, so the child's shared descriptor reads
    /// it from the start.
    fn stage_input(&mut self, input: &[u8]) -> Result<()> {
        self.input_file.set_len(0)?;
        self.input_file.seek(SeekFrom::Start(0))?;
        self.input_file.write_all(input)?;
        self.input_file.flush()?;
        self.input_file.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    fn reset_logs(&mut self) -> Result<()> {
        for f in [&mut self.out_file, &mut self.err_file] {
            f.set_len(0)?;
            f.seek(SeekFrom::Start(0))?;
        }
        Ok(())
    }

    /// Read back a bounded prefix of a log file.
    ///
    /// Takes `&mut File` and seeks the engine's own handle rather than
    /// duplicating one per call: at a few thousand executions a second the
    /// extra `dup` and `close` per run are measurable. The empty-log case is
    /// short-circuited because most executions produce no output at all.
    fn read_log(f: &mut File, max_bytes: usize) -> Result<(Vec<u8>, bool)> {
        let len = f.metadata()?.len();
        if len == 0 {
            return Ok((Vec::new(), false));
        }
        f.seek(SeekFrom::Start(0))?;
        let cap = max_bytes as u64;
        let mut buf = Vec::with_capacity(len.min(cap) as usize);
        let n = Read::take(&mut *f, cap).read_to_end(&mut buf)?;
        let _ = n;
        Ok((buf, len > cap))
    }

    fn collect_coverage(&self) -> (Option<Box<[u8; shm::MAP_SIZE]>>, Vec<shm::CmpEntry>, bool) {
        match &self.shm {
            None => (None, Vec::new(), false),
            Some(shm) => {
                let mut map = Box::new([0u8; shm::MAP_SIZE]);
                shm.snapshot_classified(&mut map);
                let cmps = if self.spec.cmplog {
                    shm.read_cmp_entries(shm::CMP_CAP)
                } else {
                    Vec::new()
                };
                (Some(map), cmps, shm.cmplog_overflowed())
            }
        }
    }

    fn run_with_fork_server(&mut self, input: &[u8]) -> Result<ExecOutcome> {
        self.stage_input(input)?;
        self.reset_logs()?;
        if let Some(shm) = &self.shm {
            shm.reset();
        }

        let start = Instant::now();
        let fs = self.fork_server.as_mut().expect("caller checked");
        let pid = fs.request_fork()?;

        let mut timed_out = false;
        let status = match fs.read_status(self.spec.timeout + STATUS_GRACE)? {
            Some(s) => s,
            None => {
                // Deadline passed. The runtime puts each run in its own
                // process group, so signalling the group reaps anything the
                // target spawned; then the pending status word still arrives,
                // which keeps the protocol in lockstep.
                timed_out = true;
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                    libc::kill(pid, libc::SIGKILL);
                }
                match fs.read_status(HANDSHAKE_TIMEOUT)? {
                    Some(s) => s,
                    None => {
                        // The fork server is wedged; drop it and fall back.
                        self.fork_server = None;
                        self.fork_server_unavailable = true;
                        self.caps.fork_server = false;
                        self.caps.limitations.push(
                            "fork server stopped responding after a timeout; \
                             continuing with exec-per-run"
                                .to_string(),
                        );
                        return self.run_with_exec(input);
                    }
                }
            }
        };
        let duration = start.elapsed();

        self.finish(status, timed_out, duration)
    }

    fn run_with_exec(&mut self, input: &[u8]) -> Result<ExecOutcome> {
        self.stage_input(input)?;
        self.reset_logs()?;
        if let Some(shm) = &self.shm {
            shm.reset();
        }

        let mut cmd = Command::new(&self.spec.binary);
        self.apply_common_command_setup(&mut cmd)?;

        // Argument vector, with @@ replaced by the test case path in file-arg
        // mode. Arguments are passed as a vector, never interpolated into a
        // shell string, so a mutated byte can never become a metacharacter.
        let input_path = self.input_path.display().to_string();
        let args: Vec<String> = self
            .spec
            .args
            .iter()
            .map(|a| a.replace("@@", &input_path))
            .collect();
        cmd.args(&args);

        match self.spec.input_mode {
            InputMode::Stdin => {
                cmd.stdin(Stdio::from(self.input_file.try_clone()?));
            }
            InputMode::FileArg => {
                cmd.stdin(Stdio::null());
            }
        }
        cmd.stdout(Stdio::from(self.out_file.try_clone()?));
        cmd.stderr(Stdio::from(self.err_file.try_clone()?));

        let limits = self.spec.limits;
        unsafe {
            cmd.pre_exec(move || {
                limits.apply_in_child();
                Ok(())
            });
        }

        let start = Instant::now();
        let mut child = cmd.spawn().map_err(|e| {
            Error::exec(
                "exec",
                format!("could not start {}: {e}", self.spec.binary.display()),
            )
        })?;
        let pid = child.id() as i32;

        let (status, timed_out) = wait_with_deadline(&mut child, pid, self.spec.timeout)?;
        let duration = start.elapsed();
        self.finish(status, timed_out, duration)
    }

    /// Shared tail of both modes: gather outputs, classify, package.
    fn finish(&mut self, status: i32, timed_out: bool, duration: Duration) -> Result<ExecOutcome> {
        self.exec_count += 1;

        let max_log = self.spec.max_log_bytes;
        let (stdout, stdout_truncated) = Self::read_log(&mut self.out_file, max_log)?;
        let (stderr, stderr_truncated) = Self::read_log(&mut self.err_file, max_log)?;
        let (coverage, cmp_entries, cmp_overflowed) = self.collect_coverage();

        // Only stderr is offered to the sanitizer oracle: a report on stdout
        // is target output, not evidence.
        let (class, exit_code, signal, sanitizer) = classify(status, timed_out, false, &stderr);

        Ok(ExecOutcome {
            class,
            exit_code,
            signal,
            duration,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            sanitizer,
            coverage,
            cmp_entries,
            cmp_overflowed,
        })
    }
}

impl Executor for NativeExecutor {
    fn run(&mut self, input: &[u8]) -> Result<ExecOutcome> {
        if self.fork_server.is_some() {
            self.run_with_fork_server(input)
        } else {
            self.run_with_exec(input)
        }
    }

    fn capabilities(&self) -> &ExecutorCapabilities {
        &self.caps
    }

    fn exec_count(&self) -> u64 {
        self.exec_count
    }

    fn reset(&mut self) -> Result<()> {
        // Dropping tears down the fork server; restart it if it was in use.
        let had = self.fork_server.is_some();
        self.fork_server = None;
        if had && !self.fork_server_unavailable {
            self.fork_server = Some(self.start_fork_server()?);
        }
        Ok(())
    }
}

impl Drop for NativeExecutor {
    fn drop(&mut self) {
        self.fork_server = None; // kill the server before removing its files
        for p in [&self.input_path, &self.out_path, &self.err_path] {
            let _ = std::fs::remove_file(p);
        }
    }
}

// --- low level helpers ----------------------------------------------------

fn new_rw_file(path: &Path) -> Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| Error::io(path, e))
}

fn pipe() -> Result<(RawFd, RawFd)> {
    let mut fds = [0 as libc::c_int; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(Error::exec(
            "pipe",
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok((fds[0], fds[1]))
}

fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

#[derive(Debug)]
enum ReadTimeout {
    TimedOut,
    Failed(String),
}

impl std::fmt::Display for ReadTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadTimeout::TimedOut => write!(f, "timed out"),
            ReadTimeout::Failed(m) => write!(f, "{m}"),
        }
    }
}

/// Read exactly `buf.len()` bytes, or give up after `timeout`.
fn read_exact_timeout(
    fd: RawFd,
    buf: &mut [u8],
    timeout: Duration,
) -> std::result::Result<(), ReadTimeout> {
    let deadline = Instant::now() + timeout;
    let mut filled = 0;
    while filled < buf.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ReadTimeout::TimedOut);
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(ReadTimeout::Failed(e.to_string()));
        }
        if rc == 0 {
            return Err(ReadTimeout::TimedOut);
        }
        let n = unsafe {
            libc::read(
                fd,
                buf[filled..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - filled,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(ReadTimeout::Failed(e.to_string()));
        }
        if n == 0 {
            return Err(ReadTimeout::Failed("pipe closed by peer".to_string()));
        }
        filled += n as usize;
    }
    Ok(())
}

/// Wait for a child, SIGKILLing its process group once the deadline passes.
fn wait_with_deadline(child: &mut Child, pid: i32, timeout: Duration) -> Result<(i32, bool)> {
    let deadline = Instant::now() + timeout;
    // Poll rather than block: `waitpid` has no timeout, and a dedicated
    // reaper thread per execution would cost more than this at the rates a
    // fuzzing loop runs at. The sleep is capped so a fast target is not
    // delayed by more than a fraction of a millisecond.
    let mut backoff = Duration::from_micros(50);
    loop {
        let mut status: libc::c_int = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            return Ok((status, false));
        }
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::exec("waitpid", e.to_string()));
        }
        if Instant::now() >= deadline {
            // Signal the group first so grandchildren go too, then the child.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
            let mut status: libc::c_int = 0;
            // Blocking wait now: the process is dead or about to be.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            let _ = child;
            return Ok((status, true));
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_millis(1));
    }
}

/// Reap any child that the engine has lost track of, so a campaign cannot
/// accumulate zombies over a long run.
pub fn reap_orphans() {
    loop {
        let mut status: libc::c_int = 0;
        let rc = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if rc <= 0 {
            break;
        }
    }
}

/// Keep `IntoRawFd` referenced; used by callers constructing specs from fds.
#[allow(dead_code)]
fn _assert_traits<T: IntoRawFd>() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_is_reported_clearly() {
        let e = resolve_binary(Path::new("/nonexistent/aether-test-binary")).unwrap_err();
        assert_eq!(e.kind(), "target_invalid");
        assert!(e.to_string().contains("does not exist"), "{e}");
    }

    #[test]
    fn non_executable_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("aether-t-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("not-exec");
        std::fs::write(&p, b"x").unwrap();
        let e = resolve_binary(&p).unwrap_err();
        assert!(e.to_string().contains("not executable"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn directory_is_refused() {
        let e = resolve_binary(Path::new("/tmp")).unwrap_err();
        assert!(e.to_string().contains("not a file"), "{e}");
    }

    #[test]
    fn read_timeout_actually_times_out() {
        let (r, w) = pipe().unwrap();
        let mut buf = [0u8; 4];
        let t = Instant::now();
        let res = read_exact_timeout(r, &mut buf, Duration::from_millis(50));
        assert!(matches!(res, Err(ReadTimeout::TimedOut)));
        assert!(t.elapsed() >= Duration::from_millis(40));
        close_fd(r);
        close_fd(w);
    }

    #[test]
    fn read_timeout_detects_a_closed_peer() {
        let (r, w) = pipe().unwrap();
        close_fd(w);
        let mut buf = [0u8; 4];
        let res = read_exact_timeout(r, &mut buf, Duration::from_millis(500));
        match res {
            Err(ReadTimeout::Failed(m)) => assert!(m.contains("closed"), "{m}"),
            other => panic!("expected a closed-peer error, got {:?}", other.is_ok()),
        }
        close_fd(r);
    }

    #[test]
    fn read_timeout_reads_a_full_word() {
        let (r, w) = pipe().unwrap();
        let word = FS_HELLO.to_ne_bytes();
        unsafe {
            libc::write(w, word.as_ptr() as *const libc::c_void, 4);
        }
        let mut buf = [0u8; 4];
        read_exact_timeout(r, &mut buf, Duration::from_millis(500)).unwrap();
        assert_eq!(u32::from_ne_bytes(buf), FS_HELLO);
        close_fd(r);
        close_fd(w);
    }
}
