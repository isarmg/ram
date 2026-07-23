#![forbid(unsafe_code)]

//! Ram 可执行程序的最薄入口。
//!
//! 参数解析、配置合并、运行时构建、监听器启动和优雅关停都由库入口
//! [`ram_fileserver::run`] 统一实现。二进制层不重复任何启动逻辑，保证通过
//! `cargo run`、发布制品或嵌入式库测试启动时使用同一条经过验证的路径。
//!
//! Minimal executable entry point for Ram. Argument parsing, configuration
//! merging, runtime construction, listener startup, and graceful shutdown all
//! live in [`ram_fileserver::run`]. Keeping the binary as a thin adapter makes
//! `cargo run`, packaged binaries, and library-driven tests exercise the same
//! validated startup path.

fn main() -> anyhow::Result<()> {
    ram_fileserver::run()
}
