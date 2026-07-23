//! 视图/序列化数据类型：目录列表、编辑器页面、WebDAV `PROPFIND` 响应
//! 所用的"纯数据"结构。它们只负责承载数据和格式化输出，
//! 不依赖请求处理器的任何状态——这是"数据与逻辑分离"的典型做法。
//!
//! ## 本模块的 Rust 知识点
//! - **`derive` 派生宏**：`#[derive(Serialize)]` 让 serde 自动生成
//!   "结构体 → JSON"的代码；`PartialEq`/`Eq`/`Ord` 等比较能力也由派生实现。
//! - **手动实现 `Ord`**：`PathType` 的排序规则是"目录永远排在文件前面"，
//!   与派生的默认字典序不同，所以手写 `impl Ord`。
//! - **枚举建模**：文件系统条目只有四种形态（目录/符号链接目录/文件/符号
//!   链接文件），用枚举穷举，`match` 时编译器会强制处理所有情况。
//!
//! View/serialization data types: state-free structures used by directory listings, editor pages,
//! and WebDAV `PROPFIND` responses. They carry and format data without depending on handler state,
//! which is the usual separation of data from logic.
//!
//! ## Rust concepts in this module
//! - **`derive` macros**: `#[derive(Serialize)]` lets serde generate structure-to-JSON code;
//!   comparison traits such as `PartialEq`, `Eq`, and `Ord` can likewise be derived.
//! - **Manual `Ord` implementation**: `PathType` must sort every directory before every file rather
//!   than use the derived lexical order, so its `impl Ord` is handwritten.
//! - **Enum modeling**: a filesystem entry has exactly four forms (directory, symlinked directory,
//!   file, or symlinked file). Encoding them in an enum makes the compiler require every `match` to
//!   handle all forms.

use serde::Serialize;
use std::cmp::Ordering;

/// 告诉前端渲染哪种页面的嵌入标记。 / Embedded marker selecting the frontend page kind.
#[derive(Debug, Serialize, PartialEq)]
pub enum DataKind {
    /// 目录列表页。 / Directory listing page.
    Index,
    /// 文件编辑页。 / File editor page.
    Edit,
    /// 文件只读查看页。 / Read-only file viewer page.
    View,
}

/// 目录列表页的完整数据：会被序列化成 JSON、base64 编码后嵌入 HTML，
/// 由前端 index.js 解码渲染。字段对应界面上的各种开关和列表内容。
/// Complete directory-page data, serialized as base64(JSON) for `index.js`.
#[derive(Debug, Serialize)]
pub struct IndexData {
    pub href: String,
    pub kind: DataKind,
    pub uri_prefix: String,
    pub allow_upload: bool,
    pub allow_delete: bool,
    pub allow_search: bool,
    pub allow_archive: bool,
    pub dir_exists: bool,
    pub user: Option<String>,
    /// 是否因服务端条目上限截断。 / Whether the server entry limit truncated the result.
    pub truncated: bool,
    /// 是否因 HTTP/JSON 无法无损表示 Linux 原始文件名字节而省略条目。
    /// Whether entries were omitted because HTTP/JSON cannot losslessly represent raw Linux filename bytes.
    pub omitted_non_utf8: bool,
    /// 仅当整个目录扫描未与任何进程内变更事务重叠时签发。浏览器把它作为 DELETE/MOVE
    /// 的乐观条件；`None` 表示安全性不足，应让界面刷新而不是猜测。
    /// Issued only when the complete scan did not overlap any process-local mutation transaction.
    /// Browsers use it as a DELETE/MOVE optimistic condition; `None` means refresh rather than guess.
    pub mutation_version: Option<String>,
    pub paths: Vec<PathItem>,
}

/// 目录列表中的单个文件或子目录。 / One file or subdirectory in a listing.
#[derive(Debug, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct PathItem {
    pub path_type: PathType,
    /// 相对于列表根的路径；多层搜索可带 `/`。 / Path relative to the listing root; search results may contain `/`.
    pub name: String,
    /// 修改时间（Unix 毫秒）。 / Modification time in Unix milliseconds.
    pub mtime: u64,
    /// 文件为字节数；目录在 `size_known` 时为可见子项数。 / File bytes, or visible child count for a known directory size.
    pub size: u64,
    /// `size` 是否是已计算的真实值。普通目录为避免额外
    /// 子树扫描返回 false；文件及 IndexOnly 下的可见计数为 true。
    /// Whether `size` is authoritative; ordinary directories avoid an extra subtree scan.
    pub size_known: bool,
}

impl PathItem {
    pub fn is_dir(&self) -> bool {
        self.path_type == PathType::Dir || self.path_type == PathType::SymlinkDir
    }

    /// 取 `name` 最后一段。 / Return the final segment of `name` (`a/b/c.txt` → `c.txt`).
    pub fn base_name(&self) -> &str {
        self.name.split('/').next_back().unwrap_or_default()
    }

    /// 按修改时间排序，目录始终在前。 / Sort by modification time with directories first.
    pub fn sort_by_mtime(&self, other: &Self) -> Ordering {
        match self
            .path_type
            .sort_group()
            .cmp(&other.path_type.sort_group())
        {
            Ordering::Equal => self.mtime.cmp(&other.mtime),
            v => v,
        }
    }

    /// 按大小排序，目录始终在前。 / Sort by size with directories first.
    pub fn sort_by_size(&self, other: &Self) -> Ordering {
        match self
            .path_type
            .sort_group()
            .cmp(&other.path_type.sort_group())
        {
            Ordering::Equal => self.size.cmp(&other.size),
            v => v,
        }
    }
}

/// 文件系统条目的四种形态；`Copy` 表示小枚举可按位复制。
/// Four filesystem entry shapes; `Copy` is appropriate because this is a small value enum.
#[derive(Debug, Serialize, Clone, Copy, Eq, PartialEq)]
pub enum PathType {
    Dir,
    SymlinkDir,
    File,
    SymlinkFile,
}

impl PathType {
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Dir | Self::SymlinkDir)
    }

    /// 粗粒度排序组：目录为 0、文件为 1，只用于比较第一层。
    /// Coarse sort group: directories are 0 and files 1; this is not the complete `Ord` value.
    pub fn sort_group(&self) -> u8 {
        u8::from(!self.is_dir())
    }
}

// 中文：手动排序让目录类在文件类之前，同时给每个枚举值唯一序；`cmp == Equal`
// 必须当且仅当 `Eq`，否则 BTreeSet/BTreeMap 会丢元素。
// English: Manual ordering puts directories first while retaining a unique
// value per variant; `cmp == Equal` must match `Eq` or ordered maps lose entries.
impl Ord for PathType {
    fn cmp(&self, other: &Self) -> Ordering {
        let to_value = |t: &Self| -> u8 {
            match t {
                Self::Dir => 0,
                Self::SymlinkDir => 1,
                Self::File => 2,
                Self::SymlinkFile => 3,
            }
        };
        to_value(self).cmp(&to_value(other))
    }
}
// 中文：Rust 要求 PartialOrd 与 Ord 一致，因此直接委托给 `cmp`。
// English: `PartialOrd` must agree with `Ord`, so delegate directly to `cmp`.
impl PartialOrd for PathType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// 以 base64(JSON) 嵌入 HTML 的编辑器/查看器数据。 / Editor/viewer data embedded as base64(JSON).
#[derive(Debug, Serialize)]
pub(crate) struct EditData {
    pub(crate) href: String,
    pub(crate) kind: DataKind,
    pub(crate) uri_prefix: String,
    /// 此已打开对象的有效能力，合并全局功能开关与已认证 ACL；浏览器不能只凭全局开关推断写权限。
    /// Effective capabilities combine process gates and ACL. The compatibility
    /// `allow_*` aliases carry these effective, never merely global, values.
    pub(crate) allow_upload: bool,
    pub(crate) allow_delete: bool,
    pub(crate) can_save: bool,
    pub(crate) can_delete: bool,
    pub(crate) can_move: bool,
    pub(crate) user: Option<String>,
    /// 是否可编辑（≤ 4 MiB 且判定为文本）。 / Whether the file is editable (≤ 4 MiB and classified as text).
    pub(crate) editable: bool,
}
