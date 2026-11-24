use std::collections::{HashSet, VecDeque};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::HWND as WinHwnd;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationInvokePattern,
    IUIAutomationLegacyIAccessiblePattern, IUIAutomationSelectionItemPattern,
    UIA_DocumentControlTypeId, UIA_InvokePatternId, UIA_LegacyIAccessiblePatternId,
    UIA_SelectionItemPatternId, UIA_TabItemControlTypeId,
};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HWND, INVALID_HANDLE_VALUE, LPARAM};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER,
    KEY_READ,
};
use windows_sys::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, BringWindowToTop, EnumWindows, GetClassNameW, GetForegroundWindow,
    GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsIconic, IsWindowVisible,
    SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW, SW_SHOWNORMAL,
};

pub const UI_TITLE_BASE: &str = "uuTunnels :: 端口映射控制台";
const DEFAULT_UI_PORT: u16 = 17890;

const KNOWN_BROWSER_EXES: &[&str] = &[
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "arc.exe",
    "chromium.exe",
    "360chrome.exe",
    "360chromex.exe",
    "360se.exe",
    "qqbrowser.exe",
    "sogouexplorer.exe",
    "waterfox.exe",
    "librewolf.exe",
    "zen.exe",
    "floorp.exe",
    "thorium.exe",
    "yandex.exe",
    "browser.exe",
    "maxthon.exe",
    "ucbrowser.exe",
    "centbrowser.exe",
];

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

pub fn tab_title_marker(ui_port: u16) -> String {
    if ui_port == DEFAULT_UI_PORT {
        UI_TITLE_BASE.to_string()
    } else {
        format!("{UI_TITLE_BASE} (:{ui_port})")
    }
}

pub fn title_matches_ui_tab(title: &str, ui_port: u16) -> bool {
    if ui_port == DEFAULT_UI_PORT {
        title.contains(UI_TITLE_BASE) && !title.contains(&format!("{UI_TITLE_BASE} (:"))
    } else {
        title.contains(&tab_title_marker(ui_port))
    }
}

pub fn is_known_browser_exe(exe_name: &str) -> bool {
    let lower = exe_name.trim().to_ascii_lowercase();
    KNOWN_BROWSER_EXES.iter().any(|&known| known == lower)
}

pub fn extract_exe_name_from_command(cmd: &str) -> Option<String> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }

    let exe_part = if let Some(rest) = trimmed.strip_prefix('"') {
        rest.split('"').next().unwrap_or("")
    } else if let Some(idx) = trimmed.to_ascii_lowercase().find(".exe") {
        &trimmed[..idx + 4]
    } else {
        trimmed.split_whitespace().next().unwrap_or("")
    };

    let filename = exe_part.rsplit(['\\', '/']).next().unwrap_or("").trim();
    if filename.is_empty() || !filename.to_ascii_lowercase().ends_with(".exe") {
        return None;
    }
    Some(filename.to_ascii_lowercase())
}

fn read_registry_string(root: HKEY, subkey: &str, value_name: &str) -> Option<String> {
    let subkey_w = to_wide(subkey);
    let value_w = to_wide(value_name);
    let mut hkey: HKEY = std::ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_READ, &mut hkey) };
    if status != ERROR_SUCCESS {
        return None;
    }

    let mut byte_len: u32 = 0;
    let q_size = unsafe {
        RegQueryValueExW(
            hkey,
            value_w.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut byte_len,
        )
    };
    if q_size != ERROR_SUCCESS || byte_len == 0 {
        unsafe { RegCloseKey(hkey) };
        return None;
    }

    let u16_len = (byte_len as usize).div_ceil(2);
    let mut buf = vec![0u16; u16_len];
    let q_val = unsafe {
        RegQueryValueExW(
            hkey,
            value_w.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut u8,
            &mut byte_len,
        )
    };
    unsafe { RegCloseKey(hkey) };

    if q_val != ERROR_SUCCESS {
        return None;
    }

    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = String::from_utf16_lossy(&buf[..end]).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn default_http_browser_exe() -> Option<String> {
    let prog_id = read_registry_string(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice",
        "ProgId",
    )?;
    let cmd = read_registry_string(
        HKEY_CLASSES_ROOT,
        &format!("{prog_id}\\shell\\open\\command"),
        "",
    )?;
    extract_exe_name_from_command(&cmd)
}

fn collect_browser_pids() -> HashSet<u32> {
    let default_exe = default_http_browser_exe();
    let mut pids = HashSet::new();

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return pids;
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snap, &mut entry) } != 0 {
        loop {
            let end = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let exe = String::from_utf16_lossy(&entry.szExeFile[..end]);
            let matches_default = default_exe
                .as_deref()
                .map(|d| exe.eq_ignore_ascii_case(d))
                .unwrap_or(false);
            if matches_default || is_known_browser_exe(&exe) {
                pids.insert(entry.th32ProcessID);
            }
            if unsafe { Process32NextW(snap, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snap) };
    pids
}

struct BrowserWindow {
    hwnd: isize,
    pid: u32,
    title: String,
}

struct EnumWindowsCtx<'a> {
    pids: &'a HashSet<u32>,
    out: Vec<BrowserWindow>,
}

fn is_ignored_window_class(cls: &str) -> bool {
    matches!(
        cls.trim(),
        "IME"
            | "MSCTFIME UI"
            | "tooltips_class32"
            | "Chrome_SystemMessageWindow"
            | "Chrome_MessageWindow"
    )
}

unsafe extern "system" fn enum_browser_windows_cb(hwnd: HWND, lparam: LPARAM) -> i32 {
    let ctx = &mut *(lparam as *mut EnumWindowsCtx<'_>);
    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, &mut pid);
    if !ctx.pids.contains(&pid) {
        return 1;
    }
    if IsWindowVisible(hwnd) == 0 {
        return 1;
    }

    let len = GetWindowTextLengthW(hwnd);
    if len <= 0 {
        return 1;
    }
    let mut buf = vec![0u16; (len + 1) as usize];
    let copied = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
    let title = String::from_utf16_lossy(&buf[..copied.max(0) as usize]);
    if title.trim().is_empty() {
        return 1;
    }

    let mut cls_buf = [0u16; 128];
    let cls_len = GetClassNameW(hwnd, cls_buf.as_mut_ptr(), cls_buf.len() as i32);
    let cls = String::from_utf16_lossy(&cls_buf[..cls_len.max(0) as usize]);
    if is_ignored_window_class(&cls) {
        return 1;
    }

    ctx.out.push(BrowserWindow {
        hwnd: hwnd as isize,
        pid,
        title,
    });
    1
}

fn list_browser_windows(pids: &HashSet<u32>) -> Vec<BrowserWindow> {
    let mut ctx = EnumWindowsCtx {
        pids,
        out: Vec::new(),
    };
    unsafe {
        EnumWindows(
            Some(enum_browser_windows_cb),
            (&mut ctx as *mut EnumWindowsCtx<'_>) as LPARAM,
        );
    }
    ctx.out
}

fn bring_window_to_foreground(hwnd_raw: isize, pid: u32) {
    let hwnd = hwnd_raw as HWND;
    unsafe {
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        } else {
            ShowWindow(hwnd, SW_SHOW);
        }
        let _ = AllowSetForegroundWindow(pid);

        let cur_tid = GetCurrentThreadId();
        let fg_hwnd = GetForegroundWindow();
        let fg_tid = if !fg_hwnd.is_null() {
            GetWindowThreadProcessId(fg_hwnd, std::ptr::null_mut())
        } else {
            0
        };
        let target_tid = GetWindowThreadProcessId(hwnd, std::ptr::null_mut());

        let attached_fg = fg_tid != 0 && fg_tid != cur_tid && AttachThreadInput(cur_tid, fg_tid, 1) != 0;
        let attached_target = target_tid != 0
            && target_tid != cur_tid
            && target_tid != fg_tid
            && AttachThreadInput(cur_tid, target_tid, 1) != 0;

        let _ = BringWindowToTop(hwnd);
        let _ = SetForegroundWindow(hwnd);

        if attached_target {
            let _ = AttachThreadInput(cur_tid, target_tid, 0);
        }
        if attached_fg {
            let _ = AttachThreadInput(cur_tid, fg_tid, 0);
        }
    }
}

struct ComApartmentGuard {
    initialized: bool,
}

impl ComApartmentGuard {
    fn init_mta() -> Self {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        Self {
            initialized: hr.is_ok(),
        }
    }
}

impl Drop for ComApartmentGuard {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

fn select_tab_element(elem: &IUIAutomationElement) -> bool {
    unsafe {
        if let Ok(sel) =
            elem.GetCurrentPatternAs::<IUIAutomationSelectionItemPattern>(UIA_SelectionItemPatternId)
        {
            if let Ok(is_sel) = sel.CurrentIsSelected() {
                if is_sel.as_bool() {
                    return true;
                }
            }
            if sel.Select().is_ok() {
                return true;
            }
        }

        if let Ok(inv) = elem.GetCurrentPatternAs::<IUIAutomationInvokePattern>(UIA_InvokePatternId) {
            if inv.Invoke().is_ok() {
                return true;
            }
        }

        if let Ok(legacy) = elem
            .GetCurrentPatternAs::<IUIAutomationLegacyIAccessiblePattern>(UIA_LegacyIAccessiblePatternId)
        {
            if legacy.DoDefaultAction().is_ok() {
                return true;
            }
        }

        elem.SetFocus().is_ok()
    }
}

fn find_and_activate_tab_in_window<F: FnOnce()>(
    uia: &IUIAutomation,
    walker: &windows::Win32::UI::Accessibility::IUIAutomationTreeWalker,
    win: &BrowserWindow,
    ui_port: u16,
    on_found: Option<F>,
) -> Option<F> {
    const MAX_DEPTH: u32 = 12;
    const MAX_NODES: usize = 2500;

    let root = unsafe { uia.ElementFromHandle(WinHwnd(win.hwnd as *mut core::ffi::c_void)) };
    let Ok(root) = root else {
        return on_found;
    };

    let mut queue = VecDeque::new();
    queue.push_back((root, 0u32));
    let mut visited = 0usize;

    while let Some((elem, depth)) = queue.pop_front() {
        visited += 1;
        if visited > MAX_NODES {
            break;
        }

        let Ok(ctrl_type) = (unsafe { elem.CurrentControlType() }) else {
            continue;
        };

        if ctrl_type == UIA_DocumentControlTypeId {
            continue;
        }

        if ctrl_type == UIA_TabItemControlTypeId {
            if let Ok(name) = unsafe { elem.CurrentName() } {
                let title = name.to_string();
                if title_matches_ui_tab(&title, ui_port) {
                    if let Some(cb) = on_found {
                        cb();
                    }
                    unsafe {
                        let hwnd = win.hwnd as HWND;
                        if IsIconic(hwnd) != 0 {
                            ShowWindow(hwnd, SW_RESTORE);
                        }
                    }
                    let _ = select_tab_element(&elem);
                    bring_window_to_foreground(win.hwnd, win.pid);
                    return None;
                }
            }
            continue;
        }

        if depth >= MAX_DEPTH {
            continue;
        }

        let mut child_opt = unsafe { walker.GetFirstChildElement(&elem) }.ok();
        while let Some(child) = child_opt {
            let next_opt = unsafe { walker.GetNextSiblingElement(&child) }.ok();
            queue.push_back((child, depth + 1));
            child_opt = next_opt;
        }
    }

    on_found
}

/// Attempts to locate an existing browser tab showing the uuTunnels UI, switch to it,
/// bring the browser window to the foreground, and invoke `on_found` before activating.
/// Returns `true` if a matching tab was found and activated.
pub fn focus_existing_ui_tab<F: FnOnce()>(ui_port: u16, on_found: F) -> bool {
    let pids = collect_browser_pids();
    if pids.is_empty() {
        return false;
    }

    let windows = list_browser_windows(&pids);
    if windows.is_empty() {
        return false;
    }

    // Pass 1: fast check on active tab window titles (<1ms, no UIA needed)
    if let Some(w) = windows.iter().find(|w| title_matches_ui_tab(&w.title, ui_port)) {
        on_found();
        bring_window_to_foreground(w.hwnd, w.pid);
        return true;
    }

    // Pass 2: UI Automation search over background browser tabs
    let _com = ComApartmentGuard::init_mta();
    let Ok(uia) = (unsafe { CoCreateInstance::<_, IUIAutomation>(&CUIAutomation, None, CLSCTX_INPROC_SERVER) }) else {
        return false;
    };
    let Ok(walker) = (unsafe { uia.ControlViewWalker() }) else {
        return false;
    };

    let mut pending_cb = Some(on_found);
    for w in &windows {
        pending_cb = find_and_activate_tab_in_window(&uia, &walker, w, ui_port, pending_cb);
        if pending_cb.is_none() {
            return true;
        }
    }

    false
}

/// Opens a new browser tab pointing to the management UI via ShellExecuteW.
pub fn open_new_ui_tab(ui_port: u16) {
    let url = format!("http://127.0.0.1:{ui_port}/");
    let op = to_wide("open");
    let target = to_wide(&url);
    unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            op.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// Focuses an existing UI tab if present (calling `on_focused` before activation),
/// otherwise opens a new browser tab. Returns `true` if an existing tab was focused.
pub fn focus_or_open_ui<F: FnOnce()>(ui_port: u16, on_focused: F) -> bool {
    if focus_existing_ui_tab(ui_port, on_focused) {
        return true;
    }
    open_new_ui_tab(ui_port);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_matches_default_port_variants() {
        assert!(title_matches_ui_tab("uuTunnels :: 端口映射控制台", 17890));
        assert!(title_matches_ui_tab(
            "uuTunnels :: 端口映射控制台 - Microsoft Edge",
            17890
        ));
        assert!(title_matches_ui_tab(
            "uuTunnels :: 端口映射控制台 - 正在休眠",
            17890
        ));
        assert!(!title_matches_ui_tab("uuTunnels - GitHub", 17890));
        assert!(!title_matches_ui_tab(
            "uuTunnels :: 端口映射控制台 (:17891) - Microsoft Edge",
            17890
        ));
    }

    #[test]
    fn title_matches_custom_port_variants() {
        assert!(title_matches_ui_tab(
            "uuTunnels :: 端口映射控制台 (:17891)",
            17891
        ));
        assert!(title_matches_ui_tab(
            "uuTunnels :: 端口映射控制台 (:17891) - Google Chrome",
            17891
        ));
        assert!(!title_matches_ui_tab(
            "uuTunnels :: 端口映射控制台 - Google Chrome",
            17891
        ));
    }

    #[test]
    fn extracts_browser_exe_from_shell_commands() {
        assert_eq!(
            extract_exe_name_from_command(
                r#""C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --single-argument %1"#
            ).as_deref(),
            Some("msedge.exe")
        );
        assert_eq!(
            extract_exe_name_from_command(r#"C:\Program Files\Mozilla Firefox\firefox.exe -osint -url "%1""#)
                .as_deref(),
            Some("firefox.exe")
        );
        assert_eq!(
            extract_exe_name_from_command("chrome.exe").as_deref(),
            Some("chrome.exe")
        );
        assert_eq!(extract_exe_name_from_command("   "), None);
    }

    #[test]
    fn identifies_known_browser_executables() {
        assert!(is_known_browser_exe("msedge.exe"));
        assert!(is_known_browser_exe("CHROME.EXE"));
        assert!(is_known_browser_exe("firefox.exe"));
        assert!(!is_known_browser_exe("Code.exe"));
        assert!(!is_known_browser_exe("notepad.exe"));
    }
}
