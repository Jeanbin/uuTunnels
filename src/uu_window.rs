use serde::Serialize;
use std::collections::HashSet;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{CloseHandle, HWND, INVALID_HANDLE_VALUE, LPARAM, RECT};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindowRect, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible, SetForegroundWindow, ShowWindow,
    SW_HIDE, SW_RESTORE, SW_SHOW,
};

#[derive(Debug, Clone, Serialize)]
pub struct UuWindowInfo {
    pub hwnd: isize,
    pub pid: u32,
    pub title: String,
    pub visible: bool,
    pub hidden_by_us: bool,
    pub is_main_window: bool,
    pub is_portmap_likely: bool,
}

pub fn is_main_uu_window(title: &str) -> bool {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.eq_ignore_ascii_case("GameViewer")
        || trimmed == "UU远程"
        || trimmed == "网易UU远程"
    {
        return true;
    }
    trimmed.contains("UU远程") && !trimmed.contains("端口映射")
}

pub fn is_internal_helper_window(title: &str, class_name: &str) -> bool {
    let cls = class_name.trim();
    let t = title.trim();
    matches!(
        cls,
        "IME" | "MSCTFIME UI" | "CicMarshalWndClass" | "GDI+ Hook Window Class" | "tooltips_class32"
    ) || matches!(t, "Default IME" | "MSCTFIME UI" | "GDI+ Window")
        || t.starts_with("QEventDispatcher")
}

static HIDDEN_HWNDS: Mutex<Option<HashSet<isize>>> = Mutex::new(None);

fn with_hidden<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashSet<isize>) -> R,
{
    let mut guard = HIDDEN_HWNDS.lock().unwrap();
    let set = guard.get_or_insert_with(HashSet::new);
    set.retain(|&raw| unsafe { IsWindow(raw as HWND) != 0 });
    f(set)
}

fn find_gameviewer_pids() -> HashSet<u32> {
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
            let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
            if name.eq_ignore_ascii_case("GameViewer.exe") {
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

struct EnumCtx {
    pids: HashSet<u32>,
    hidden: HashSet<isize>,
    out: Vec<UuWindowInfo>,
}

unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: LPARAM) -> i32 {
    let ctx = &mut *(lparam as *mut EnumCtx);
    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, &mut pid);
    if !ctx.pids.contains(&pid) {
        return 1;
    }

    let raw = hwnd as isize;
    let visible = IsWindowVisible(hwnd) != 0;
    let hidden_by_us = ctx.hidden.contains(&raw);

    let len = GetWindowTextLengthW(hwnd);
    let title = if len > 0 {
        let mut buf = vec![0u16; (len + 1) as usize];
        let copied = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
        String::from_utf16_lossy(&buf[..copied.max(0) as usize])
    } else {
        String::new()
    };

    let mut cls_buf = [0u16; 128];
    let cls_len = GetClassNameW(hwnd, cls_buf.as_mut_ptr(), cls_buf.len() as i32);
    let cls = String::from_utf16_lossy(&cls_buf[..cls_len.max(0) as usize]);

    if is_internal_helper_window(&title, &cls) {
        return 1;
    }

    let mut rect: RECT = std::mem::zeroed();
    let (mut w, mut h) = (0, 0);
    if GetWindowRect(hwnd, &mut rect) != 0 {
        w = rect.right - rect.left;
        h = rect.bottom - rect.top;
    }

    let trimmed_title = title.trim();
    if !hidden_by_us {
        if visible {
            if (trimmed_title.is_empty() && !(w >= 300 && h >= 200)) || (w < 80 || h < 50) {
                return 1;
            }
        } else {
            // Also detect real UU windows that were hidden in a previous session
            let is_minimized = IsIconic(hwnd) != 0;
            if trimmed_title.is_empty() || (!is_minimized && (w < 200 || h < 120)) {
                return 1;
            }
        }
    }

    let lower = title.to_lowercase();
    let is_main_window = is_main_uu_window(&title);
    let is_portmap_likely = !is_main_window
        && (title.contains("端口映射")
            || lower.contains("port")
            || lower.contains("mapping")
            || !trimmed_title.is_empty());

    ctx.out.push(UuWindowInfo {
        hwnd: raw,
        pid,
        title: if trimmed_title.is_empty() {
            if w >= 300 && h >= 200 {
                format!("UU 远程窗口 ({w}×{h})")
            } else {
                format!("GameViewer 窗口 ({raw})")
            }
        } else {
            title
        },
        visible,
        hidden_by_us,
        is_main_window,
        is_portmap_likely,
    });
    1
}

pub fn list_uu_windows() -> Vec<UuWindowInfo> {
    let pids = find_gameviewer_pids();
    if pids.is_empty() {
        return Vec::new();
    }
    let hidden = with_hidden(|s| s.clone());
    let mut ctx = EnumCtx {
        pids,
        hidden,
        out: Vec::new(),
    };
    unsafe {
        EnumWindows(Some(enum_cb), (&mut ctx as *mut EnumCtx) as LPARAM);
    }
    ctx.out.sort_by_key(|w| (!w.is_portmap_likely, w.hwnd));
    ctx.out
}

pub fn hide_window(hwnd_raw: isize) -> bool {
    let hwnd = hwnd_raw as HWND;
    if unsafe { IsWindow(hwnd) } == 0 {
        return false;
    }
    unsafe {
        ShowWindow(hwnd, SW_HIDE);
    }
    with_hidden(|s| {
        s.insert(hwnd_raw);
    });
    true
}

pub fn show_window(hwnd_raw: isize) -> bool {
    let hwnd = hwnd_raw as HWND;
    if unsafe { IsWindow(hwnd) } == 0 {
        with_hidden(|s| {
            s.remove(&hwnd_raw);
        });
        return false;
    }
    unsafe {
        ShowWindow(hwnd, SW_SHOW);
        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
    }
    with_hidden(|s| {
        s.remove(&hwnd_raw);
    });
    true
}

/// Hides visible UU Remote port-mapping / secondary windows, keeping the main UU window untouched.
pub fn hide_portmap_windows() -> usize {
    let wins = list_uu_windows();
    let targets: Vec<isize> = wins
        .iter()
        .filter(|w| w.visible && !w.is_main_window)
        .map(|w| w.hwnd)
        .collect();

    let mut count = 0;
    for hwnd in targets {
        if hide_window(hwnd) {
            count += 1;
        }
    }
    count
}

pub fn restore_all_hidden() -> usize {
    let mut targets: Vec<isize> = with_hidden(|s| s.iter().copied().collect());
    let mut seen: HashSet<isize> = targets.iter().copied().collect();

    for w in list_uu_windows() {
        if !w.visible && !w.is_main_window && seen.insert(w.hwnd) {
            targets.push(w.hwnd);
        }
    }

    let mut count = 0;
    for hwnd in targets {
        if show_window(hwnd) {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_main_uu_window_vs_portmap_panel() {
        assert!(is_main_uu_window("网易UU远程"));
        assert!(is_main_uu_window("UU远程"));
        assert!(is_main_uu_window("GameViewer"));
        assert!(!is_main_uu_window("ubuntu-2404"));
        assert!(!is_main_uu_window("linux-host"));
        assert!(!is_main_uu_window("端口映射"));
        assert!(!is_main_uu_window("UU远程 - 端口映射"));
    }

    #[test]
    fn filters_internal_helper_windows() {
        assert!(is_internal_helper_window("Default IME", "IME"));
        assert!(is_internal_helper_window("MSCTFIME UI", "MSCTFIME UI"));
        assert!(is_internal_helper_window("QEventDispatcherWin32_Internal_Widget", "Qt5152QWindow"));
        assert!(!is_internal_helper_window("ubuntu-2404", "Qt5152QWindow"));
        assert!(!is_internal_helper_window("linux-host", "Qt5152QWindow"));
        assert!(!is_internal_helper_window("网易UU远程", "Qt5152QWindow"));
    }
}
