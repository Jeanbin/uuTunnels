use anyhow::Result;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_SZ,
};

const RUN_SUBKEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const VALUE_NAME: &str = "uuTunnels";

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

pub fn is_enabled() -> bool {
    let subkey = to_wide(RUN_SUBKEY);
    let name = to_wide(VALUE_NAME);
    let mut hkey: HKEY = std::ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey) };
    if status != ERROR_SUCCESS {
        return false;
    }
    let mut data_len: u32 = 0;
    let q = unsafe {
        RegQueryValueExW(
            hkey,
            name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut data_len,
        )
    };
    unsafe { RegCloseKey(hkey) };
    q == ERROR_SUCCESS && data_len > 0
}

pub fn set_enabled(enabled: bool) -> Result<()> {
    let subkey = to_wide(RUN_SUBKEY);
    let name = to_wide(VALUE_NAME);
    let mut hkey: HKEY = std::ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_WRITE, &mut hkey) };
    if status != ERROR_SUCCESS {
        anyhow::bail!("打开注册表 Run 项失败 (code={status})");
    }

    let res = if enabled {
        let exe = std::env::current_exe()?;
        let cmd = format!("\"{}\" --no-open", exe.display());
        let wide = to_wide(&cmd);
        let byte_len = (wide.len() * std::mem::size_of::<u16>()) as u32;
        unsafe {
            RegSetValueExW(
                hkey,
                name.as_ptr(),
                0,
                REG_SZ,
                wide.as_ptr() as *const u8,
                byte_len,
            )
        }
    } else {
        let del = unsafe { RegDeleteValueW(hkey, name.as_ptr()) };
        if del == ERROR_FILE_NOT_FOUND {
            ERROR_SUCCESS
        } else {
            del
        }
    };

    unsafe { RegCloseKey(hkey) };
    if res != ERROR_SUCCESS {
        anyhow::bail!("更新开机自启注册表失败 (code={res})");
    }
    Ok(())
}
