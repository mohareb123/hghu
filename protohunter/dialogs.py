"""Windows native file dialog; no Tk or uploaded executable is needed."""
import os


def choose_file(kind='input'):
    if os.name != 'nt':
        raise ValueError('The native file chooser is available in the Windows desktop application only')
    import ctypes
    from ctypes import wintypes as w
    class OPENFILENAMEW(ctypes.Structure):
        _fields_ = [('lStructSize', w.DWORD), ('hwndOwner', w.HWND), ('hInstance', w.HINSTANCE),
                    ('lpstrFilter', w.LPCWSTR), ('lpstrCustomFilter', w.LPWSTR), ('nMaxCustFilter', w.DWORD),
                    ('nFilterIndex', w.DWORD), ('lpstrFile', w.LPWSTR), ('nMaxFile', w.DWORD),
                    ('lpstrFileTitle', w.LPWSTR), ('nMaxFileTitle', w.DWORD), ('lpstrInitialDir', w.LPCWSTR),
                    ('lpstrTitle', w.LPCWSTR), ('Flags', w.DWORD), ('nFileOffset', w.WORD),
                    ('nFileExtension', w.WORD), ('lpstrDefExt', w.LPCWSTR), ('lCustData', ctypes.c_ssize_t),
                    ('lpfnHook', ctypes.c_void_p), ('lpTemplateName', w.LPCWSTR), ('pvReserved', ctypes.c_void_p),
                    ('dwReserved', w.DWORD), ('FlagsEx', w.DWORD)]
    choices = {'input': ('Android files', '*.apk;*.xapk;*.apks;*.zip;*.dex;*.smali;*.so;*.proto;*.dat;*.obb;*.aab'),
               'apktool': ('Apktool JAR', '*.jar'), 'java': ('Java executable', 'java.exe'),
               'jadx': ('JADX CLI launcher', '*.bat;*.exe;*.jar'),
               'il2cpp': ('Il2CppDumper', '*.exe;*.dll'), 'dotnet': ('dotnet runtime', 'dotnet.exe'),
               'apksigner': ('Android apksigner', '*.jar;*.bat;*.exe'), 'zipalign': ('Android zipalign', 'zipalign.exe'),
               'keystore': ('Signing keystore', '*.jks;*.keystore;*.p12')}
    if kind not in choices:
        raise ValueError('Unknown chooser type')
    title, pattern = choices[kind]
    buffer = ctypes.create_unicode_buffer(32768)
    spec = OPENFILENAMEW()
    spec.lStructSize = ctypes.sizeof(spec)
    spec.lpstrFilter = title + '\0' + pattern + '\0All files\0*.*\0\0'
    spec.lpstrFile = ctypes.cast(buffer, w.LPWSTR)
    spec.nMaxFile = len(buffer)
    spec.lpstrTitle = 'ProtoHunter - ' + title
    spec.Flags = 0x80000 | 0x1000 | 0x800 | 0x8 | 0x2000000
    library = ctypes.WinDLL('comdlg32', use_last_error=True)
    library.GetOpenFileNameW.argtypes = [ctypes.POINTER(OPENFILENAMEW)]
    library.GetOpenFileNameW.restype = w.BOOL
    if not library.GetOpenFileNameW(ctypes.byref(spec)):
        error = library.CommDlgExtendedError()
        if error:
            raise OSError(f'Windows file dialog error {error}')
        return None
    return buffer.value
