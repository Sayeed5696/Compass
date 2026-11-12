/*
 * Compass.exe - starts the Compass server with no console window, opens the
 * browser, and keeps a tray icon (Open Compass / Open log folder / Stop Compass).
 *
 * Build (from Linux or Windows, with Zig 0.13):
 *   zig build-exe compass_launcher.c compass.rc -target x86_64-windows-gnu -lc \
 *       -luser32 -lshell32 -lws2_32 -ladvapi32 -O ReleaseSmall --subsystem windows \
 *       -femit-bin=../Compass.exe
 *
 * Python is found in this order: a "python" folder next to Compass.exe, the
 * Windows registry (python.org installs, 3.10 or newer), the py launcher
 * (pyw.exe -3), then pythonw.exe on PATH.
 */
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <wchar.h>
#include <stdarg.h>

#define IDI_COMPASS 1
#define WM_TRAY (WM_APP + 1)
#define ID_OPEN 1001
#define ID_LOGS 1002
#define ID_STOP 1003
#define TIMER_WATCH 1
#define BUF 1024

static HINSTANCE g_inst;
static wchar_t g_dir[MAX_PATH];
static wchar_t g_url[64];
static int g_port = 8765;
static PROCESS_INFORMATION g_proc;
static HANDLE g_job;
static HWND g_wnd;
static NOTIFYICONDATAW g_nid;
static UINT g_taskbar_created;
static BOOL g_stopping = FALSE;

/* ------------------------------------------------------------- helpers */
static void fmt(wchar_t *out, size_t n, const wchar_t *f, ...)
{
    va_list ap;
    va_start(ap, f);
    _vsnwprintf(out, n - 1, f, ap);
    va_end(ap);
    out[n - 1] = 0;
}

static BOOL file_exists(const wchar_t *p)
{
    DWORD a = GetFileAttributesW(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void message(const wchar_t *text, UINT icon)
{
    MessageBoxW(NULL, text, L"Compass", MB_OK | icon | MB_SETFOREGROUND | MB_TOPMOST);
}

static ULONGLONG g_last_open;

static void open_browser(void)
{
    ULONGLONG now = GetTickCount64();
    if (g_last_open && now - g_last_open < 1500) /* a double-click opens one tab, not two */
        return;
    g_last_open = now;
    ShellExecuteW(NULL, L"open", g_url, NULL, NULL, SW_SHOWNORMAL);
}

static void open_logs(void)
{
    wchar_t p[MAX_PATH];
    fmt(p, MAX_PATH, L"%ls\\data", g_dir);
    ShellExecuteW(NULL, L"open", p, NULL, NULL, SW_SHOWNORMAL);
}

/* True when something is already listening on 127.0.0.1:port. */
static BOOL port_open(int port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return FALSE;
    struct sockaddr_in a;
    ZeroMemory(&a, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    BOOL ok = connect(s, (struct sockaddr *)&a, sizeof a) == 0;
    closesocket(s);
    return ok;
}

/* Last few lines of data\compass.log, for error messages. */
static void log_tail(wchar_t *out, size_t n)
{
    wchar_t p[MAX_PATH];
    char raw[1400];
    DWORD got = 0;
    out[0] = 0;
    fmt(p, MAX_PATH, L"%ls\\data\\compass.log", g_dir);
    HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;
    LARGE_INTEGER size;
    if (GetFileSizeEx(h, &size) && size.QuadPart > (LONGLONG)(sizeof raw - 1)) {
        LARGE_INTEGER pos;
        pos.QuadPart = size.QuadPart - (LONGLONG)(sizeof raw - 1);
        SetFilePointerEx(h, pos, NULL, FILE_BEGIN);
    }
    ReadFile(h, raw, sizeof raw - 1, &got, NULL);
    CloseHandle(h);
    raw[got] = 0;
    char *start = raw;
    int lines = 0;
    for (char *c = raw + got; c > raw; c--) { /* keep the last 6 lines */
        if (*c == '\n' && ++lines > 6) {
            start = c + 1;
            break;
        }
    }
    int w = MultiByteToWideChar(CP_UTF8, 0, start, -1, out, (int)n - 1);
    out[w > 0 ? w : 0] = 0;
}

/* ------------------------------------------------------------- Python */
static BOOL usable(const wchar_t *exe)
{
    if (!file_exists(exe))
        return FALSE;
    /* The Microsoft Store placeholder in WindowsApps only opens the Store. */
    return wcsstr(exe, L"\\WindowsApps\\") == NULL;
}

static BOOL python_from_registry(wchar_t *exe, size_t n)
{
    HKEY roots[2] = {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    REGSAM views[2] = {KEY_WOW64_64KEY, KEY_WOW64_32KEY};
    int best = 0;
    for (int r = 0; r < 2; r++) {
        for (int v = 0; v < 2; v++) {
            HKEY core;
            if (RegOpenKeyExW(roots[r], L"Software\\Python\\PythonCore", 0, KEY_READ | views[v], &core) != ERROR_SUCCESS)
                continue;
            wchar_t name[64];
            for (DWORD i = 0;; i++) {
                DWORD len = 64;
                if (RegEnumKeyExW(core, i, name, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                    break;
                int major = 0, minor = 0;
                if (swscanf(name, L"%d.%d", &major, &minor) != 2 || major != 3 || minor < 10)
                    continue;
                int score = major * 100 + minor;
                if (score <= best)
                    continue;
                wchar_t sub[128], path[MAX_PATH];
                DWORD bytes = sizeof path;
                fmt(sub, 128, L"%ls\\InstallPath", name);
                if (RegGetValueW(core, sub, L"WindowedExecutablePath", RRF_RT_REG_SZ, NULL, path, &bytes) != ERROR_SUCCESS) {
                    bytes = sizeof path;
                    if (RegGetValueW(core, sub, NULL, RRF_RT_REG_SZ, NULL, path, &bytes) != ERROR_SUCCESS)
                        continue;
                    size_t l = wcslen(path);
                    if (l && path[l - 1] == L'\\')
                        path[l - 1] = 0;
                    wchar_t full[MAX_PATH];
                    fmt(full, MAX_PATH, L"%ls\\pythonw.exe", path);
                    lstrcpynW(path, full, MAX_PATH);
                }
                if (usable(path)) {
                    lstrcpynW(exe, path, (int)n);
                    best = score;
                }
            }
            RegCloseKey(core);
        }
    }
    return best > 0;
}

/* Fills exe and args (extra arguments before the script). */
static BOOL find_python(wchar_t *exe, size_t n, wchar_t *args, size_t an)
{
    args[0] = 0;
    fmt(exe, n, L"%ls\\python\\pythonw.exe", g_dir);
    if (file_exists(exe))
        return TRUE;
    if (python_from_registry(exe, n))
        return TRUE;
    if (SearchPathW(NULL, L"pyw.exe", NULL, (DWORD)n, exe, NULL) && usable(exe)) {
        lstrcpynW(args, L"-3", (int)an);
        return TRUE;
    }
    if (SearchPathW(NULL, L"pythonw.exe", NULL, (DWORD)n, exe, NULL) && usable(exe))
        return TRUE;
    return FALSE;
}

/* ------------------------------------------------------------- server */
static BOOL start_server(const wchar_t *python, const wchar_t *args)
{
    wchar_t cmd[BUF], data[MAX_PATH];
    fmt(cmd, BUF, L"\"%ls\" %ls \"%ls\\server.py\"", python, args, g_dir);
    fmt(data, MAX_PATH, L"%ls\\data", g_dir);
    CreateDirectoryW(data, NULL);
    SetEnvironmentVariableW(L"COMPASS_NO_BROWSER", L"1");
    SetEnvironmentVariableW(L"COMPASS_LAUNCHER", L"1");
    SetEnvironmentVariableW(L"PYTHONUTF8", L"1");

    /* Everything started here lives in a job, so it ends when Compass.exe ends. */
    g_job = CreateJobObjectW(NULL, NULL);
    if (g_job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION li;
        ZeroMemory(&li, sizeof li);
        li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(g_job, JobObjectExtendedLimitInformation, &li, sizeof li);
    }
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!CreateProcessW(python, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, g_dir, &si, &g_proc))
        return FALSE;
    if (g_job)
        AssignProcessToJobObject(g_job, g_proc.hProcess);
    ResumeThread(g_proc.hThread);
    return TRUE;
}

static BOOL server_alive(void)
{
    return g_proc.hProcess && WaitForSingleObject(g_proc.hProcess, 0) == WAIT_TIMEOUT;
}

static void stop_server(void)
{
    g_stopping = TRUE;
    if (g_job)
        TerminateJobObject(g_job, 0);
    else if (g_proc.hProcess)
        TerminateProcess(g_proc.hProcess, 0);
    if (g_proc.hProcess)
        WaitForSingleObject(g_proc.hProcess, 5000);
}

static void failed_to_start(void)
{
    wchar_t tail[1600], text[2400];
    log_tail(tail, 1600);
    if (wcsstr(tail, L"10048") || wcsstr(tail, L"Address already in use"))
        fmt(text, 2400, L"Compass could not start because port %d is already used by another program.\n\n"
                        L"Close that program, or set the COMPASS_PORT environment variable to another port, then open Compass again.", g_port);
    else
        fmt(text, 2400, L"Compass could not start.\n\nLast lines of data\\compass.log:\n\n%ls", tail[0] ? tail : L"(the log is empty)");
    message(text, MB_ICONERROR);
}

/* ------------------------------------------------------------- tray */
static void tray_add(BOOL announce)
{
    ZeroMemory(&g_nid, sizeof g_nid);
    g_nid.cbSize = sizeof g_nid;
    g_nid.hWnd = g_wnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY;
    g_nid.hIcon = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_COMPASS), IMAGE_ICON,
                                    GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);
    fmt(g_nid.szTip, 128, L"Compass is running (port %d)", g_port);
    if (announce) {
        g_nid.uFlags |= NIF_INFO;
        lstrcpynW(g_nid.szInfoTitle, L"Compass is running", 64);
        lstrcpynW(g_nid.szInfo, L"Use the compass icon here to open Compass or stop it.", 256);
        g_nid.dwInfoFlags = NIIF_INFO;
    }
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

static void tray_remove(void)
{
    if (g_nid.hWnd)
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
    g_nid.hWnd = NULL;
}

static void tray_menu(void)
{
    POINT pt;
    GetCursorPos(&pt);
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING, ID_OPEN, L"Open Compass");
    AppendMenuW(m, MF_STRING, ID_LOGS, L"Open log folder");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, ID_STOP, L"Stop Compass");
    SetMenuDefaultItem(m, ID_OPEN, FALSE);
    SetForegroundWindow(g_wnd); /* required so the menu closes when clicking elsewhere */
    TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, g_wnd, NULL);
    PostMessageW(g_wnd, WM_NULL, 0, 0);
    DestroyMenu(m);
}

static LRESULT CALLBACK wndproc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == g_taskbar_created && g_taskbar_created) { /* Explorer restarted */
        tray_add(FALSE);
        return 0;
    }
    switch (msg) {
    case WM_TRAY:
        if (lp == WM_LBUTTONUP || lp == WM_LBUTTONDBLCLK)
            open_browser();
        else if (lp == WM_RBUTTONUP || lp == WM_CONTEXTMENU)
            tray_menu();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == ID_OPEN)
            open_browser();
        else if (LOWORD(wp) == ID_LOGS)
            open_logs();
        else if (LOWORD(wp) == ID_STOP) {
            tray_remove();
            stop_server();
            DestroyWindow(h);
        }
        return 0;
    case WM_TIMER:
        if (wp == TIMER_WATCH && !g_stopping && !server_alive()) {
            KillTimer(h, TIMER_WATCH);
            tray_remove();
            failed_to_start();
            DestroyWindow(h);
        }
        return 0;
    case WM_QUERYENDSESSION:
        return TRUE;
    case WM_ENDSESSION:
        if (wp) {
            tray_remove();
            stop_server();
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

/* ------------------------------------------------------------- main */
int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmdline, int show)
{
    (void)prev;
    (void)cmdline;
    (void)show;
    g_inst = inst;

    GetModuleFileNameW(NULL, g_dir, MAX_PATH);
    wchar_t *slash = wcsrchr(g_dir, L'\\');
    if (slash)
        *slash = 0;

    wchar_t envport[16];
    if (GetEnvironmentVariableW(L"COMPASS_PORT", envport, 16)) {
        int p = _wtoi(envport);
        if (p > 0 && p < 65536)
            g_port = p;
    }
    fmt(g_url, 64, L"http://127.0.0.1:%d/", g_port);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* Already running? Just open it. */
    HANDLE mutex = CreateMutexW(NULL, FALSE, L"Local\\CompassLauncher");
    if (GetLastError() == ERROR_ALREADY_EXISTS || port_open(g_port)) {
        for (int i = 0; i < 75 && !port_open(g_port); i++)
            Sleep(200);
        open_browser();
        if (mutex)
            CloseHandle(mutex);
        WSACleanup();
        return 0;
    }

    wchar_t script[MAX_PATH];
    fmt(script, MAX_PATH, L"%ls\\server.py", g_dir);
    if (!file_exists(script)) {
        message(L"Compass.exe must stay in the Compass folder, next to server.py and the app and web folders.\n\n"
                L"Move it back, or create a shortcut to it instead of moving it.", MB_ICONERROR);
        return 1;
    }

    wchar_t python[MAX_PATH], args[16];
    if (!find_python(python, MAX_PATH, args, 16)) {
        message(L"Compass needs Python 3.10 or newer on this PC.\n\n"
                L"Install it from python.org (tick \"Add python.exe to PATH\"), then open Compass again.", MB_ICONERROR);
        return 1;
    }

    if (!start_server(python, args)) {
        wchar_t text[600];
        fmt(text, 600, L"Compass could not start Python:\n%ls\n\nWindows error %lu.", python, GetLastError());
        message(text, MB_ICONERROR);
        return 1;
    }

    /* Wait up to 30 seconds for the server to answer. */
    BOOL ready = FALSE;
    for (int i = 0; i < 150; i++) {
        if (!server_alive())
            break;
        if (port_open(g_port)) {
            ready = TRUE;
            break;
        }
        Sleep(200);
    }
    if (!ready && !server_alive()) {
        failed_to_start();
        return 1;
    }

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(IDI_COMPASS));
    wc.lpszClassName = L"CompassLauncherWindow";
    RegisterClassExW(&wc);
    g_wnd = CreateWindowExW(0, wc.lpszClassName, L"Compass", WS_OVERLAPPED, 0, 0, 0, 0, NULL, NULL, inst, NULL);
    g_taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
    tray_add(TRUE);
    open_browser();
    SetTimer(g_wnd, TIMER_WATCH, 2000, NULL);

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }

    tray_remove();
    if (server_alive())
        stop_server();
    if (g_job)
        CloseHandle(g_job);
    if (mutex)
        CloseHandle(mutex);
    WSACleanup();
    return 0;
}
