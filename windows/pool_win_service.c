/*
 * pool_win_service.c - POOL Windows Service
 *
 * Runs POOL as a Windows service or console application. Provides:
 *   - Service registration (install/uninstall)
 *   - Named pipe control interface (equivalent to /dev/pool on Linux)
 *   - Session management using the cross-platform pool_platform.h API
 *   - Event logging
 *
 * Build: cl /O2 /W4 pool_win_service.c pool_win_platform.c
 *        /link bcrypt.lib ws2_32.lib advapi32.lib
 *
 * Install:   pool_service.exe --install
 * Uninstall: pool_service.exe --uninstall
 * Console:   pool_service.exe --console
 */

#ifdef _WIN32

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/pool_proto.h"
#include "../common/pool_platform.h"

#define POOL_SERVICE_NAME   L"POOLProtocol"
#define POOL_DISPLAY_NAME   L"POOL Protected Overlay Transport"
#define POOL_PIPE_NAME      L"\\\\.\\pipe\\pool_control"
#define POOL_MAX_WIN_SESSIONS 64

/* Pipe command codes (mirror Linux ioctl commands) */
#define POOL_CMD_LISTEN     1
#define POOL_CMD_CONNECT    2
#define POOL_CMD_SEND       3
#define POOL_CMD_RECV       4
#define POOL_CMD_SESSIONS   5
#define POOL_CMD_CLOSE      6
#define POOL_CMD_STOP       7

/* Service globals */
static SERVICE_STATUS_HANDLE g_status_handle;
static SERVICE_STATUS g_status;
static HANDLE g_stop_event;
static HANDLE g_pipe_thread;

/* Session table */
struct pool_win_session {
    int active;
    uint32_t peer_ip;
    uint16_t peer_port;
    pool_socket_t sock;
    uint8_t session_id[POOL_SESSION_ID_SIZE];
    uint64_t bytes_sent;
    uint64_t bytes_recv;
};

static struct pool_win_session g_sessions[POOL_MAX_WIN_SESSIONS];
static CRITICAL_SECTION g_session_lock;

/* Pipe command header */
struct pool_pipe_cmd {
    uint32_t cmd;
    uint32_t len;
    uint8_t data[4096];
};

/* Pipe response header */
struct pool_pipe_resp {
    int32_t  result;
    uint32_t len;
    uint8_t  data[4096];
};

static void init_sessions(void)
{
    InitializeCriticalSection(&g_session_lock);
    memset(g_sessions, 0, sizeof(g_sessions));
}

static struct pool_win_session *alloc_session(void)
{
    int i;
    EnterCriticalSection(&g_session_lock);
    for (i = 0; i < POOL_MAX_WIN_SESSIONS; i++) {
        if (!g_sessions[i].active) {
            g_sessions[i].active = 1;
            g_sessions[i].bytes_sent = 0;
            g_sessions[i].bytes_recv = 0;
            pool_crypto_random(g_sessions[i].session_id,
                               POOL_SESSION_ID_SIZE);
            LeaveCriticalSection(&g_session_lock);
            return &g_sessions[i];
        }
    }
    LeaveCriticalSection(&g_session_lock);
    return NULL;
}

static void free_session(struct pool_win_session *sess)
{
    if (sess) {
        pool_net_close(sess->sock);
        sess->active = 0;
    }
}

/* Handle a control pipe command */
static void handle_pipe_command(const struct pool_pipe_cmd *cmd,
                                DWORD bytes_read,
                                struct pool_pipe_resp *resp)
{
    resp->result = -1;
    resp->len = 0;

    /* W04: Validate cmd.len against bytes actually read */
    if (cmd->len > bytes_read - offsetof(struct pool_pipe_cmd, data)) {
        pool_log_warn("pipe command len %u exceeds read %lu", cmd->len,
                      (unsigned long)bytes_read);
        return;
    }
    if (cmd->len > sizeof(cmd->data)) {
        pool_log_warn("pipe command len %u exceeds data buffer", cmd->len);
        return;
    }

    switch (cmd->cmd) {
    case POOL_CMD_CONNECT: {
        /* data = [ip:4][port:2] */
        uint32_t ip;
        uint16_t port;
        struct pool_win_session *sess;

        if (cmd->len < 6)
            break;
        memcpy(&ip, cmd->data, 4);
        memcpy(&port, cmd->data + 4, 2);
        ip = ntohl(ip);
        port = ntohs(port);

        sess = alloc_session();
        if (!sess)
            break;

        sess->peer_ip = ip;
        sess->peer_port = port;

        if (pool_net_tcp_connect(&sess->sock, ip, port) != 0) {
            free_session(sess);
            break;
        }

        resp->result = 0;
        memcpy(resp->data, sess->session_id, POOL_SESSION_ID_SIZE);
        resp->len = POOL_SESSION_ID_SIZE;
        pool_log_info("connected to %u.%u.%u.%u:%u",
                      (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                      (ip >> 8) & 0xFF, ip & 0xFF, port);
        break;
    }

    case POOL_CMD_SESSIONS: {
        /* Return list of active sessions */
        int i, count = 0;
        EnterCriticalSection(&g_session_lock);
        for (i = 0; i < POOL_MAX_WIN_SESSIONS; i++) {
            if (!g_sessions[i].active)
                continue;
            /* Pack: [session_id:16][ip:4][port:2] = 22 bytes each */
            int off = count * 22;
            if (off + 22 > (int)sizeof(resp->data))
                break;
            memcpy(resp->data + off, g_sessions[i].session_id,
                   POOL_SESSION_ID_SIZE);
            uint32_t nip = htonl(g_sessions[i].peer_ip);
            uint16_t nport = htons(g_sessions[i].peer_port);
            memcpy(resp->data + off + 16, &nip, 4);
            memcpy(resp->data + off + 20, &nport, 2);
            count++;
        }
        LeaveCriticalSection(&g_session_lock);
        resp->result = 0;
        resp->len = count * 22;
        break;
    }

    case POOL_CMD_CLOSE: {
        /* data = session_id */
        int i;
        if (cmd->len < POOL_SESSION_ID_SIZE)
            break;
        EnterCriticalSection(&g_session_lock);
        for (i = 0; i < POOL_MAX_WIN_SESSIONS; i++) {
            if (!g_sessions[i].active)
                continue;
            if (memcmp(g_sessions[i].session_id, cmd->data,
                       POOL_SESSION_ID_SIZE) == 0) {
                free_session(&g_sessions[i]);
                resp->result = 0;
                break;
            }
        }
        LeaveCriticalSection(&g_session_lock);
        break;
    }

    case POOL_CMD_STOP:
        SetEvent(g_stop_event);
        resp->result = 0;
        break;

    default:
        pool_log_warn("unknown pipe command: %u", cmd->cmd);
        break;
    }
}

/* Named pipe listener thread */
static DWORD WINAPI pipe_listener_thread(LPVOID param)
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR psd = NULL;
    BOOL acl_ok = FALSE;

    (void)param;

    /*
     * W03: Create a DACL that restricts pipe access to SYSTEM and
     * local Administrators only (prevents local DoS and privilege
     * escalation via unprivileged pipe connections).
     */
    if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1, &psd, NULL)) {
        memset(&sa, 0, sizeof(sa));
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = psd;
        sa.bInheritHandle = FALSE;
        acl_ok = TRUE;
    }

    while (WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0) {
        HANDLE pipe = CreateNamedPipeW(
            POOL_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            4,  /* limit to 4 concurrent instances instead of unlimited */
            sizeof(struct pool_pipe_resp),
            sizeof(struct pool_pipe_cmd),
            5000, acl_ok ? &sa : NULL);

        if (pipe == INVALID_HANDLE_VALUE) {
            pool_log_error("CreateNamedPipe failed: %lu", GetLastError());
            Sleep(1000);
            continue;
        }

        if (ConnectNamedPipe(pipe, NULL) ||
            GetLastError() == ERROR_PIPE_CONNECTED) {
            struct pool_pipe_cmd cmd;
            struct pool_pipe_resp resp;
            DWORD bytes_read, bytes_written;

            if (ReadFile(pipe, &cmd, sizeof(cmd), &bytes_read, NULL)) {
                handle_pipe_command(&cmd, bytes_read, &resp);
                WriteFile(pipe, &resp, sizeof(resp), &bytes_written, NULL);
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }

    if (psd)
        LocalFree(psd);
    return 0;
}

/* Service control handler */
static VOID WINAPI service_ctrl_handler(DWORD ctrl)
{
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_status_handle, &g_status);
        SetEvent(g_stop_event);
        break;

    case SERVICE_CONTROL_INTERROGATE:
        SetServiceStatus(g_status_handle, &g_status);
        break;
    }
}

/* Service main */
static VOID WINAPI service_main(DWORD argc, LPWSTR *argv)
{
    (void)argc;
    (void)argv;

    g_status_handle = RegisterServiceCtrlHandlerW(POOL_SERVICE_NAME,
                                                   service_ctrl_handler);
    if (!g_status_handle)
        return;

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = SERVICE_START_PENDING;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                   SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_status_handle, &g_status);

    g_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    init_sessions();

    /* Start pipe listener */
    g_pipe_thread = CreateThread(NULL, 0, pipe_listener_thread, NULL, 0, NULL);

    g_status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_status_handle, &g_status);

    pool_log_info("POOL service started");

    /* Wait for stop signal */
    WaitForSingleObject(g_stop_event, INFINITE);

    /* Cleanup */
    {
        int i;
        EnterCriticalSection(&g_session_lock);
        for (i = 0; i < POOL_MAX_WIN_SESSIONS; i++) {
            if (g_sessions[i].active)
                free_session(&g_sessions[i]);
        }
        LeaveCriticalSection(&g_session_lock);
    }

    WaitForSingleObject(g_pipe_thread, 5000);
    CloseHandle(g_pipe_thread);
    CloseHandle(g_stop_event);

    g_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_status_handle, &g_status);
    pool_log_info("POOL service stopped");
}

/* Install service */
static int service_install(void)
{
    SC_HANDLE scm, svc;
    WCHAR path[MAX_PATH];

    GetModuleFileNameW(NULL, path, MAX_PATH);

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        fprintf(stderr, "OpenSCManager failed: %lu\n", GetLastError());
        return 1;
    }

    svc = CreateServiceW(scm, POOL_SERVICE_NAME, POOL_DISPLAY_NAME,
                          SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                          SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                          path, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        fprintf(stderr, "CreateService failed: %lu\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }

    printf("POOL service installed successfully.\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

/* Uninstall service */
static int service_uninstall(void)
{
    SC_HANDLE scm, svc;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm)
        return 1;

    svc = OpenServiceW(scm, POOL_SERVICE_NAME, DELETE);
    if (!svc) {
        CloseServiceHandle(scm);
        return 1;
    }

    DeleteService(svc);
    printf("POOL service uninstalled.\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

/* Console mode (for testing) */
static int run_console(void)
{
    printf("POOL service running in console mode. Press Ctrl+C to stop.\n");

    g_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    init_sessions();

    g_pipe_thread = CreateThread(NULL, 0, pipe_listener_thread, NULL, 0, NULL);

    pool_log_info("POOL console mode started, pipe: %ls", POOL_PIPE_NAME);

    WaitForSingleObject(g_stop_event, INFINITE);

    {
        int i;
        EnterCriticalSection(&g_session_lock);
        for (i = 0; i < POOL_MAX_WIN_SESSIONS; i++) {
            if (g_sessions[i].active)
                free_session(&g_sessions[i]);
        }
        LeaveCriticalSection(&g_session_lock);
    }

    WaitForSingleObject(g_pipe_thread, 5000);
    CloseHandle(g_pipe_thread);
    CloseHandle(g_stop_event);
    return 0;
}

int wmain(int argc, wchar_t *argv[])
{
    if (argc > 1) {
        if (wcscmp(argv[1], L"--install") == 0)
            return service_install();
        if (wcscmp(argv[1], L"--uninstall") == 0)
            return service_uninstall();
        if (wcscmp(argv[1], L"--console") == 0)
            return run_console();
        fprintf(stderr, "Usage: %ls [--install|--uninstall|--console]\n",
                argv[0]);
        return 1;
    }

    /* Run as service */
    SERVICE_TABLE_ENTRYW dispatch[] = {
        { (LPWSTR)POOL_SERVICE_NAME, service_main },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherW(dispatch)) {
        /* If not started as service, run in console mode */
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            return run_console();
        return 1;
    }
    return 0;
}

#endif /* _WIN32 */
