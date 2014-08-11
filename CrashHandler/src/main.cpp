//////////////////////////////////////////////////////////////////////////
// This is a proof of concept for a new crash handler client for windows
// based on the experience with google's breakpad. 
//
// Just like breakpad out-of-process mode, there basic operation
// is based on named pipes and has an initial phase or registration
// between client and server, later possibly a dump request event
// and eventually a end-of-life event for the client.
//
// Also like breakpad the request of a dump is based on signaling
// an event and wait on another, these obtained during the registration
// phase.
//
// It is meant to be better than breakpad in a number of areas:
// Server:
// 1- Stateless design. There is no central list of registered clients
//    and the resulting mass of code and overhead of lookup/add/removal.
//    All the state is implicitly mantained by the windows thread pool.
// 2- Multi-threaded. Servicing the registrations over the pipe is done
//    by multiple threads, speeding up the registration greatly.
// 3- Synchronous pipe operations. Both faster and the resulting code
//    is simpler than breakpad.
// 4- Clean theadpool handles management. In breakpad we never got a
//    handle on the right way or time to call UnregisterWait(). This
//    version gets it right.
//

#include <SDKDDKVer.h>

#include <stdio.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <array>

#include <Windows.h>
#include <DbgHelp.h>

const wchar_t kPipeName[] = L"\\\\.\\pipe\\crash_srv_pipe";

struct CrashRegistrationBlock {
  char header[8];
  DWORD pid;
  DWORD tid;
  MINIDUMP_EXCEPTION_INFORMATION* mex;

  CrashRegistrationBlock()
      : pid(0), tid(0), mex(nullptr) {
    memcpy(header, "dumpv100", sizeof(header));
    pid = ::GetCurrentProcessId();
  }
};

struct CrashACKBlock {
  char header[8];
  HANDLE signal_event;
  HANDLE wait_event;

  CrashACKBlock()
    : signal_event(NULL), wait_event(NULL) {
    memcpy(header, "dumpack1", sizeof(header));
  }
};

// Takes care of using SECURITY_IDENTIFICATION so the pipes server cannot
// impersonate us.
bool SafeCallNamedPipe(
  const wchar_t* name,
  void* send, DWORD send_size,
  void* recv, DWORD recv_size,
  DWORD* read, int retries) {
  HANDLE pipe;
  while (true) {
    pipe = ::CreateFile(
        name,
        GENERIC_READ | GENERIC_WRITE,
        0, 
        NULL,
        OPEN_EXISTING,
        SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
        NULL);
    if (pipe != INVALID_HANDLE_VALUE)
      break;
    if (!retries) {
      return false;
    } else {
      --retries;
      ::Sleep(10);
    }
  }
  DWORD mode = PIPE_READMODE_MESSAGE;
  ::SetNamedPipeHandleState(pipe, &mode, NULL, NULL);
  return  TRUE == ::TransactNamedPipe(pipe, send, send_size, recv, recv_size, read, NULL);
}

class CrashClient {
public:
  CrashClient() {
    crb_.pid = ::GetCurrentProcessId();
    crb_.tid = ::GetCurrentThreadId();
    crb_.mex = &mexinfo_;
    // Async registration. Not sure this is a good idea.
    ::QueueUserWorkItem(&Register, this, 0);
    global_client = this;
  }

  CrashClient(const CrashClient&) = delete;
  
private:
  static DWORD __stdcall Register(void* ctx) {
    CrashClient* client = reinterpret_cast< CrashClient*>(ctx);
    DWORD read = 0;
    // CallNamedPipe has the disadvantage that the token can be stolen
    // if an adversary is squating on the named pipe.
    if (SafeCallNamedPipe(kPipeName,
                        &client->crb_, sizeof(client->crb_),
                        &client->cab_, sizeof(client->cab_),
                        &read, 3)) {
      if (client->cab_.signal_event && client->cab_.wait_event)
        ::SetUnhandledExceptionFilter(ExHandler);
    }
    return 0;
  }

  static LONG __stdcall ExHandler(PEXCEPTION_POINTERS ex_ptrs) {
    CrashACKBlock& cab = global_client->cab_;
    CrashRegistrationBlock& crb = global_client->crb_;
    crb.mex->ThreadId = ::GetCurrentThreadId();
    crb.mex->ClientPointers = TRUE;
    crb.mex->ExceptionPointers = ex_ptrs;

    ::SignalObjectAndWait(cab.signal_event, cab.wait_event, 20000, FALSE);
    return EXCEPTION_EXECUTE_HANDLER;
  }

  MINIDUMP_EXCEPTION_INFORMATION mexinfo_;
  CrashRegistrationBlock crb_;
  CrashACKBlock cab_;
  
  static CrashClient* global_client;
};

CrashClient* CrashClient::global_client = nullptr;

///////////////////////////////////////////////////////////////////////////////

HANDLE CreateAutoResetEvent() {
  return ::CreateEventW(NULL, FALSE, FALSE, NULL);
}

HANDLE DuplicateEvent(HANDLE process, HANDLE event) {
  HANDLE handle;
  return ::DuplicateHandle(
      ::GetCurrentProcess(), event,
      process, &handle,
      SYNCHRONIZE|EVENT_MODIFY_STATE, FALSE, 0) ?
        handle : NULL;
}

class CrashService {  
public:
  CrashService(int pipe_instances) {
    port_ = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);

    for (int ix = 0; ix != pipe_instances; ++ix) {
      HANDLE pipe = ::CreateNamedPipe(kPipeName,
          PIPE_ACCESS_DUPLEX,
          PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,
          pipe_instances,
          512, 512,
          20,
          NULL);
      SvcContext* contex = new SvcContext(port_, pipe);
      ::CreateThread(NULL, 0, &PipeServiceProc, contex, 0, NULL);
    }
  }

  CrashService(const CrashService&) = delete;

  void Run() {
    OVERLAPPED* ov = nullptr;
    ULONG_PTR key = 0;
    DWORD bytes = 0;
    int client_count = 0;
    int dumps_taken = 0;

    while (true) {
      ::GetQueuedCompletionStatus(port_, &bytes, &key, &ov, INFINITE);
      if (!key)
        break;
      ClientRecord* client = reinterpret_cast<ClientRecord*>(key);
      switch (client->state) {
        case kRegisterClient:
          wprintf(L"client registered with pid=%d\n", client->pid);
          ++client_count;
          break;
        case kUnRegisterClient:
          ::UnregisterWait(client->dump_tpr);
          ::UnregisterWait(client->process_tpr);
          ::CloseHandle(client->dump_done);
          ::CloseHandle(client->dump_request);
          wprintf(L"client unregistered with pid=%d\n", client->pid);
          --client_count;
          break;
        case kDumpready:
          ++dumps_taken;
          wprintf(L"client dump ready with pid=%d\n", client->pid);
          break;
        default:
          __debugbreak();
          break;
      }
      delete client;
    }
  }

  static DWORD __stdcall PipeServiceProc(void* ctx) {
    SvcContext* svc_context = reinterpret_cast<SvcContext*>(ctx);

    CrashRegistrationBlock crb;
    while (true) {
      while (true) {
        // Connect can return false if the client connects before we get here.
        // Best bet is to just try to read from the pipe.
        ::ConnectNamedPipe(svc_context->pipe, NULL);
        DWORD read = 0;
        if (!::ReadFile(svc_context->pipe, &crb, sizeof(crb), &read, NULL))
          break;
        if (read != sizeof(crb))
          break;
        if (crb.pid < 8)
          break;
        DWORD real_pid = 0;
        // The next function is only available in Vista+.
        ::GetNamedPipeClientProcessId(svc_context->pipe, &real_pid);
        if (crb.pid != real_pid)
          break;
        ClientRecord client(svc_context->main_port, kRegisterClient, crb.pid);
        client.process = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, crb.pid);
        if (!client.process) {
          if (!::ImpersonateNamedPipeClient(svc_context->pipe))
            break;
          client.process = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, crb.pid);
          ::RevertToSelf();
          if (!client.process)
            break;
        }

        client.dump_request = CreateAutoResetEvent();
        client.dump_done = CreateAutoResetEvent();

        CrashACKBlock cab;
        cab.wait_event = DuplicateEvent(client.process, client.dump_done);
        cab.signal_event = DuplicateEvent(client.process, client.dump_request);
        if ((cab.wait_event == NULL) || (cab.signal_event == NULL))
          break;

        DWORD written = 0;
        if (!::WriteFile(svc_context->pipe, &cab, sizeof(cab), &written, NULL))
          break;

        ::PostQueuedCompletionStatus(
            svc_context->main_port, 0, ULONG_PTR(new ClientRecord(client)), NULL);

        ::RegisterWaitForSingleObject(&client.dump_tpr,
                                      client.dump_request,
                                      &OnDumpEvent, new ClientRecord(client),
                                      INFINITE, WT_EXECUTEDEFAULT);

        ::RegisterWaitForSingleObject(&client.process_tpr,
                                      client.process,
                                      &OnProcessEnd, new ClientRecord(client),
                                      INFINITE, WT_EXECUTEONLYONCE);

        break;
      }
      ::DisconnectNamedPipe(svc_context->pipe);
    }
    return 0;
  }

private:
  enum State {
    kRegisterClient,
    kUnRegisterClient,
    kDumpready,
  };

  struct ClientRecord {
    HANDLE port;
    State state;
    DWORD pid;
    HANDLE process;
    HANDLE dump_done;
    HANDLE dump_request;
    HANDLE dump_tpr;
    HANDLE process_tpr;
    
    ClientRecord(HANDLE port, State state, DWORD pid)
      : port(port),
        state(state),
        pid(pid),
        process(NULL),
        dump_done(NULL),
        dump_request(NULL),
        dump_tpr(NULL),
        process_tpr(NULL) {
    }
  };

  struct SvcContext {
    HANDLE main_port;
    HANDLE pipe;

    SvcContext(HANDLE main_port, HANDLE pipe)
        : main_port(main_port), pipe(pipe) {
    }
  };

  static void __stdcall OnDumpEvent(void* ctx, BOOLEAN) {
    ClientRecord* client = reinterpret_cast<ClientRecord*>(ctx);
    client->state = kDumpready;
    
    // Capture dump here and write it to disk now.
    ::Sleep(10);
    ::SetEvent(client->dump_done);

    ::PostQueuedCompletionStatus(
        client->port, 0, ULONG_PTR(client), NULL);
  }

  static void __stdcall OnProcessEnd(void* ctx, BOOLEAN) {
    ClientRecord* client = reinterpret_cast<ClientRecord*>(ctx);
    client->state = kUnRegisterClient;
    ::PostQueuedCompletionStatus(
        client->port, 0, ULONG_PTR(client), NULL);
  }

  HANDLE port_;
};

///////////////////////////////////////////////////////////////////////////////

void DoEvenMoreWork(int x) {
  if (!x)
    __debugbreak();
}

void DoSomeWork() {
  static int x = 0;
  if (!x)
    DoEvenMoreWork(x);
  x++;
}

int Client() {
  wprintf(L"crash client\n");
  CrashClient crash_client;
  while (true) {
    ::Sleep(10000);
    DoSomeWork();
  }
  return 0;
}

int Server() {
  wprintf(L"crash server\n");
  CrashService crash_service(2);
  crash_service.Run();
  return 0;
}

int __cdecl wmain(int argc, wchar_t* argv[]) {
  if (argc < 2) {
    return Client();
  } else {
    if (argv[1] != std::wstring(L"--server"))
      return 1;
    return Server();
  }
}