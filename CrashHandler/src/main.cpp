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

class CrashClient {
  MINIDUMP_EXCEPTION_INFORMATION mexinfo_;
  CrashRegistrationBlock crb_;
  CrashACKBlock cab_;
  
  static CrashClient* global_client;

public:
  CrashClient() {
    crb_.pid = ::GetCurrentProcessId();
    crb_.tid = ::GetCurrentThreadId();
    crb_.mex = &mexinfo_;
    // Async registration.
    ::QueueUserWorkItem(&Register, this, 0);
    global_client = this;
  }

  CrashClient(const CrashClient&) = delete;
  
private:
  static DWORD __stdcall Register(void* ctx) {
    CrashClient* client = reinterpret_cast< CrashClient*>(ctx);
    DWORD read = 0;
    if (::CallNamedPipe(kPipeName,
                        &client->crb_, sizeof(client->crb_),
                        &client->cab_, sizeof(client->cab_),
                        &read, 200000)) {
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
};

CrashClient* CrashClient::global_client = nullptr;

///////////////////////////////////////////////////////////////////////////////

HANDLE CreateAutoResetEvent() {
  return ::CreateEvent(NULL, TRUE, FALSE, NULL);
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
  HANDLE pipe_;

  struct ClientRecord {
    DWORD pid;
    HANDLE process;
    HANDLE dump_done;
    HANDLE dump_request;
    HANDLE dump_tpr;
    HANDLE process_tpr;
    
    ClientRecord(DWORD pid)
      : pid(pid),
        process(NULL),
        dump_done(NULL),
        dump_request(NULL),
        dump_tpr(NULL),
        process_tpr(NULL) {
    }
  };

  std::vector<ClientRecord> clients_;

  static void __stdcall OnDumpEvent(void* ctx, BOOLEAN) {

  }

  static void __stdcall OnProcessEnd(void* ctx, BOOLEAN) {

  }
  
public:
  CrashService() {
    pipe_ = ::CreateNamedPipe(kPipeName,
        PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,
        1,
        512, 512,
        20,
        NULL);
  }

  void Run() {
    CrashRegistrationBlock crb;
    while (true) {
      while (true) {
        if (!::ConnectNamedPipe(pipe_, NULL))
          return;
        DWORD read = 0;
        if (!::ReadFile(pipe_, &crb, sizeof(crb), &read, NULL))
          break;
        if (read != sizeof(crb))
          break;
        if (crb.pid < 8)
          break;
        DWORD real_pid = 0;
        ::GetNamedPipeClientProcessId(pipe_, &real_pid);
        if (crb.pid != real_pid)
          break;
        ClientRecord client(crb.pid);
        client.process = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, crb.pid);
        if (!client.process) {
          if (!::ImpersonateNamedPipeClient(pipe_))
            break;
          client.process = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, crb.pid);
          ::RevertToSelf();
          if (!client.process)
            break;
        }

        CrashACKBlock cab;
        client.dump_request = CreateAutoResetEvent();
        client.dump_done = CreateAutoResetEvent();
        cab.wait_event = DuplicateEvent(client.process, client.dump_done);
        cab.signal_event = DuplicateEvent(client.process, client.dump_request);
        if ((cab.wait_event == NULL) || (cab.signal_event == NULL))
          break;

        DWORD written = 0;
        if (!::WriteFile(pipe_, &cab, sizeof(cab), &written, NULL))
          break;

        ::RegisterWaitForSingleObject(&client.dump_tpr,
                                      client.dump_request,
                                      &OnDumpEvent, new ClientRecord(client),
                                      INFINITE, WT_EXECUTEDEFAULT);

        ::RegisterWaitForSingleObject(&client.process_tpr,
                                      client.process,
                                      &OnDumpEvent, new ClientRecord(client),
                                      INFINITE, WT_EXECUTEONLYONCE);

        clients_.emplace_back(client);
        wprintf(L"client pid=%d registered\n", client.pid);
        break;
      }
      wprintf(L"registration done. %d registered client(s)\n", clients_.size());
      ::DisconnectNamedPipe(pipe_);
    }
  }

  CrashService(const CrashService&) = delete;

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
  CrashService crash_service;
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