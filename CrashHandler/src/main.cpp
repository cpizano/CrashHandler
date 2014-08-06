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

class EventThread {
  static const int kEventCount = 60;
  HANDLE events_[kEventCount];
  size_t event_index_;

  static DWORD __stdcall WaitRoutine(void* ctx) {
    EventThread* event_thread = reinterpret_cast<EventThread*>(ctx);
    while (true) {
      DWORD wr = ::WaitForMultipleObjectsEx(
          kEventCount, event_thread->events_, FALSE, INFINITE, TRUE);
      if (wr < kEventCount)
        event_thread->OnEvent(wr);
      else if (wr == WAIT_IO_COMPLETION)
        break;
      else
        __debugbreak();
    }
    return 0;
  }

public:
  EventThread() : event_index_(0) {
    for (int ix = 0; ix != kEventCount; ++ix) {
      events_[ix] = ::CreateEvent(NULL, FALSE, FALSE, NULL);
    }
    ::CreateThread(NULL, 0, &WaitRoutine, this, 0, NULL);
  }

  HANDLE GetEvent(HANDLE process) {
    HANDLE event = NULL;
    if (!::DuplicateHandle(::GetCurrentProcess(), events_[event_index_],
                           process, &event,
                           SYNCHRONIZE, FALSE, 0))
      return NULL;
    event_index_++;
    return event;
  }

  void OnEvent(size_t index) {

  }

};


class CrashService {
  HANDLE pipe_;

  struct ClientRecord {
    HANDLE process;
    HANDLE dump_done;
    HANDLE dump_request;
    DWORD pid;

    ClientRecord(DWORD pid)
        : process(NULL), dump_done(NULL), dump_request(NULL), pid(pid) {
    }
  };

  EventThread event_thread_;
  std::vector<ClientRecord> clients_;
  
public:
  CrashService() {
    pipe_ = ::CreateNamedPipe(kPipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
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
        cab.signal_event = event_thread_.GetEvent(client.process);
        client.dump_done = ::CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!::DuplicateHandle(::GetCurrentProcess(), client.dump_done,
                               client.process, &cab.wait_event,
                               SYNCHRONIZE, FALSE, 0))
          break;
        DWORD written = 0;
        if (!::WriteFile(pipe_, &cab, sizeof(cab), &written, NULL))
          break;
        clients_.emplace_back(client);
        break;
      }
      ::DisconnectNamedPipe(pipe_);
    }
  }

  CrashService(const CrashService&) = delete;

};

///////////////////////////////////////////////////////////////////////////////

void DoEvenMoreWork(int x) {
#if 1
  if (!x)
    __debugbreak();
#endif
}

void DoSomeWork() {
  static int x = 0;
  if (!x)
    DoEvenMoreWork(x);
  x++;
}

int Client() {
  CrashClient crash_client;
  while (true) {
    ::Sleep(20);
    DoSomeWork();
  }
  return 0;
}

int Server() {
  CrashService crash_service;
  crash_service.Run();
  ::Sleep(200000);
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