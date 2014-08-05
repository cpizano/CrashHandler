#include <SDKDDKVer.h>

#include <stdio.h>
#include <tchar.h>
#include <string>

#include <Windows.h>

const wchar_t kPipeName[] = L"\\\\.\\pipe\\crash_srv_pipe";

struct CrashInfoBlock {
  char header[6];
  DWORD pid;
  DWORD tid;
  int checksum;
  EXCEPTION_RECORD* er;

  CrashInfoBlock() : pid(0), tid(0), checksum(0), er(nullptr) {
    memcpy(header, "dump10", sizeof(header));
    pid = ::GetCurrentProcessId();
  }
};

class CrashClient {
  volatile HANDLE pipe_;
  CrashInfoBlock* cib_;

  static CrashClient* global_client;

public:
  CrashClient() : pipe_(0), cib_(nullptr) {
    ::QueueUserWorkItem(&OpenPipe, this, 0);
    cib_ = new CrashInfoBlock;
  }

  CrashClient(const CrashClient&) = delete;
  
private:
  static DWORD __stdcall OpenPipe(void* ctx) {
    CrashClient* client = reinterpret_cast< CrashClient*>(ctx);
    HANDLE pipe = ::CreateFile(kPipeName,
                               GENERIC_READ | GENERIC_WRITE, 0,
                               NULL,
                               OPEN_EXISTING, 0,
                               NULL);
    if (pipe != INVALID_HANDLE_VALUE) {
      _InlineInterlockedExchangePointer(&client->pipe_, pipe);
      _InlineInterlockedExchangePointer(reinterpret_cast<void**>(&global_client), client);
      ::SetUnhandledExceptionFilter(ExHandler);
    }
    return 0;
  }

  static LONG __stdcall ExHandler(PEXCEPTION_POINTERS ex_info) {
    CrashInfoBlock& cib = *global_client->cib_;
    HANDLE pipe = global_client->pipe_;
    cib.er = ex_info->ExceptionRecord;
    cib.tid = ::GetCurrentThreadId();
    DWORD written = 0;
    if (::WriteFile(pipe, &cib, sizeof(cib), &written, NULL)) {
      ::Sleep(200000);
    }
    return EXCEPTION_EXECUTE_HANDLER;
  }
};

CrashClient* CrashClient::global_client = nullptr;

/////////////////////////////////////////////////////////////////////////////////////////////////////////

class CrashService {
  HANDLE pipe_;

public:
  CrashService() {
    pipe_ = ::CreateNamedPipe(kPipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,    
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        3,
        512, 512,
        20,            
        NULL);
  }

  CrashService(const CrashService&) = delete;

};

/////////////////////////////////////////////////////////////////////////////////////////////////////////

void DoEvenMoreWork(int x) {
  Sleep(10);
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
  CrashClient crash_client;
  DoSomeWork();
  return 0;
}

int Server() {

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