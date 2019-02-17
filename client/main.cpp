#include <Windows.h>

#include "main.h"
#include "log.h"
#include "net.h"

static LONG OrigWndProc = NULL;
static bool keys[256] = { false };

LRESULT WINAPI HookWndProc(HWND hWnd, UINT msg, WPARAM wParam, UINT lParam) {
	
	switch (msg) {
	case WM_KEYDOWN:
		if (!keys[wParam]) {
			BitStream bs;
			bs.Write(KL_PACKET_KEYDOWN);
			bs.Write(wParam);
			net::send(&bs);
			keys[wParam] = true;
		} break;
	case WM_KEYUP:
		if (keys[wParam]) {
			BitStream bs;
			bs.Write(KL_PACKET_KEYUP);
			bs.Write(wParam);
			net::send(&bs);
			keys[wParam] = false;
		} break;
	case WM_CLOSE: {
		logger::free();
	} break;
	}

	return CallWindowProc((WNDPROC)(OrigWndProc), hWnd, msg, wParam, lParam);

}

DWORD WINAPI MainThread(HMODULE hModule) {
	while (!*(HWND*)(0xC97C1C)) Sleep(10);
	OrigWndProc = SetWindowLong(*(HWND*)(0xC97C1C), GWL_WNDPROC, (LONG)(&HookWndProc));
	return EXIT_SUCCESS;
}

BOOL APIENTRY DllMain(
	HMODULE hModule,
	DWORD dwReasonForCall,
	LPVOID lpReserved
) {
	switch (dwReasonForCall) {
	case DLL_PROCESS_ATTACH:
		return (logger::init() && net::init((uint32_t)(LoadLibrary("samp.dll"))) && CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(MainThread), hModule, 0, NULL));
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	} return TRUE;
}
