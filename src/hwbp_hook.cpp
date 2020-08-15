#pragma once
#include "hwbp_hook.hpp"

#ifdef _WIN64
#define XIP Rip
#else
#define XIP Eip
#endif

hook_manager hook_manager::_manager;

hook_manager& hook_manager::get() {
	return _manager;
}

__forceinline hwbp_hook* get_hook(PEXCEPTION_POINTERS info) {

	if (info == nullptr) return nullptr;

	for (auto& [name, data] : hook_manager::get().all()) {

		if (!data->hooked()) continue;

		if (info->ContextRecord->XIP == data->original<uintptr_t>())
			return data.get();
	}
	return nullptr;
}

#define SINGLE_STEP 0x100

LONG __stdcall _internal_handler(PEXCEPTION_POINTERS info) {

	if (info->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
		return EXCEPTION_CONTINUE_SEARCH;

	hwbp_hook* hk = get_hook(info);
	if (hk == nullptr)
		return EXCEPTION_CONTINUE_EXECUTION;

	info->ContextRecord->XIP = hk->hook_addr<uintptr_t>();

	return EXCEPTION_CONTINUE_EXECUTION;
}

bool hook_manager::init(PVECTORED_EXCEPTION_HANDLER handler) {

	if (_initialized) return true;

	if (!handler) handler = _internal_handler;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) return false;

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);

	DWORD process_id = GetCurrentProcessId();
	DWORD thread_id = GetCurrentThreadId();

	if (!Thread32First(snapshot, &te32)) {
		CloseHandle(snapshot);
		return false;
	}

	do {
		if (te32.th32OwnerProcessID != process_id)
			continue;

		HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 0, te32.th32ThreadID);
		if (h != INVALID_HANDLE_VALUE)
			_thread_handles.push_back(h);

	} while (Thread32Next(snapshot, &te32));

	CloseHandle(snapshot);

	_handle = AddVectoredExceptionHandler(1, handler);
	if (_handle != nullptr) {
		_handler = handler;
		_initialized = true;
		return true;
	}

	return false;
}

bool hook_manager::deinit() {

	if (!_initialized) return true;

	for (auto handle : _thread_handles)
		CloseHandle(handle);

	if (RemoveVectoredExceptionHandler(_handle)) {
		_initialized = false;
		_handle = nullptr;
		return true;
	}
	return false;
}

_mhooks& hook_manager::all() {
	return _hooks;
}

std::vector<HANDLE>* hook_manager::threads() {
	return &_thread_handles;
}

std::shared_ptr<hwbp_hook>& hook_manager::operator[](const std::string& hook) {

	if (_hooks.find(hook) != _hooks.end())
		return _hooks[hook];

	_hooks[hook] = std::make_shared<hwbp_hook>(this);
	return _hooks[hook];

}

hook_manager::~hook_manager() {
	if (_initialized) deinit();
}

hwbp_hook::hwbp_hook(hook_manager* manager) {
	_manager = manager;
}

hwbp_hook::~hwbp_hook() {
	if (_hooked) unhook();
}

bool hwbp_hook::hook(void* target, void* hook, HANDLE thread) {

	if (_hooked) return true;

	_original = target;
	_hook = hook;

	auto set_hook = [this](HANDLE thread, void* _original) -> bool {

		if (thread == INVALID_HANDLE_VALUE || thread == nullptr)
			return false;

		CONTEXT ctx;
		bool	freeReg = false;

		ZeroMemory(&ctx, sizeof(ctx));
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (!GetThreadContext(thread, &ctx)) return false;

		for (_register = 0; _register < 4; _register++) {
			if ((ctx.Dr7 & (1ULL << (_register * 2))) == 0) {
				freeReg = true;
				break;
			}
		}

		if (!freeReg) return false;

		switch (_register) {
		case 0: ctx.Dr0 = reinterpret_cast<uintptr_t>(_original); break;
		case 1: ctx.Dr1 = reinterpret_cast<uintptr_t>(_original); break;
		case 2: ctx.Dr2 = reinterpret_cast<uintptr_t>(_original); break;
		case 3: ctx.Dr3 = reinterpret_cast<uintptr_t>(_original); break;
		default: return false;
		}

		ctx.Dr7 &= ~(3ULL << (16 + 4 * _register));
		ctx.Dr7 &= ~(3ULL << (18 + 4 * _register));
		ctx.Dr7 |= 1ULL << (2 * _register);

		if (!SetThreadContext(thread, &ctx)) return false;

		return true;
	};

	if (thread == nullptr) {
		for (auto thread : *_manager->threads()) {
			set_hook(thread, _original);
		}
	}
	else
		set_hook(thread, _original);

	_hooked = true;
	return true;
}


bool hwbp_hook::unhook(HANDLE thread) {

	if (!_hooked) return true;

	if (thread != nullptr) {
		CONTEXT context;
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (GetThreadContext(thread, &context)) {
			context.Dr7 &= ~(1ULL << (2 * _register));
			SetThreadContext(thread, &context);
		}
	}

	else {
		for (auto thread : *_manager->threads()) {

			if (thread == INVALID_HANDLE_VALUE || thread == nullptr)
				continue;

			CONTEXT context;
			context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

			if (GetThreadContext(thread, &context)) {
				context.Dr0 = 0;

				context.Dr7 &= ~(1ULL << (2 * 0));

				SetThreadContext(thread, &context);
			}

		}
	}

	_hooked = false;
	return true;
}

bool hwbp_hook::rehook() {
	return this->hook(_original, _hook, GetCurrentThread());
}

bool hwbp_hook::hooked() {
	return _hooked;
}