#pragma once
#pragma once

#include <map>
#include <string>
#include <memory>
#include <vector>
#include <type_traits>

#include <Windows.h>
#include <tlhelp32.h>

class hook_manager;

class hwbp_hook {
public:
	hwbp_hook(hook_manager* manager);
	~hwbp_hook();

	bool hook(void* target, void* hook, HANDLE thread = nullptr);
	bool unhook(HANDLE thread = nullptr);
	bool rehook();
	bool hooked();

	template <class T, class... Args>
	constexpr T call(Args... args) {
		if constexpr (!std::is_same<T, void>::value) {
			T t;
			if (!_hooked) return T(0);
			if (!unhook(GetCurrentThread())) return T(0);
			t = original<T(*)(Args...)>()(args...);
			if (!rehook()) return T(0);
			return t;
		}
		else {
			if (!_hooked) return;
			if (!unhook(GetCurrentThread())) return;
			original<T(*)(Args...)>()(args...);
			rehook();
		}
	}

	template <class T>
	T original();
	template <class T>
	T hook_addr();

private:
	char _register = 0;
	CONTEXT* _ctx = nullptr;
	hook_manager* _manager = nullptr;
	void* _original = nullptr;
	void* _hook = nullptr;
	bool _hooked = false;
	bool _original_call = false;
};

template<class T>
inline T hwbp_hook::original() {
	return reinterpret_cast<T>(_original);
}

template<class T>
inline T hwbp_hook::hook_addr() {
	return reinterpret_cast<T>(_hook);
}


using _mhooks = std::map<std::string, std::shared_ptr<hwbp_hook>>;

class hook_manager {
public:
	static hook_manager& get();

	bool init(PVECTORED_EXCEPTION_HANDLER handler = nullptr);
	bool deinit();
	_mhooks& all();

	std::vector<HANDLE>* threads();
	std::shared_ptr<hwbp_hook>& operator[](const std::string& hook);

private:
	hook_manager() = default;
	~hook_manager();
	hook_manager(const hook_manager&) = delete;
	hook_manager& operator=(const hook_manager&) = delete;

private:
	static hook_manager _manager;
	bool _initialized = false;
	_mhooks _hooks = {};
	void* _handle = nullptr;
	std::vector<HANDLE> _thread_handles;
	PVECTORED_EXCEPTION_HANDLER _handler = nullptr;
};