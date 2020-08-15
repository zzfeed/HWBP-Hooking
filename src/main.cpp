#pragma once

#include "hwbp_hook.hpp"
#include <cstdio>

void hk_Sleep(DWORD dur) {
	printf("hk_Sleep: %d\n", dur);
	hook_manager::get()["Sleep"]->call<void>(dur);
}

BOOL hk_Beep(DWORD freq, DWORD dur) {
	printf("hk_Beep: %d - %d\n", freq, dur);
	return hook_manager::get()["Beep"]->call<BOOL>(freq, dur);
}

//	output: 
//	hk_Sleep: 1000
//	hk_Beep: 100 - 100

int main() {

	auto& mgr = hook_manager::get();

	mgr.init();
	mgr["Sleep"]->hook(Sleep, hk_Sleep);
	mgr["Beep"]->hook(Beep, hk_Beep);

	Sleep(1000);
	Beep(100, 100);

	return 0;
}