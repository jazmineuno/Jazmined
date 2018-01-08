// Copyright 2018 Waitman Gobble
// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "stdafx.h"
#include "SignalHandler.h"
#include <mutex>
#include <iostream>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace {

	std::function<void(void)> m_handler;

	void handleSignal() {
		static std::mutex m_mutex;
		std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
		if (!lock.owns_lock()) {
			return;
		}
		m_handler();
	}


	BOOL WINAPI winHandler(DWORD type) {
		if (CTRL_C_EVENT == type || CTRL_BREAK_EVENT == type) {
			handleSignal();
			return TRUE;
		}
		else {
			std::cerr << "Got control signal " << type << ". Exiting without saving...";
			return FALSE;
		}
		return TRUE;
	}


}


namespace Tools {

	bool SignalHandler::install(std::function<void(void)> t)
	{

		bool r = TRUE == ::SetConsoleCtrlHandler(&winHandler, TRUE);
		if (r) {
			m_handler = t;
		}
		return r;
	}

}
