// Copyright 2018 Waitman Gobble
// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "stdafx.h"
#include <new>

#include "hash.h"
#include <Windows.h>

using std::bad_alloc;

namespace Crypto {

	enum {
		MAP_SIZE = SLOW_HASH_CONTEXT_SIZE + ((-SLOW_HASH_CONTEXT_SIZE) & 0xfff)
	};

	cn_context::cn_context(void) {
		data = VirtualAlloc(nullptr, MAP_SIZE, MEM_COMMIT, PAGE_READWRITE);
		if (data == nullptr) {
			throw bad_alloc();
		}
	}

	cn_context::~cn_context(void) noexcept(false) {
		if (!VirtualFree(data, 0, MEM_RELEASE)) {
			throw bad_alloc();
		}
	}


}
