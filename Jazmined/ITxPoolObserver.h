// Copyright 2018 Waitman Gobble
// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

namespace CryptoNote {
	class ITxPoolObserver {
	public:
		~ITxPoolObserver() { }

		virtual void txDeletedFromPool() = 0;
	};
}
