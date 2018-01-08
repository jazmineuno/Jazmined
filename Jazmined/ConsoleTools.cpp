// Copyright 2018 Waitman Gobble
// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "stdafx.h"
#include "ConsoleTools.h"

#include <stdio.h>

#include <Windows.h>
#include <io.h>

namespace Common {
	namespace Console {

		bool isConsoleTty() {
			static bool istty = 0 != _isatty(_fileno(stdout));
			return istty;
		}

		void setTextColor(Color color) {
			if (!isConsoleTty()) {
				return;
			}

			if (color > Color::BrightMagenta) {
				color = Color::Default;
			}


			static WORD winColors[] = {
				// default
				FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
				// main
				FOREGROUND_BLUE,
				FOREGROUND_GREEN,
				FOREGROUND_RED,
				FOREGROUND_RED | FOREGROUND_GREEN,
				FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
				FOREGROUND_GREEN | FOREGROUND_BLUE,
				FOREGROUND_RED | FOREGROUND_BLUE,
				// bright
				FOREGROUND_BLUE | FOREGROUND_INTENSITY,
				FOREGROUND_GREEN | FOREGROUND_INTENSITY,
				FOREGROUND_RED | FOREGROUND_INTENSITY,
				FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
				FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
				FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
				FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY
			};

			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), winColors[static_cast<size_t>(color)]);


		}

	}
}
