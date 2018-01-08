// Copyright 2018 Waitman Gobble
// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "stdafx.h"
#include "Util.h"
#include <cstdio>

#include <boost/filesystem.hpp>

#include "CryptoNoteConfig.h"

#include <windows.h>
#include <shlobj.h>
#include <strsafe.h>


namespace Tools
{
	std::string get_windows_version_display_string()
	{
		std::string pszOS = "MS Windows";
		return pszOS;
	}


	std::string get_os_version_string()
	{
		return get_windows_version_display_string();
	}



	std::string get_special_folder_path(int nfolder, bool iscreate)
	{
		namespace fs = boost::filesystem;
		char psz_path[MAX_PATH] = "";

		if (SHGetSpecialFolderPathA(NULL, psz_path, nfolder, iscreate)) {
			return psz_path;
		}

		return "";
	}

	std::string getDefaultDataDirectory()
	{
		std::string config_folder;
		config_folder = get_special_folder_path(CSIDL_APPDATA, true) + "\\" + CryptoNote::CRYPTONOTE_NAME;
		return config_folder;
	}

	bool create_directories_if_necessary(const std::string& path)
	{
		namespace fs = boost::filesystem;
		boost::system::error_code ec;
		fs::path fs_path(path);
		if (fs::is_directory(fs_path, ec)) {
			return true;
		}

		return fs::create_directories(fs_path, ec);
	}

	std::error_code replace_file(const std::string& replacement_name, const std::string& replaced_name)
	{
		int code;
		// Maximizing chances for success
		DWORD attributes = ::GetFileAttributes(((LPCWSTR)replaced_name.c_str()));
		if (INVALID_FILE_ATTRIBUTES != attributes)
		{
			::SetFileAttributes((LPCWSTR)replaced_name.c_str(), attributes & (~FILE_ATTRIBUTE_READONLY));
		}

		bool ok = 0 != ::MoveFileEx((LPCWSTR)replacement_name.c_str(), (LPCWSTR)replaced_name.c_str(), MOVEFILE_REPLACE_EXISTING);
		code = ok ? 0 : static_cast<int>(::GetLastError());
		return std::error_code(code, std::system_category());
	}

	bool directoryExists(const std::string& path) {
		boost::system::error_code ec;
		return boost::filesystem::is_directory(path, ec);
	}

}
