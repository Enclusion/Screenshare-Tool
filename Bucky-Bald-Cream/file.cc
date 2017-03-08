#include "file.h"


namespace fs = boost::filesystem;


struct BoostPathHasher {
	size_t operator()(const fs::wpath& t) const {
		return hash_value(t);
	}
};


boost::optional<std::wstring> GetAppDataPath() {
	const auto app_data = L"APPDATA";
	const auto bufflen = GetEnvironmentVariable(app_data, nullptr, 0);
	if (bufflen > 0) {
		auto buffer = std::unique_ptr<wchar_t[]>(new wchar_t[bufflen]);
		auto strlen = bufflen - 1;
		if (GetEnvironmentVariable(app_data, buffer.get(), bufflen) == strlen) {
			return boost::optional<std::wstring>{std::wstring(buffer.get(), strlen)};
		}
	}
	return boost::optional<std::wstring>{};
}

boost::optional<fs::wpath> GetDefaultModsPath() {
	const wchar_t kModsPath[] = L"\\mods";
	const wchar_t kMinecraftPath[] = L"\\.minecraft";
	const auto app_data = GetAppDataPath();
	if (app_data) {
		auto mods_path = fs::wpath(*app_data + kMinecraftPath + kModsPath);
		return boost::optional<fs::wpath>{mods_path.remove_trailing_separator()};
	}
	return boost::optional<fs::wpath>{};
}

bool GetAllFilesInFolder(boost::filesystem::wpath folderPath, const std::wstring& jarExt, std::vector<fs::wpath>* files)
{
	try
	{
		if (exists(folderPath))
		{
			if (is_directory(folderPath))
			{
				for (fs::recursive_directory_iterator dir(folderPath), end; dir != end; ++dir) {

					if (!is_directory(*dir) && dir->path().extension() == jarExt) {
						files->push_back(dir->path());
					}

				}
				return true;
			}
		}
	}
	catch (const boost::filesystem::filesystem_error& ex)
	{
		std::cout << ex.what() << '\n';
	}
	return false;
}


std::string GetSha1(const std::string& data) {
	boost::uuids::detail::sha1 sha1;
	sha1.process_bytes(data.data(), data.size());

	unsigned hash[5] = { 0 };
	sha1.get_digest(hash);

	std::ostringstream oss;
	boost::algorithm::hex(boost::make_iterator_range(
		reinterpret_cast<const char*>(hash),
		reinterpret_cast<const char*>(hash + 5)),
		std::ostream_iterator<char>(oss));

	return oss.str();
}

bool HashMods(std::vector<std::string> hashes) {
	const wchar_t kJarExt[] = L".jar";
	std::vector<fs::wpath> files;

	auto default_mods_path = GetDefaultModsPath();

	if (default_mods_path) {

		std::unordered_set<fs::wpath, BoostPathHasher> mods_directories;
		mods_directories.emplace(*default_mods_path);

		for (auto it = mods_directories.begin(); it != mods_directories.end(); it++) {

			fs::wpath mPath(it->wstring());

			if (GetAllFilesInFolder(mPath, kJarExt, &files)) {
				for (auto it = files.begin(); it != files.end(); it++) {
					hashes.push_back(GetSha1(it->string()));
				}
				return true;
			}
		}
	}
	return false;
}