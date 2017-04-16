#include "FileHelper.h"
#include "whereami.h"
#include <fstream>
#include <string\StringHelper.h>
#if defined(_MSC_VER)
#include "dirent.h"
#include <Dbghelp.h>
#include <io.h> 
#include <direct.h>
#include <Shellapi.h>
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Dbghelp.lib")
#elif defined(__GNUC__)
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#else
#error unsupported compiler
#endif

#if defined(_MSC_VER)
#define stat _stat
#define access _access
#define getcwd _getcwd
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

bool FileHelper::GetExecutablePath(std::string &full_path, std::string &dir)
{
    return GetPath(wai_getExecutablePath, full_path, dir);
}
/**
*get the module path, dll can use this function get module path
*full_path(out): module absolute path
*dir(out): module dir absolute path
*/
bool FileHelper::GetModulePath(std::string &full_path, std::string &dir)
{
    return GetPath(wai_getModulePath, full_path, dir);
}

/**
*get current work dir, if fail return empty
*/
std::string FileHelper::GetCurrentWorkDir()
{
    std::string result;
    char *path = getcwd(NULL, 0);
    if (path == NULL) return "";
    result = path;
    free(path);
    return std::move(result);
}

/**
*set current work dir
*/
bool FileHelper::SetCurrentWorkDir(const std::string &path)
{
    if (path.empty()) return false;
#if defined(_MSC_VER)
    return SetCurrentDirectoryA(path.c_str()) == 0 ? false : true;
#elif defined(__GNUC__)
    return chdir(path.c_str()) == 0 ? true : false;
#else
#error unsupported compiler
#endif
}

/**
*add the file separator at the end of the path, if it is not exist.
*note that you should input the dir path
*path(in/out): the path that you want make sure of the file separator at the end
*/
std::string & FileHelper::CoordinateFileSeparator(std::string &path)
{
    size_t nLength = path.length();
    if (!nLength) return path;
    if (OS_FILE_SEPARATOR == path.substr(nLength - 1)) return path;
    path += OS_FILE_SEPARATOR;
    return path;
}

/**
*add the file separator at the end of the path, if it is not exist.
*note that you should input the dir path
*path(in/out): the path that you want make sure of the file separator at the end
*/
std::string && FileHelper::CoordinateFileSeparator(std::string &&path)
{
    size_t nLength = path.length();
    if (!nLength) return std::move(path);
    if (OS_FILE_SEPARATOR == path.substr(nLength - 1)) return std::move(path);
    path += OS_FILE_SEPARATOR;
    return std::move(path);
}

/**
*add the file separator at the end of the path, if it is not exist.
*note that you should input the dir path
*path(in/out): the path that you want make sure of the file separator at the end
*/
std::string FileHelper::CoordinateFileSeparator(const std::string &path)
{
    std::string result = path;
    size_t nLength = result.length();
    if (!nLength) return result;
    if (OS_FILE_SEPARATOR == result.substr(nLength - 1)) return result;
    result += OS_FILE_SEPARATOR;
    return result;
}

/**
*get the absolute path of the path
*path(in): the path that you want to become absolute path, if it is absolute path, the function do nothing
*pwd(in): absolute dir for path "."
*/
std::string FileHelper::GetAbsolutePath(const std::string &path, const std::string &pwd)
{
    if (path.empty()) return "";
    std::string cur_work_dir = pwd;
    if (cur_work_dir.empty()) cur_work_dir = GetCurrentWorkDir();
    CoordinateFileSeparator(cur_work_dir);
    std::string tmp_path = path;

    std::string root_prefix = "root";
    bool has_root = false;
#if defined(_MSC_VER)
    if (tmp_path.size() >= 2 && tmp_path.c_str()[1] == ':') has_root = true;
#elif defined(__GNUC__)
    if (tmp_path.size() >= 1 && tmp_path.c_str()[0] == '/') has_root = true;
#else
#error unsupported compiler
#endif
    if (!has_root) tmp_path = cur_work_dir + tmp_path;
    tmp_path = root_prefix + tmp_path;

    bool add_file_separator = tmp_path.c_str()[tmp_path.size() - 1] == OS_FILE_SEPARATOR[0];
    std::vector<std::string> files = StringHelper::split(tmp_path, OS_FILE_SEPARATOR);
    std::vector<std::string> files_absolute;
    for (auto file : files)
    {
        if (file.empty()) continue;
        if (file == (".")) continue;
        if (file == (".."))
        {
            if (files_absolute.size() < 2) return "";
            files_absolute.erase(--files_absolute.end());
            continue;
        }
        files_absolute.push_back(std::move(file));
    }

    std::string result;
    auto it = files_absolute.begin();
    result += std::move(*it++);
    for (; it != files_absolute.end(); it++)
    {
        if ((*it).empty()) continue;
        result += OS_FILE_SEPARATOR + std::move(*it);
    }
    return std::string(result, root_prefix.size()) + (add_file_separator ? OS_FILE_SEPARATOR : "");
}

/**
*get the last name in path, in /abc/def out def, in /abc/def/ out def.
*path(in): the path you want to get the last name
*if failed, it will return empty string
*/
std::string FileHelper::GetLastNameInPath(const std::string &path)
{
    auto end = path.find_last_not_of(OS_FILE_SEPARATOR);
    if (end == std::string::npos) return "";
    auto start = path.find_last_of(OS_FILE_SEPARATOR, end);
    if (start == std::string::npos) return "";
    if (start >= end) return "";
    std::string dir_name = std::string(path, start + 1, end - start);
    return std::move(dir_name);
}

/**
*get the dir in path, in /abc/def out /abc/, in /abc/def/ out /abc/def/.
*path(in): the path you want to get the dir
*if failed, it will return empty string
*/
std::string FileHelper::GetDirInPath(const std::string &path)
{
    if (path.empty()) return "";
    if (std::string(path.c_str(), path.size() - 1, 1) == OS_FILE_SEPARATOR) return path;
    auto end = path.find_last_of(OS_FILE_SEPARATOR);
    if (end == std::string::npos) return "";
    std::string dir_name = std::string(path, 0, end + 1);
    return std::move(dir_name);
}

/**
*check if input path is a dir, and it is exist
*path(in): file path
*/
bool FileHelper::IsDir(const std::string &path)
{
    return FileStatCheck(path, S_IFDIR);
}

/**
*check if input path is a file, and it is exist
*path(in): file path
*/
bool FileHelper::IsFile(const std::string &path)
{
    return FileStatCheck(path, S_IFREG);
}

/**
*check if input path is exist
*path(in): file path
*/
bool FileHelper::IsExist(const std::string &path)
{
    if (path.empty()) return false;
    if (access(path.c_str(), 0)) return false;
    return true;
}

/**
*list the files under the dir_path
*dir_path(in): the dir path
*type(in): the file type you want to list, you can use LIST_FILE_REG, LIST_FILE_DIR, LIST_FILE_OTHER with bit mask
*recursive(in): if you want to list the files in the sub dir, you can set to true
*/
std::set<std::string> FileHelper::ListSubFiles(const std::string &dir_path, int type, bool recursive)
{
    std::set<std::string> result;
    std::string dir_name = dir_path;
    DIR *dir = NULL;
    struct dirent *ent = NULL;

    if (dir_name.empty()) return result;
    dir_name = GetAbsolutePath(dir_name);
    dir = opendir(dir_name.c_str());
    if (!dir) return result;
    CoordinateFileSeparator(dir_name);
    while ((ent = readdir(dir)) != NULL && result.size() <= LIST_FILE_MAX_NUM) {
        /* Decide what to do with the directory entry */
        switch (ent->d_type) {
        case DT_LNK:
        case DT_REG:
        {
            if (LIST_FILE_REG&type) result.insert(dir_name + ent->d_name);
            break;
        }
        case DT_DIR:
        {
            if (std::string(ent->d_name) == "." || std::string(ent->d_name) == "..") break;
            if (LIST_FILE_DIR&type) result.insert(dir_name + ent->d_name);
            if (!recursive) break;
            std::set<std::string> tmp;
            tmp = ListSubFiles(dir_name + ent->d_name, type, true);
            result.insert(tmp.begin(), tmp.end());
            break;
        }
        default:
            if (LIST_FILE_OTHER&type) result.insert(dir_name + ent->d_name);
            break;
        }
    }
    closedir(dir);
    return result;
}

/**
*make all the dirs of the dir_path
*dir_path(in): the dir path you want to make sure exist
*/
bool FileHelper::MkDir(const std::string &dir_path)
{
    if (dir_path.empty()) return false;
    std::string tmp_path = dir_path;
    CoordinateFileSeparator(tmp_path);
#if defined(_MSC_VER)
    return MakeSureDirectoryPathExists(tmp_path.c_str()) == TRUE ? true : false;
#elif defined(__GNUC__)
    std::vector<std::string> dir_names = StringHelper::split(tmp_path, OS_FILE_SEPARATOR);
    std::string root = tmp_path.c_str()[0] == '/' ? OS_FILE_SEPARATOR : "";
    bool ret = true;
    for (auto name : dir_names)
    {
        if (name.empty()) continue;
        root += name + OS_FILE_SEPARATOR;
        if (IsExist(root)) continue;
        if (!mkdir(root.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) continue;
        ret = false;
        break;
    }
    return ret;
#else
#error unsupported compiler
#endif
}

/**
*delete the file
*path(in): the path you want to delete
*can_recycle(in): windows only, if user can recycle from recycle bin
*/
bool FileHelper::Rm(const std::string &path, bool can_recycle)
{
    if (path.empty()) return false;
    if (!IsExist(path)) return true;
#if defined(_MSC_VER)
    char *buf = new (std::nothrow) char[path.size() + 2];
    if (!buf) return false;
    memcpy_s(buf, path.size() + 1, path.c_str(), path.size());
    memset(&buf[path.size()], 0, 2);
    SHFILEOPSTRUCTA s = { 0 };
    s.wFunc = FO_DELETE;
    s.pTo = NULL;
    s.pFrom = buf;
    s.fFlags = FOF_SILENT | FOF_NOCONFIRMMKDIR | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_NO_UI;
    s.fFlags |= can_recycle ? FOF_ALLOWUNDO : 0;
    int ret = SHFileOperationA(&s);
    delete[]buf;
    return  ret == 0 ? true : false;
#elif defined(__GNUC__)
    if (IsFile(path)) return remove(path.c_str()) == 0 ? true : false;
    std::set<std::string> files = ListSubFiles(path, LIST_FILE_REG | LIST_FILE_OTHER);
    for (auto file : files)
    {
        if (remove(file.c_str())) return false;
    }
    std::set<std::string> dirs = ListSubFiles(path, LIST_FILE_DIR);
    for (auto it = dirs.rbegin(); it != dirs.rend(); it++)
    {
        if (remove((*it).c_str())) return false;
    }
    return remove(path.c_str()) == 0 ? true : false;
#else
#error unsupported compiler
#endif
}

/**
*move the file to another
*src_path(in): the path you want to move from
*dst_path(in): the path you want to move to
*if src_path is file: if dst_path is exist dir, then move into dst dir;
if dst_path is exist file, then org file replace dst file;
if dst_path is not exist, and end with file separator, the src file move to dst  dir path
if dst_path is not exist, and end without file separator, the src file move to dst file path
if src_path is dir: if dst_path is exist file, then failed;
if dst_path is exist dir, then move src_dir into dst_path, if under dst_path has same name dir, merge them;
if dst_path is not exist dir, then move src_dir to dst_path;
*/
bool FileHelper::Mv(const std::string &src_path, const std::string &dst_path)
{
    if (src_path.empty()) return false;
    if (dst_path.empty()) return false;
    if (!IsExist(src_path)) return false;
    if (src_path == dst_path) return true;
    std::string tmp_dst_path = dst_path;
    if (IsDir(tmp_dst_path)) CoordinateFileSeparator(tmp_dst_path);
    if (IsFile(src_path) && (std::string(tmp_dst_path, tmp_dst_path.size() - 1) == OS_FILE_SEPARATOR)) tmp_dst_path += GetLastNameInPath(src_path);
#if defined(_MSC_VER)
    char *src_buf = new (std::nothrow) char[src_path.size() + 2];
    if (!src_buf) return false;
    memcpy_s(src_buf, src_path.size() + 1, src_path.c_str(), src_path.size());
    memset(&src_buf[src_path.size()], 0, 2);

    char *dst_buf = new (std::nothrow) char[tmp_dst_path.size() + 2];
    if (!dst_buf)
    {
        delete[]src_buf;
        return false;
    }
    memcpy_s(dst_buf, tmp_dst_path.size() + 1, tmp_dst_path.c_str(), tmp_dst_path.size());
    memset(&dst_buf[tmp_dst_path.size()], 0, 2);

    SHFILEOPSTRUCTA s = { 0 };
    s.wFunc = FO_MOVE;
    s.pTo = dst_buf;
    s.pFrom = src_buf;
    s.fFlags = FOF_SILENT | FOF_NOCONFIRMMKDIR | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_NO_UI;
    int ret = SHFileOperationA(&s);
    delete[]src_buf;
    delete[]dst_buf;
    return  ret == 0 ? true : false;
#elif defined(__GNUC__)
    if (IsDir(src_path))
    {
        if (IsFile(tmp_dst_path)) return false;
        std::string tmp_src_path = CoordinateFileSeparator(GetAbsolutePath(src_path));
        if (tmp_src_path.empty()) return false;
        std::string src_dir = GetLastNameInPath(tmp_src_path);
        if (src_dir.empty()) return false;
        GetAbsolutePath(tmp_dst_path);
        if (tmp_dst_path.empty()) return false;
        CoordinateFileSeparator(tmp_dst_path);
        if (IsExist(tmp_dst_path)) tmp_dst_path += src_dir + OS_FILE_SEPARATOR;
        if (!IsExist(tmp_dst_path)) MkDir(tmp_dst_path);

        auto all_src_dirs = ListSubFiles(tmp_src_path, LIST_FILE_DIR);
        for (auto src_dir : all_src_dirs)
        {
            std::string dst_dir = tmp_dst_path + std::string(src_dir, tmp_src_path.size());
            if (!IsExist(dst_dir)) MkDir(dst_dir);
        }

        auto all_src_files = ListSubFiles(tmp_src_path, LIST_FILE_REG | LIST_FILE_OTHER);
        for (auto src_file : all_src_files)
        {
            std::string dst_file = tmp_dst_path + std::string(src_file, tmp_src_path.size());
            rename(src_file.c_str(), dst_file.c_str());
        }
        Rm(tmp_src_path);
        return true;
    }

    if (IsFile(src_path))
    {
        MkDir(GetDirInPath(tmp_dst_path));
        return rename(src_path.c_str(), tmp_dst_path.c_str()) == 0 ? true : false;
    }

    return false;
#else
#error unsupported compiler
#endif
}

/**
*copy the file to another
*src_path(in): the path you want to copy from
*dst_path(in): the path you want to copy to
*if src_path is file: if dst_path is exist dir, then copy into dst dir;
if dst_path is exist file, then org file replace dst file;
if dst_path is not exist, and end with file separator, the src file copy to dst dir path
if dst_path is not exist, and end without file separator, the src file copy to dst file path
if src_path is dir:  if dst_path is exist file, then failed;
if dst_path is exist dir, then copy src_dir into dst_path, if under dst_path has same name dir, merge them;
if dst_path is not exist, then copy src_dir to dst_path;
*/
bool FileHelper::Cp(const std::string &src_path, const std::string &dst_path)
{
    if (src_path.empty()) return false;
    if (dst_path.empty()) return false;
    if (!IsExist(src_path)) return false;
    if (src_path == dst_path) return true;
    std::string tmp_dst_path = dst_path;
    if (IsDir(tmp_dst_path)) CoordinateFileSeparator(tmp_dst_path);
    if (IsFile(src_path) && (std::string(tmp_dst_path, tmp_dst_path.size() - 1) == OS_FILE_SEPARATOR)) tmp_dst_path += GetLastNameInPath(src_path);
#if defined(_MSC_VER)
    char *src_buf = new (std::nothrow) char[src_path.size() + 2];
    if (!src_buf) return false;
    memcpy_s(src_buf, src_path.size() + 1, src_path.c_str(), src_path.size());
    memset(&src_buf[src_path.size()], 0, 2);

    char *dst_buf = new (std::nothrow) char[tmp_dst_path.size() + 2];
    if (!dst_buf)
    {
        delete[]src_buf;
        return false;
    }
    memcpy_s(dst_buf, tmp_dst_path.size() + 1, tmp_dst_path.c_str(), tmp_dst_path.size());
    memset(&dst_buf[tmp_dst_path.size()], 0, 2);

    SHFILEOPSTRUCTA s = { 0 };
    s.wFunc = FO_COPY;
    s.pTo = dst_buf;
    s.pFrom = src_buf;
    s.fFlags = FOF_SILENT | FOF_NOCONFIRMMKDIR | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_NO_UI;
    int ret = SHFileOperationA(&s);
    delete[]src_buf;
    delete[]dst_buf;
    return  ret == 0 ? true : false;
#elif defined(__GNUC__)
    if (IsDir(src_path))
    {
        if (IsFile(tmp_dst_path)) return false;
        std::string tmp_src_path = CoordinateFileSeparator(GetAbsolutePath(src_path));
        if (tmp_src_path.empty()) return false;
        std::string src_dir = GetLastNameInPath(tmp_src_path);
        if (src_dir.empty()) return false;
        GetAbsolutePath(tmp_dst_path);
        if (tmp_dst_path.empty()) return false;
        CoordinateFileSeparator(tmp_dst_path);
        if (IsExist(tmp_dst_path)) tmp_dst_path += src_dir + OS_FILE_SEPARATOR;
        if (!IsExist(tmp_dst_path)) MkDir(tmp_dst_path);

        auto all_src_dirs = ListSubFiles(tmp_src_path, LIST_FILE_DIR);
        for (auto src_dir : all_src_dirs)
        {
            std::string dst_dir = tmp_dst_path + std::string(src_dir, tmp_src_path.size());
            if (!IsExist(dst_dir)) MkDir(dst_dir);
        }

        auto all_src_files = ListSubFiles(tmp_src_path, LIST_FILE_REG | LIST_FILE_OTHER);
        for (auto src_file : all_src_files)
        {
            std::string dst_file = tmp_dst_path + std::string(src_file, tmp_src_path.size());
            link(src_file.c_str(), dst_file.c_str());
        }
        return true;
    }

    if (IsFile(src_path))
    {
        MkDir(GetDirInPath(tmp_dst_path));
        return link(src_path.c_str(), tmp_dst_path.c_str()) == 0 ? true : false;
    }

    return false;
#else
#error unsupported compiler
#endif
}

/**
*get the file size in byte
*file_path(in): file path
*/
size_t FileHelper::GetFileSize(const std::string &file_path)
{
    if (!IsFile(file_path)) return 0;
    std::ifstream file(file_path, std::ios::binary);
    if (!file.good()) return 0;
    file.seekg(0, std::ios::end);
    auto size = file.tellg();
    if (size == (decltype(size))-1) return 0;
    if (!file.good()) return 0;
    file.seekg(0, std::ios::beg);
    return (size_t)size;
}

/**
*get the file content
*file_path(in): the file path
*you can get all file content bytes in return string.c_str()
*/
std::string FileHelper::GetFileContent(const std::string& file_path)
{
    std::ifstream fs(file_path.c_str());
    if (!fs) return "";
    std::ostringstream buffer;
    buffer << fs.rdbuf();
    return buffer.str();
}

/**
*get the file content
*file_path(in): the file path
*/
bool FileHelper::SetFileContent(const std::string& file_path, const char *buf, size_t buf_size, bool append)
{
    if (buf == NULL) return false;
    if (!buf_size) return true;
    std::ofstream file(file_path, std::ios::binary | (append ? std::ios::app : (decltype(std::ios::binary))0));
    if (!file) return false;
    file.write(buf, buf_size);
    if (!file.good()) return false;
    return true;
}

#if defined(_MSC_VER)
/**
*get windows %temp% path
*/
std::string FileHelper::GetWinTempPath()
{
    char path[PATH_MAX + 1] = { 0 };
    if (!GetTempPathA(PATH_MAX, path)) return "";
    return path;
}

/**
*get windows path
*/
std::string FileHelper::GetWinTypePath(int type)
{
    char m_lpszDefaultDir[PATH_MAX + 1] = { 0 };
    char szDocument[PATH_MAX + 1] = { 0 };
    LPITEMIDLIST pidl = NULL;

    do
    {
        if (SHGetSpecialFolderLocation(NULL, type, &pidl) != S_OK) break;
        if (!SHGetPathFromIDListA(pidl, szDocument)) break;
        if (!GetShortPathNameA(szDocument, m_lpszDefaultDir, PATH_MAX)) break;
    } while (0);
    if (pidl)  CoTaskMemFree(pidl);

    return m_lpszDefaultDir;
}
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

bool FileHelper::GetPath(GetPathFun fun, std::string &full_path, std::string &dir)
{
    int length = fun(NULL, 0, NULL);
    if (length <= 0) return false;
    char *buf = new (std::nothrow) char[length + 1];
    if (buf == NULL) return false;
    int dirname_length = 0;
    fun(buf, length, &dirname_length);
    buf[length] = '\0';
    full_path = std::string(buf, length);
    dir = std::string(buf, dirname_length);
    delete[]buf;
    return true;
}

bool FileHelper::FileStatCheck(const std::string &file_path, unsigned short mode)
{
    if (file_path.empty()) return false;
    struct stat buf = { 0 };
    if (stat(file_path.c_str(), &buf)) return false;
    if (buf.st_mode & mode) return true;
    return false;
}