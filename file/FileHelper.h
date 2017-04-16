#ifndef FILE_HELPER_H_INCLUDED
#define FILE_HELPER_H_INCLUDED

#if defined(_MSC_VER)
#include <Shlobj.h>
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
#include <string>
#include <set>

#define LIST_FILE_MAX_NUM 1024
#define LIST_FILE_REG     0X01
#define LIST_FILE_DIR     0X02
#define LIST_FILE_OTHER   0X04
#define LIST_FILE_ALL     0XFF

#if defined(_MSC_VER)
#define OS_FILE_SEPARATOR "\\"
#define OS_FILE_ROOT ":"
#elif defined(__GNUC__)
#define OS_FILE_SEPARATOR "/"
#define OS_FILE_ROOT "/"
#else
#error unsupported compiler
#endif

class FileHelper
{
private:
    typedef int (*GetPathFun)(char*, int, int*);

public:
    /**
    *get the exec path
    *full_path(out): exec absolute path
    *dir(out): exec dir absolute path
    */
    static bool GetExecutablePath(std::string &full_path, std::string &dir);

    /**
    *get the module path, dll can use this function get module path
    *full_path(out): module absolute path
    *dir(out): module dir absolute path
    */
    static bool GetModulePath(std::string &full_path, std::string &dir);

    /**
    *get current work dir, if fail return empty
    */
    static std::string GetCurrentWorkDir();

    /**
    *set current work dir
    */
    static bool SetCurrentWorkDir(const std::string &path);

    /**
    *add the file separator at the end of the path, if it is not exist.
    *note that you should input the dir path
    *path(in/out): the path that you want make sure of the file separator at the end
    */
    static std::string & CoordinateFileSeparator(std::string &path);

    /**
    *add the file separator at the end of the path, if it is not exist.
    *note that you should input the dir path
    *path(in/out): the path that you want make sure of the file separator at the end
    */
    static std::string && CoordinateFileSeparator(std::string &&path);

    /**
    *add the file separator at the end of the path, if it is not exist.
    *note that you should input the dir path
    *path(in/out): the path that you want make sure of the file separator at the end
    */
    static std::string CoordinateFileSeparator(const std::string &path);

    /**
    *get the absolute path of the path
    *path(in): the path that you want to become absolute path, if it is absolute path, the function do nothing
    *pwd(in): absolute dir for path "."
    */
    static std::string GetAbsolutePath(const std::string &path, const std::string &pwd = "");

    /**
    *get the last name in path, in /abc/def out def, in /abc/def/ out def.
    *path(in): the path you want to get the last name
    *if failed, it will return empty string
    */
    static std::string GetLastNameInPath(const std::string &path);

    /**
    *get the dir in path, in /abc/def out /abc/, in /abc/def/ out /abc/def/.
    *path(in): the path you want to get the dir
    *if failed, it will return empty string
    */
    static std::string GetDirInPath(const std::string &path);

    /**
    *check if input path is a dir, and it is exist
    *path(in): file path
    */
    static bool IsDir(const std::string &path);

    /**
    *check if input path is a file, and it is exist
    *path(in): file path
    */
    static bool IsFile(const std::string &path);

    /**
    *check if input path is exist
    *path(in): file path
    */
    static bool IsExist(const std::string &path);

    /**
    *list the files under the dir_path
    *dir_path(in): the dir path
    *type(in): the file type you want to list, you can use LIST_FILE_REG, LIST_FILE_DIR, LIST_FILE_OTHER with bit mask
    *recursive(in): if you want to list the files in the sub dir, you can set to true
    */
    static std::set<std::string> ListSubFiles(const std::string &dir_path, int type = LIST_FILE_REG, bool recursive = true);

    /**
    *make all the dirs of the dir_path
    *dir_path(in): the dir path you want to make sure exist
    */
    static bool MkDir(const std::string &dir_path);

    /**
    *delete the file
    *path(in): the path you want to delete
    *can_recycle(in): windows only, if user can recycle from recycle bin
    */
    static bool Rm(const std::string &path, bool can_recycle = false);

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
    static bool Mv(const std::string &src_path, const std::string &dst_path);

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
    static bool Cp(const std::string &src_path, const std::string &dst_path);

    /**
    *get the file size in byte
    *file_path(in): file path
    */
    static size_t GetFileSize(const std::string &file_path);

    /**
    *get the file content
    *file_path(in): the file path
    *you can get all file content bytes in return string.c_str()
    */
    static std::string GetFileContent(const std::string& file_path);

    /**
    *get the file content
    *file_path(in): the file path
    */
    static bool SetFileContent(const std::string& file_path, const char *buf, size_t buf_size, bool append = false);

#if defined(_MSC_VER)
    /**
    *get windows %temp% path, C:\Users\%user%\AppData\Local\temp
    */
    static std::string GetWinTempPath();

    /**
    *get windows path,
    *type: path type, here is some list
    *      CSIDL_PROGRAM_FILES->C:\Program Files  (C:\PROGRA~1)
    *      CSIDL_LOCAL_APPDATA->C:\Users\%user%\AppData\Local
    *      CSIDL_PROGRAM_FILESX86->C:\Program Files (x86)  (C:\PROGRA~2)
    *      CSIDL_COMMON_APPDATA->C:\ProgramData  (C:\PROGRA~3)
    *      CSIDL_WINDOWS->C:\Windows
    *      CSIDL_SYSTEM->C:\Windows\System32
    *      CSIDL_SYSTEMX86->C:\Windows\SysWOW64
    *      CSIDL_DESKTOP->C:\Users\%user%\Desktop
    */
    static std::string GetWinTypePath(int type = CSIDL_LOCAL_APPDATA);
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

private:
    static bool GetPath(GetPathFun fun, std::string &full_path, std::string &dir);
    static bool FileStatCheck(const std::string &file_path, unsigned short mode);

};

#endif
