// FileHelper.cpp : Defines the entry point for the console application.
//

#include "FileHelper.h"
#include <iostream>
#include <fstream>
#include <string\StringHelper.h>

#ifdef WIN32
#define FILE_PATH_ROOT_TEST "C:\\"
#else
#define FILE_PATH_ROOT_TEST "/"
#endif

void GetExecutablePathTest()
{
    bool ret;
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::string exec_full_path, exec_dir;
    ret = FileHelper::GetExecutablePath(exec_full_path, exec_dir);
    std::cout << "exec info: " << std::endl
        << "    ret : " << ret << std::endl
        << "    exec full path " << exec_full_path << std::endl
        << "    exec dir path" << exec_dir << std::endl;
}

void GetModulePathTest()
{
    bool ret;
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::string module_full_path, module_dir;
    ret = FileHelper::GetModulePath(module_full_path, module_dir);
    std::cout << "module info: " << std::endl
        << "    ret : " << ret << std::endl
        << "    module full path " << module_full_path << std::endl
        << "    module dir path" << module_dir << std::endl;
}

void GetCurrentWorkDirTest()
{
    bool ret;
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::string cur_work_dir = FileHelper::GetCurrentWorkDir();
    std::cout << "current work dir: " << cur_work_dir << std::endl;
    ret = FileHelper::SetCurrentWorkDir(FILE_PATH_ROOT_TEST);
    std::cout << "    set current work dir ret: " << ret << std::endl
        << "    current work dir: " << FileHelper::GetCurrentWorkDir() << std::endl;
    FileHelper::SetCurrentWorkDir(cur_work_dir);
}

#define SetCurrentWorkDirTest GetCurrentWorkDirTest

void ListSubFilesTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;

    {
        std::set<std::string> files;
        files = FileHelper::ListSubFiles(".", LIST_FILE_ALL, true);
        std::cout << "all file nums under " << FileHelper::GetAbsolutePath(".") << ": " << files.size() << std::endl;
        for (auto file : files)
        {
            std::cout << "    " << file << std::endl;
        }
    }

    {
        std::set<std::string> files;
        files = FileHelper::ListSubFiles(".", LIST_FILE_REG, false);
        std::cout << "    normal file nums under " << FileHelper::GetAbsolutePath(".") << ": " << files.size() << std::endl;
        for (auto file : files)
        {
            std::cout << "    " << file << std::endl;
        }
    }

    {
        std::set<std::string> files;
        files = FileHelper::ListSubFiles(".", LIST_FILE_DIR, true);
        std::cout << "    dir file nums under " << FileHelper::GetAbsolutePath(".") << ": " << files.size() << std::endl;
        for (auto file : files)
        {
            std::cout << "    " << file << std::endl;
        }
    }
}

void CoordinateFileSeparatorTest()
{
    static std::string coordinate_path_1 = ".";
    static std::string coordinate_path_2 = std::string(".") + OS_FILE_SEPARATOR;
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::cout << "path "<< coordinate_path_1 << " coordinate after: " << FileHelper::CoordinateFileSeparator(std::string(coordinate_path_1)) << std::endl;
    std::cout << "path "<< coordinate_path_2 << " coordinate after: " << FileHelper::CoordinateFileSeparator(std::string(coordinate_path_2)) << std::endl;
}

void GetAbsolutePathTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string org_path = ".";
        std::string current_dir = FileHelper::GetCurrentWorkDir();
        std::cout << "current dir: " << current_dir << std::endl
            << "    org path: " << org_path << std::endl
            << "    absolute path: " << FileHelper::GetAbsolutePath(org_path) << std::endl;
    }
    {
        std::string org_path = "..";
        std::string current_dir = std::string(FILE_PATH_ROOT_TEST) + "a" + OS_FILE_SEPARATOR + "b" + OS_FILE_SEPARATOR + "c" + OS_FILE_SEPARATOR + "d";
        std::cout << "current dir: " << current_dir << std::endl
            << "    org path: " << org_path << std::endl
            << "    absolute path: " << FileHelper::GetAbsolutePath(org_path, current_dir) << std::endl;
    }
    {
        std::string org_path = std::string("a") + OS_FILE_SEPARATOR + ".." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "b" + OS_FILE_SEPARATOR + "c";
        std::string current_dir = FileHelper::GetCurrentWorkDir();
        std::cout << "current dir: " << current_dir << std::endl
            << "    org path: " << org_path << std::endl
            << "    absolute path: " << FileHelper::GetAbsolutePath(org_path) << std::endl;
    }
    {
        std::string org_path = FILE_PATH_ROOT_TEST;
        std::string current_dir = std::string(FILE_PATH_ROOT_TEST) + "a" + OS_FILE_SEPARATOR + "b" + OS_FILE_SEPARATOR + "c" + OS_FILE_SEPARATOR + "d";
        std::cout << "current dir: " << current_dir << std::endl
            << "    org path: " << org_path << std::endl
            << "    absolute path: " << FileHelper::GetAbsolutePath(org_path, current_dir) << std::endl;
    }
    {
        std::string org_path = std::string(FILE_PATH_ROOT_TEST) + "a" + OS_FILE_SEPARATOR + ".." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "b" + OS_FILE_SEPARATOR + "c";
        std::string current_dir = FileHelper::GetCurrentWorkDir();
        std::cout << "current dir: " << current_dir << std::endl
            << "    org path: " << org_path << std::endl
            << "    absolute path: " << FileHelper::GetAbsolutePath(org_path) << std::endl;
    }
    {
        std::string org_path = std::string("..") + OS_FILE_SEPARATOR + ".." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "b" + OS_FILE_SEPARATOR + "c" + OS_FILE_SEPARATOR;
        std::string current_dir = std::string(FILE_PATH_ROOT_TEST) + "a" + OS_FILE_SEPARATOR + "b" + OS_FILE_SEPARATOR + "c" + OS_FILE_SEPARATOR + "d";
        std::cout << "current dir: " << current_dir << std::endl
            << "    org path: " << org_path << std::endl
            << "    absolute path: " << FileHelper::GetAbsolutePath(org_path, current_dir) << std::endl;
    }
}

void GetLastNameInPathTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string path = ".";
        std::cout << "path: " << path << std::endl
            << "    path last name: " << FileHelper::GetLastNameInPath(path) << std::endl;
    }
    {
        std::string path = "..";
        std::cout << "path: " << path << std::endl
            << "    path last name: " << FileHelper::GetLastNameInPath(path) << std::endl;
    }
    {
        std::string path = FILE_PATH_ROOT_TEST;
        std::cout << "path: " << path << std::endl
            << "    path last name: " << FileHelper::GetLastNameInPath(path) << std::endl;
    }
    {
        std::string path = std::string("..") + OS_FILE_SEPARATOR + ".." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "b" + OS_FILE_SEPARATOR + "c" + OS_FILE_SEPARATOR;
        std::cout << "path: " << path << std::endl
            << "    path last name: " << FileHelper::GetLastNameInPath(path) << std::endl;
    }
    {
        std::string path = std::string("..") + OS_FILE_SEPARATOR + ".." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "b" + OS_FILE_SEPARATOR + "c";
        std::cout << "path: " << path << std::endl
            << "    path last name: " << FileHelper::GetLastNameInPath(path) << std::endl;
    }
    {
        std::string path = std::string("..") + OS_FILE_SEPARATOR + ".." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "b" + OS_FILE_SEPARATOR + "c" + OS_FILE_SEPARATOR + "..";
        std::cout << "path: " << path << std::endl
            << "    path last name: " << FileHelper::GetLastNameInPath(path) << std::endl;
    }
    {
        std::string path = std::string(FILE_PATH_ROOT_TEST) + ".." + OS_FILE_SEPARATOR + ".." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "b" + OS_FILE_SEPARATOR + "c" + OS_FILE_SEPARATOR + "..";
        std::cout << "path: " << path << std::endl
            << "    path last name: " << FileHelper::GetLastNameInPath(path) << std::endl;
    }
}

void GetDirInPathTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string path = ".";
        std::cout << "path: " << path << std::endl
            << "    path dir name: " << FileHelper::GetDirInPath(path) << std::endl;
    }
    {
        std::string path = std::string(".") + OS_FILE_SEPARATOR;
        std::cout << "path: " << path << std::endl
            << "    path dir name: " << FileHelper::GetDirInPath(path) << std::endl;
    }
    {
        std::string path = FILE_PATH_ROOT_TEST;
        std::cout << "path: " << path << std::endl
            << "    path dir name: " << FileHelper::GetDirInPath(path) << std::endl;
    }
    {
        std::string path = std::string("..") + OS_FILE_SEPARATOR + ".." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "b" + OS_FILE_SEPARATOR + "c" + OS_FILE_SEPARATOR;
        std::cout << "path: " << path << std::endl
            << "    path dir name: " << FileHelper::GetDirInPath(path) << std::endl;
    }
    {
        std::string path = std::string(FILE_PATH_ROOT_TEST) + ".." + OS_FILE_SEPARATOR + ".." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "." + OS_FILE_SEPARATOR + "b" + OS_FILE_SEPARATOR + "c" + OS_FILE_SEPARATOR + "abcd.txt";
        std::cout << "path: " << path << std::endl
            << "    path dir name: " << FileHelper::GetDirInPath(path) << std::endl;
    }
}

void IsDirTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string path = ".";
        std::cout << "path: " << path << std::endl
            << "    is dir: " << FileHelper::IsDir(path) << std::endl;
    }
    {
        std::string path = "..";
        std::cout << "path: " << path << std::endl
            << "    is dir: " << FileHelper::IsDir(path) << std::endl;
    }
    {
        std::string path = std::string(".") + OS_FILE_SEPARATOR + "FileHelper.h";
        std::cout << "path: " << path << std::endl
            << "    is dir: " << FileHelper::IsDir(path) << std::endl;
    }
    {
        std::string path = std::string(".") + OS_FILE_SEPARATOR + "UNEXIST.h";
        std::cout << "path: " << path << std::endl
            << "    is dir: " << FileHelper::IsDir(path) << std::endl;
    }
}

void IsFileTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string path = ".";
        std::cout << "path: " << path << std::endl
            << "    is file: " << FileHelper::IsFile(path) << std::endl;
    }
    {
        std::string path = "..";
        std::cout << "path: " << path << std::endl
            << "    is file: " << FileHelper::IsFile(path) << std::endl;
    }
    {
        std::string path = std::string(".") + OS_FILE_SEPARATOR + "FileHelper.h";
        std::cout << "path: " << path << std::endl
            << "    is file: " << FileHelper::IsFile(path) << std::endl;
    }
    {
        std::string path = std::string(".") + OS_FILE_SEPARATOR + "UNEXIST.h";
        std::cout << "path: " << path << std::endl
            << "    is file: " << FileHelper::IsFile(path) << std::endl;
    }
}

void IsExistTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string path = ".";
        std::cout << "path: " << path << std::endl
            << "    is exist: " << FileHelper::IsExist(path) << std::endl;
    }
    {
        std::string path = "..";
        std::cout << "path: " << path << std::endl
            << "    is exist: " << FileHelper::IsExist(path) << std::endl;
    }
    {
        std::string path = std::string(".") + OS_FILE_SEPARATOR + "FileHelper.h";
        std::cout << "path: " << path << std::endl
            << "    is exist: " << FileHelper::IsExist(path) << std::endl;
    }
    {
        std::string path = std::string(".") + OS_FILE_SEPARATOR + "UNEXIST.h";
        std::cout << "path: " << path << std::endl
            << "    is exist: " << FileHelper::IsExist(path) << std::endl;
    }
}

void GetFileSizeTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string path = ".";
        std::cout << "path: " << path << std::endl
            << "    file size: " << FileHelper::GetFileSize(path) << std::endl;
    }
    {
        std::string path = "..";
        std::cout << "path: " << path << std::endl
            << "    file size: " << FileHelper::GetFileSize(path) << std::endl;
    }
    {
        std::string path = std::string(".") + OS_FILE_SEPARATOR + "FileHelper.h";
        std::cout << "path: " << path << std::endl
            << "    file size: " << FileHelper::GetFileSize(path) << std::endl;
    }
    {
        std::string path = std::string(".") + OS_FILE_SEPARATOR + "UNEXIST.h";
        std::cout << "path: " << path << std::endl
            << "    file size: " << FileHelper::GetFileSize(path) << std::endl;
    }
}

void MkDirTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        bool ret;
        std::string path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        FileHelper::Rm(path, false);
        std::cout << "path: " << path << std::endl
            << "    is exist: " << FileHelper::IsExist(path) << std::endl;
        ret = FileHelper::MkDir(path);
        std::cout << "    mkdir ret: " << ret << std::endl
            << "    is exist: " << FileHelper::IsExist(path) << std::endl;
        FileHelper::Rm(path);
    }
    {
        bool ret;
        std::string path = FileHelper::CoordinateFileSeparator(FileHelper::GetCurrentWorkDir()) + "Temp1";
        FileHelper::Rm(path, false);
        std::cout << "path: " << path << std::endl
            << "    is exist: " << FileHelper::IsExist(path) << std::endl;
        ret = FileHelper::MkDir(path);
        std::cout << "    mkdir ret: " << ret << std::endl
            << "    is exist: " << FileHelper::IsExist(path) << std::endl;
        FileHelper::Rm(path);
    }
    {
        bool ret;
        std::string path = std::string(".") + OS_FILE_SEPARATOR + "Temp1" + OS_FILE_SEPARATOR + "Temp2";
        FileHelper::Rm(path, false);
        std::cout << "path: " << path << std::endl
            << "    is exist: " << FileHelper::IsExist(path) << std::endl;
        ret = FileHelper::MkDir(path);
        std::cout << "    mkdir ret: " << ret << std::endl
            << "    is exist: " << FileHelper::IsExist(path) << std::endl;
        FileHelper::Rm(path);
    }
    {
        bool ret;
        std::string path = FileHelper::CoordinateFileSeparator(FileHelper::GetCurrentWorkDir()) + "Temp1" + OS_FILE_SEPARATOR + "Temp2";
        FileHelper::Rm(path, false);
        std::cout << "path: " << path << std::endl
            << "    is exist: " << FileHelper::IsExist(path) << std::endl;
        ret = FileHelper::MkDir(path);
        std::cout << "    mkdir ret: " << ret << std::endl
            << "    is exist: " << FileHelper::IsExist(path) << std::endl;
        FileHelper::Rm(path);
    }
}

void RmTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        bool ret;
        std::string dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string file_path = dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(dir_path);
        {
            std::ofstream file(file_path);
        }
        std::cout << "dir path: " << dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dir_path) << std::endl
            << "    file path: " << file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(file_path) << std::endl;
        ret = FileHelper::Rm(file_path);
        std::cout << "    rm file ret: " << ret << std::endl
            << "    dir is exist: " << FileHelper::IsExist(dir_path) << std::endl
            << "    file is exist: " << FileHelper::IsExist(file_path) << std::endl;
        FileHelper::Rm(dir_path);
    }
    {
        bool ret;
        std::string dir_path = FileHelper::CoordinateFileSeparator(FileHelper::GetCurrentWorkDir()) + "Temp1";
        std::string file_path = dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(dir_path);
        {
            std::ofstream file(file_path);
        }
        std::cout << "dir path: " << dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dir_path) << std::endl
            << "    file path: " << file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(file_path) << std::endl;
        ret = FileHelper::Rm(file_path);
        std::cout << "    rm file ret: " << ret << std::endl
            << "    dir is exist: " << FileHelper::IsExist(dir_path) << std::endl
            << "    file is exist: " << FileHelper::IsExist(file_path) << std::endl;
        FileHelper::Rm(dir_path);
    }
    {
        bool ret;
        std::string dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string file_path = dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(dir_path);
        {
            std::ofstream file(file_path);
        }
        std::cout << "dir path: " << dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dir_path) << std::endl
            << "    file path: " << file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(file_path) << std::endl;
        ret = FileHelper::Rm(dir_path);
        std::cout << "    rm dir ret: " << ret << std::endl
            << "    dir is exist: " << FileHelper::IsExist(dir_path) << std::endl
            << "    file is exist: " << FileHelper::IsExist(file_path) << std::endl;
        FileHelper::Rm(dir_path);
    }
    {
        bool ret;
        std::string dir_path = FileHelper::CoordinateFileSeparator(FileHelper::GetCurrentWorkDir()) + "Temp1";
        std::string file_path = dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(dir_path);
        {
            std::ofstream file(file_path);
        }
        std::cout << "dir path: " << dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dir_path) << std::endl
            << "    file path: " << file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(file_path) << std::endl;
        ret = FileHelper::Rm(dir_path);
        std::cout << "    rm dir ret: " << ret << std::endl
            << "    dir is exist: " << FileHelper::IsExist(dir_path) << std::endl
            << "    file is exist: " << FileHelper::IsExist(file_path) << std::endl;
        FileHelper::Rm(dir_path);
    }
}

void MvTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        {
            std::ofstream file(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file path: " << org_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file path: " << dst_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        ret = FileHelper::Mv(org_file_path, dst_file_path);
        std::cout << "    mv file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2" + OS_FILE_SEPARATOR;
        std::string dst_file_path = dst_dir_path + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        {
            std::ofstream file(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file path: " << org_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file path: " << dst_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        ret = FileHelper::Mv(org_file_path, dst_dir_path);
        std::cout << "    mv file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        FileHelper::MkDir(dst_dir_path);
        {
            std::ofstream file(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file path: " << org_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file path: " << dst_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        ret = FileHelper::Mv(org_file_path, dst_dir_path);
        std::cout << "    mv file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        FileHelper::MkDir(dst_dir_path);
        {
            std::ofstream file1(org_file_path, std::ios::binary);
            std::ofstream file2(dst_file_path, std::ios::binary);
            file2.write("a", 1);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file path: " << org_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file path: " << dst_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        ret = FileHelper::Mv(org_file_path, dst_file_path);
        std::cout << "    mv file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        {
            std::ofstream file1(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        ret = FileHelper::Mv(org_dir_path, dst_dir_path);
        std::cout << "    mv file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        FileHelper::MkDir(dst_dir_path);
        {
            std::ofstream file1(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        ret = FileHelper::Mv(org_dir_path, dst_dir_path);
        std::cout << "    mv file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        FileHelper::MkDir(dst_dir_path + +OS_FILE_SEPARATOR + "Temp1");
        {
            std::ofstream file1(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        ret = FileHelper::Mv(org_dir_path, dst_dir_path);
        std::cout << "    mv file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        FileHelper::MkDir(org_dir_path + OS_FILE_SEPARATOR + "Temp1");
        FileHelper::MkDir(dst_dir_path + OS_FILE_SEPARATOR + "Temp1" + OS_FILE_SEPARATOR + "Temp1");
        {
            std::ofstream file1(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        ret = FileHelper::Mv(org_dir_path, dst_dir_path);
        std::cout << "    mv file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
}

void CpTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        {
            std::ofstream file(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file path: " << org_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file path: " << dst_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        ret = FileHelper::Cp(org_file_path, dst_file_path);
        std::cout << "    cp file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2" + OS_FILE_SEPARATOR;
        std::string dst_file_path = dst_dir_path + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        {
            std::ofstream file(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file path: " << org_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file path: " << dst_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        ret = FileHelper::Cp(org_file_path, dst_dir_path);
        std::cout << "    cp file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        FileHelper::MkDir(dst_dir_path);
        {
            std::ofstream file(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file path: " << org_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file path: " << dst_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        ret = FileHelper::Cp(org_file_path, dst_dir_path);
        std::cout << "    cp file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        FileHelper::MkDir(dst_dir_path);
        {
            std::ofstream file1(org_file_path, std::ios::binary);
            std::ofstream file2(dst_file_path, std::ios::binary);
            file2.write("a", 1);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file path: " << org_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file path: " << dst_file_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        ret = FileHelper::Cp(org_file_path, dst_file_path);
        std::cout << "    cp file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl
            << "    org file is exist: " << FileHelper::IsExist(org_file_path) << std::endl
            << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl
            << "    dst file is exist: " << FileHelper::IsExist(dst_file_path) << std::endl;
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        {
            std::ofstream file1(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        ret = FileHelper::Cp(org_dir_path, dst_dir_path);
        std::cout << "    cp file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        FileHelper::MkDir(dst_dir_path);
        {
            std::ofstream file1(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        ret = FileHelper::Cp(org_dir_path, dst_dir_path);
        std::cout << "    cp file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        FileHelper::MkDir(dst_dir_path + +OS_FILE_SEPARATOR + "Temp1");
        {
            std::ofstream file1(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        ret = FileHelper::Cp(org_dir_path, dst_dir_path);
        std::cout << "    cp file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
    {
        bool ret;
        std::string org_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string org_file_path = org_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        std::string dst_dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp2";
        std::string dst_file_path = dst_dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(org_dir_path);
        FileHelper::MkDir(org_dir_path + OS_FILE_SEPARATOR + "Temp1");
        FileHelper::MkDir(dst_dir_path + OS_FILE_SEPARATOR + "Temp1" + OS_FILE_SEPARATOR + "Temp1");
        {
            std::ofstream file1(org_file_path, std::ios::binary);
        }
        std::cout << "org dir path: " << org_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir path: " << dst_dir_path << std::endl
            << "    is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        ret = FileHelper::Cp(org_dir_path, dst_dir_path);
        std::cout << "    cp file ret: " << ret << std::endl
            << "    org dir is exist: " << FileHelper::IsExist(org_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(org_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(org_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        std::cout << "    dst dir is exist: " << FileHelper::IsExist(dst_dir_path) << std::endl;
        {
            std::set<std::string> files;
            files = FileHelper::ListSubFiles(dst_dir_path, LIST_FILE_ALL, true);
            std::cout << "    all file nums under " << FileHelper::GetAbsolutePath(dst_dir_path) << ": " << files.size() << std::endl;
            for (auto file : files)
            {
                std::cout << "        " << file << std::endl;
            }
        }
        FileHelper::Rm(org_dir_path);
        FileHelper::Rm(dst_dir_path);
    }
}

void GetFileContentTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string file_path = dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        FileHelper::MkDir(dir_path);
        {
            std::ofstream file(file_path, std::ios::binary);
        }
        std::string content = FileHelper::GetFileContent(file_path);
        std::cout << "    file content: " << StringHelper::byte2basestr((unsigned char *)content.c_str(), content.size(), ":", StringHelper::hex, 2) << std::endl;
        FileHelper::Rm(dir_path);
    }
    {
        std::string dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string file_path = dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        char buf[] = "123456789";
        FileHelper::MkDir(dir_path);
        {
            std::ofstream file(file_path, std::ios::binary);
            file.write(buf, sizeof(buf));
        }
        std::string content = FileHelper::GetFileContent(file_path);
        std::cout << "    file content: " << StringHelper::byte2basestr((unsigned char *)content.c_str(), content.size(), ":", StringHelper::hex, 2) << std::endl;
        FileHelper::Rm(dir_path);
    }
    {
        std::string dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string file_path = dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        char buf[] = {1,2,3,4,5,6,7,8,9};
        FileHelper::MkDir(dir_path);
        {
            std::ofstream file(file_path, std::ios::binary);
            file.write(buf, sizeof(buf));
        }
        std::string content = FileHelper::GetFileContent(file_path);
        std::cout << "    file content: " << StringHelper::byte2basestr((unsigned char *)content.c_str(), content.size(), ":", StringHelper::hex, 2) << std::endl;
        FileHelper::Rm(dir_path);
    }
}

void SetFileContentTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string file_path = dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        char buf[] = "123456789";
        FileHelper::MkDir(dir_path);
        FileHelper::SetFileContent(file_path, buf, sizeof(buf));
        FileHelper::SetFileContent(file_path, buf, sizeof(buf));
        std::string content = FileHelper::GetFileContent(file_path);
        std::cout << "    file content: " << StringHelper::byte2basestr((unsigned char *)content.c_str(), content.size(), ":", StringHelper::hex, 2) << std::endl;
        FileHelper::Rm(dir_path);
    }
    {
        std::string dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string file_path = dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        char buf[] = { 1,2,3,4,5,6,7,8,9 };
        FileHelper::MkDir(dir_path);
        FileHelper::SetFileContent(file_path, buf, sizeof(buf));
        FileHelper::SetFileContent(file_path, buf, sizeof(buf));
        std::string content = FileHelper::GetFileContent(file_path);
        std::cout << "    file content: " << StringHelper::byte2basestr((unsigned char *)content.c_str(), content.size(), ":", StringHelper::hex, 2) << std::endl;
        FileHelper::Rm(dir_path);
    }
    {
        std::string dir_path = std::string(".") + OS_FILE_SEPARATOR + "Temp1";
        std::string file_path = dir_path + OS_FILE_SEPARATOR + "EXIST.file";
        char buf[] = { 1,2,3,4,5,6,7,8,9 };
        FileHelper::MkDir(dir_path);
        FileHelper::SetFileContent(file_path, buf, sizeof(buf));
        FileHelper::SetFileContent(file_path, buf, sizeof(buf), true);
        std::string content = FileHelper::GetFileContent(file_path);
        std::cout << "    file content: " << StringHelper::byte2basestr((unsigned char *)content.c_str(), content.size(), ":", StringHelper::hex, 2) << std::endl;
        FileHelper::Rm(dir_path);
    }
}

void GetWinTempPathTest()
{
#ifdef WIN32
    std::cout << "windows temp path: " << FileHelper::GetWinTempPath() << std::endl;
#endif // WIN32
    return;
}

void GetWinLocalAppDataPathTest()
{
#ifdef WIN32
    std::cout << "windows local app data path: " << FileHelper::GetWinLocalAppDataPath() << std::endl;
#endif // WIN32
    return;
}

int main()
{
    GetExecutablePathTest();
    GetModulePathTest();
    GetCurrentWorkDirTest();
    ListSubFilesTest();
    CoordinateFileSeparatorTest();
    GetAbsolutePathTest();
    GetLastNameInPathTest();
    GetDirInPathTest();
    IsDirTest();
    IsFileTest();
    IsExistTest();
    GetFileSizeTest();
    MkDirTest();
    RmTest();
    MvTest();
    CpTest();
    GetFileContentTest();
    SetFileContentTest();
    GetWinTempPathTest();
    GetWinLocalAppDataPathTest();
    return 0;
}

