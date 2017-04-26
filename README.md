# CppLib
Lib for cpp project, all the lib can be used for windows, but only some can be used for linux.<br/>
[*algorithm: WIN/LINUX, it is quickly algorithm lib](https://github.com/machenjie/CppLib/tree/master/algorithm)<br/>
[*args: WIN/LINUX, it is a command line parse class lib](https://github.com/machenjie/CppLib/tree/master/args)<br/>
[*curl: WIN/LINUX, it is a wrapper of libcurl](https://github.com/machenjie/CppLib/tree/master/curl)<br/>
[*dll: WIN ONLY, use for load dll from memory](https://github.com/machenjie/CppLib/tree/master/dll)<br/>
[*event: WIN/LINUX, an simple event engine using closure](https://github.com/machenjie/CppLib/tree/master/event)<br/>
[*file: WIN/LINUX, it is a file/directory operation lib](https://github.com/machenjie/CppLib/tree/master/file)<br/>
[*json: WIN/LINUX, it is a json lib, open source code](https://github.com/machenjie/CppLib/tree/master/json)<br/>
[*kernel32: WIN/LINUX, it is a wrapper of system operation](https://github.com/machenjie/CppLib/tree/master/kernel32)<br/>
[*md5: WIN/LINUX, it is a md5 lib](https://github.com/machenjie/CppLib/tree/master/md5)<br/>
[*network: WIN/LINUX, it is a network info collect lib](https://github.com/machenjie/CppLib/tree/master/network)<br/>
[*plog: WIN/LINUX, it is a log lib, open source code](https://github.com/machenjie/CppLib/tree/master/plog)<br/>
[*pugixml: WIN/LINUX, it is a xml parse lib, open source code](https://github.com/machenjie/CppLib/tree/master/pugixml)<br/>
[*salsa20: WIN/LINUX, it is a salsa20 encrypt/decrypt lib, base on open source code](https://github.com/machenjie/CppLib/tree/master/salsa20)<br/>
[*socket: WIN/LINUX, it is a wrapper of socket](https://github.com/machenjie/CppLib/tree/master/socket)<br/>
[*string: WIN/LINUX, it is a string operation lib](https://github.com/machenjie/CppLib/tree/master/string)<br/>
[*threadpool: WIN/LINUX, it is a threadpool lib, based on open source code](https://github.com/machenjie/CppLib/tree/master/threadpool)<br/>
[*time: WIN/LINUX, it is a time helper lib](https://github.com/machenjie/CppLib/tree/master/time)<br/>
[*uid: WIN/LINUX, it is a uuid/guid generate lib, if you want to use in linux, you must install uuid package](https://github.com/machenjie/CppLib/tree/master/uid)<br/>
[*winreg: WIN ONLY, it is a windows registry operation lib, based on open source code](https://github.com/machenjie/CppLib/tree/master/winreg)<br/>
[*zip: WIN/LINUX, it is a zip/unzip lib](https://github.com/machenjie/CppLib/tree/master/zip)<br/>

For some of them is a wrap of other open source code, so if it has hurt your interests, please contact me.

It is not a complete project, only include the lib src codes, and examples. You can look at the <lib name>/doc for more information of the lib, and <lib name>/doc/sample for the sample code of the lib.

If you have any questions, feel free to contact me.

Useage:<br/>
You should download all the package, and put them under the directory like follow:<br/>
├─util<br/>
>├─algorithm<br/>
>├─args<br/>
>...<br/>

after do that, you should add the compile parameter:<br/>
>WIN: change the Additional Include Directories, add you util directory location<br/>
>Linux: add the compile parameter -I "you util directory location"<br/>

TEST:<br/>
Every lib has had a simple test with VS2015 and gun with c++11 std.<br/>
