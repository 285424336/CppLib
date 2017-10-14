// DumpCatch.cpp : 定义控制台应用程序的入口点。
//

#include <dumpcatch\DumpCatch.h>

bool Init()
{
	//CDumpCatch::Instance();
	CDumpCatch::SetDumpFilePath(L"C:\\Users\\Administrator\\Desktop\\");
	return true;
}

bool init = Init();
int main()
{
	int *a = NULL;
	*a = 2;
    return 0;
}

