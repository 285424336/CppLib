// DumpCatch.cpp : �������̨Ӧ�ó������ڵ㡣
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

