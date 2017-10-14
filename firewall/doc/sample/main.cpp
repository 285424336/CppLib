// FireWallHelper.cpp : Defines the entry point for the console application.
//

#include "FireWallHelper.h"
#include <iostream>
#include <file\FileHelper.h>

int main()
{
    std::wstring wstrRuleName = L"mcjfiretest";
    std::wstring wstrAppPath = L"afdasdg";
    while (1) {
        std::cout << FireWallHelper::GetInstance().AddRule(wstrRuleName, wstrAppPath) << std::endl;
        std::cout << FireWallHelper::GetInstance().RemoveRule(wstrRuleName) << std::endl;
        std::cout << FireWallHelper::GetInstance().IsRuleExist(wstrRuleName, wstrAppPath) << std::endl;
    }
    return 0;
}

