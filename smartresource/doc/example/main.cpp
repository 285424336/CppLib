// SmartResource.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <smartresource\SmartResource.h>
#include <iostream>

class Test : public Resource
{
protected:
    virtual bool LoadResource()
    {
        std::cout << "load resource" << std::endl;
        return false;
    }
    virtual void UnloadResource()
    {
        std::cout << "unload resource" << std::endl;
        return;
    }
};

int main()
{
    Test test;
    {
        SmartResource res1(test);
        SmartResource res2(test);
        SmartResource res3(test);
        SmartResource res4(test);
    }
    {
        SmartResource res(test);
    }
    return 0;
}

