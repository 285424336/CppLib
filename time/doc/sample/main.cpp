// TimeHelper.cpp : Defines the entry point for the console application.
//
#if defined(_MSC_VER)
#include <time\TimeHelper.h>
#elif defined(__GNUC__)
#include <time/TimeHelper.h>
#else
#error unsupported compiler
#endif
#include <iostream>

void PrintTM(const struct tm &tm)
{
    std::cout << "    year " << tm.tm_year + TM_YEAR_BASE << std::endl;
    std::cout << "    month " << tm.tm_mon + 1 << std::endl;
    std::cout << "    day " << tm.tm_mday << std::endl;
    std::cout << "    hour " << tm.tm_hour << std::endl;
    std::cout << "    minute " << tm.tm_min << std::endl;
    std::cout << "    second " << tm.tm_sec << std::endl;
    std::cout << "    day in week " << tm.tm_wday << std::endl;
    std::cout << "    day in year " << tm.tm_yday << std::endl;
    std::cout << "    daylight saving time " << tm.tm_isdst << std::endl;
}

void GetTimeOfDayTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    std::cout << tv.tv_sec << " " << tv.tv_usec << std::endl;
    std::cout << tz.tz_minuteswest << " " << tz.tz_dsttime << std::endl;
}

void CurrentTimeStampTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::cout << "current time stamp " << TimeHelper::CurrentTimeStamp() << std::endl;
}

void TimeStamp2TMTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    struct tm tm = { 0 };
    {
        TimeHelper::TimeStamp2TM(tm, TimeHelper::CurrentTimeStamp(), true);
        std::cout << "utc tm info:" << std::endl;
        PrintTM(tm);
    }
    {
        TimeHelper::TimeStamp2TM(tm, TimeHelper::CurrentTimeStamp(), false);
        std::cout << "local tm info:" << std::endl;
        PrintTM(tm);
    }
}

void TM2TimeStampTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    struct tm tm;
    time_t time = TimeHelper::CurrentTimeStamp();
    TimeHelper::TimeStamp2TM(tm, time);
    std::cout << "before: " << time << " after: " << TimeHelper::TM2TimeStamp(tm) << std::endl;
}

void TM2TimeStrTEST()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    struct tm tm;
    {
        TimeHelper::TimeStamp2TM(tm, TimeHelper::CurrentTimeStamp(), true);
        std::cout << "UTC time: " << TimeHelper::TM2TimeStr(tm) << std::endl;
    }
    {
        TimeHelper::TimeStamp2TM(tm, TimeHelper::CurrentTimeStamp(), false);
        std::cout << "local time: " << TimeHelper::TM2TimeStr(tm) << std::endl;
    }
}

void TimeStr2TMTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    struct tm tm;
    TimeHelper::TimeStamp2TM(tm, TimeHelper::CurrentTimeStamp());
    std::string tm_str = TimeHelper::TM2TimeStr(tm);
    TimeHelper::TimeStr2TM(tm, tm_str);
    PrintTM(tm);
}

void TimeStamp2TimeTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    time_t ts = TimeHelper::CurrentTimeStamp();
    {
        std::cout << "UTC time: " << TimeHelper::TimeStamp2TimeStr(ts, "%Y-%m-%d %H:%M:%S", true) << std::endl;
    }
    {
        std::cout << "local time: " << TimeHelper::TimeStamp2TimeStr(ts, "%Y-%m-%d %H:%M:%S", false) << std::endl;
    }
}

void TimeStr2TimeStampTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    time_t ts = TimeHelper::CurrentTimeStamp();
    {
        std::cout << "before: " << ts << " after: " << TimeHelper::TimeStr2TimeStamp(TimeHelper::TimeStamp2TimeStr(ts, "%Y-%m-%d %H:%M:%S", true), "%Y-%m-%d %H:%M:%S", true) << std::endl;
    }
    {
        std::cout << "before: " << ts << " after: " << TimeHelper::TimeStr2TimeStamp(TimeHelper::TimeStamp2TimeStr(ts, "%Y-%m-%d %H:%M:%S", false), "%Y-%m-%d %H:%M:%S", false) << std::endl;
    }
}

void IsLeapTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    int year[] = {2000,2100,2016};
    for (int i = 0; i < (sizeof(year) / sizeof(year[0])); i++)
    {
        std::cout << "year: " << year[i] << " is leap " << TimeHelper::IsLeap(year[i]) << std::endl;
    }
}

void FirstWeekDayOfTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    int year[] = { 2000,2100,2016,2018 };
    for (int i = 0; i < (sizeof(year) / sizeof(year[0])); i++)
    {
        std::cout << "year: " << year[i] << " first week day is " << TimeHelper::FirstWeekDayOf(year[i]) << std::endl;
    }
}

int main()
{
    GetTimeOfDayTest();
    CurrentTimeStampTest();
    TimeStamp2TMTest();
    TM2TimeStampTest();
    TM2TimeStrTEST();
    TimeStr2TMTest();
    TimeStamp2TimeTest();
    TimeStr2TimeStampTest();
    IsLeapTest();
    FirstWeekDayOfTest();
    return 0;
}

