#ifndef TIME_HELPER_H_INCLUDED
#define TIME_HELPER_H_INCLUDED

#if defined(_MSC_VER)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <WinSock2.h>
#include <time.h>  
#include <string.h>  
#include <stdlib.h>  
#include <stdio.h>  
#include <cctype>
#elif defined(__GNUC__)
#include <sys/time.h>
#include <string.h>
#else
#error unsupported compiler
#endif
#include <time.h>
#include <string>

#ifndef TM_YEAR_BASE
#define TM_YEAR_BASE 1900 
#endif // !TM_YEAR_BASE

/* Timeval subtraction in microseconds */
#define TIMEVAL_SUBTRACT(a,b) (((a).tv_sec - (b).tv_sec) * 1000000 + (a).tv_usec - (b).tv_usec)
/* Timeval subtract in milliseconds */
#define TIMEVAL_MSEC_SUBTRACT(a,b) ((((a).tv_sec - (b).tv_sec) * 1000) + ((a).tv_usec - (b).tv_usec) / 1000)
/* Timeval subtract in seconds; truncate towards zero */
#define TIMEVAL_SEC_SUBTRACT(a,b) ((a).tv_sec - (b).tv_sec + (((a).tv_usec < (b).tv_usec) ? - 1 : 0))
/* Timeval subtract in fractional seconds; convert to float */
#define TIMEVAL_FSEC_SUBTRACT(a,b) ((a).tv_sec - (b).tv_sec + (((a).tv_usec - (b).tv_usec)/1000000.0))

/* assign one timeval to another timeval plus some msecs: a = b + msecs */
#define TIMEVAL_MSEC_ADD(a, b, msecs) { (a).tv_sec = (b).tv_sec + ((msecs) / 1000); (a).tv_usec = (b).tv_usec + ((msecs) % 1000) * 1000; (a).tv_sec += (a).tv_usec / 1000000; (a).tv_usec %= 1000000; }
#define TIMEVAL_ADD(a, b, usecs) { (a).tv_sec = (b).tv_sec + ((usecs) / 1000000); (a).tv_usec = (b).tv_usec + ((usecs) % 1000000); (a).tv_sec += (a).tv_usec / 1000000; (a).tv_usec %= 1000000; }

/* Find our if one timeval is before or after another, avoiding the integer
overflow that can result when doing a TIMEVAL_SUBTRACT on two widely spaced
timevals. */
#define TIMEVAL_BEFORE(a, b) (((a).tv_sec < (b).tv_sec) || ((a).tv_sec == (b).tv_sec && (a).tv_usec < (b).tv_usec))
#define TIMEVAL_AFTER(a, b) (((a).tv_sec > (b).tv_sec) || ((a).tv_sec == (b).tv_sec && (a).tv_usec > (b).tv_usec))

/* Convert a timeval to floating point seconds */
#define TIMEVAL_SECS(a) ((double) (a).tv_sec + (double) (a).tv_usec / 1000000)

static char utc[] = { "UTC" };
/* RFC-822/RFC-2822 */
static const char * const nast[5] = {
    "EST",    "CST",    "MST",    "PST",    "\0\0\0"
};
static const char * const nadt[5] = {
    "EDT",    "CDT",    "MDT",    "PDT",    "\0\0\0"
};
/*
* Table to determine the ordinal date for the start of a month.
*/
static const int start_of_month[2][13] = {
    /* non-leap year */
    { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
    /* leap year */
    { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
};

static const char *day[7] = {
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday",
    "Friday", "Saturday"
};
static const char *abday[7] = {
    "Sun","Mon","Tue","Wed","Thu","Fri","Sat"
};
static const char *mon[12] = {
    "January", "February", "March", "April", "May", "June", "July",
    "August", "September", "October", "November", "December"
};
static const char *abmon[12] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};
static const char *am_pm[2] = {
    "AM", "PM"
};

#if defined(_MSC_VER)
struct timezone
{
    int  tz_minuteswest; // minutes W of Greenwich  
    int  tz_dsttime;     // type of dst correction
};
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#define DELTA_EPOCH_IN_MICROSECS 11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_MICROSECS 11644473600000000ULL
#endif
static struct timezone tz = []() {struct timezone ttz; _tzset(); _get_timezone((long*)&ttz.tz_minuteswest); ttz.tz_minuteswest /= 60; _get_daylight(&ttz.tz_dsttime); return ttz; }();
inline int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    FILETIME ft;
    unsigned long long tmpres = 0;
    static int tzflag = 0;
    if (tv)
    {
#ifdef _WIN32_WCE
        SYSTEMTIME st;
        GetSystemTime(&st);
        SystemTimeToFileTime(&st, &ft);
#else
        GetSystemTimeAsFileTime(&ft);
#endif
        tmpres |= ft.dwHighDateTime;
        tmpres <<= 32;
        tmpres |= ft.dwLowDateTime;

        /*converting file time to unix epoch*/
        tmpres /= 10;  /*convert into microseconds*/
        tmpres -= DELTA_EPOCH_IN_MICROSECS;
        tv->tv_sec = (long)(tmpres / 1000000UL);
        tv->tv_usec = (long)(tmpres % 1000000UL);
    }

    if (tz)
    {
        *tz = ::tz;
    }
    return 0;
}
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

class TimeHelper
{
public:
    /**
    *get the utc timestamp
    */
    inline static time_t CurrentTimeStamp(){ return time(NULL); }

    /**
    *transfer timestamp to tm
    *ts(in): utc timestamp
    *to_utc(in): is to utc tm
    */
    inline static bool TimeStamp2TM(struct tm &tm, const time_t ts, const bool to_utc = false)
    { 
        bool ret = false;
#if defined(_MSC_VER)
        errno_t res;
        if(to_utc)
            res = gmtime_s(&tm, &ts);
        else
            res = localtime_s(&tm, &ts);
        ret = res ? false : true;
#elif defined(__GNUC__)
        struct tm *p;
        if (to_utc)
            p = gmtime_r(&ts, &tm);
        else
            p = localtime_r(&ts, &tm);
        ret = p ? true : false;
#else
#error unsupported compiler
#endif
        return ret;
    }

    /**
    *transfer tm to timestamp
    *tm(in):  tm
    *from_utc(in): is utc tm
    *return: -1:false, other true
    */
    inline static time_t TM2TimeStamp(struct tm &tm, const bool from_utc = false)
    {
        if (from_utc)
#if defined(_MSC_VER)
            return _mkgmtime(&tm);
#elif defined(__GNUC__)
        {
            time_t ret = 0;
            std::string tz;
            char *p = getenv("TZ");
            if (p) tz = p;
            setenv("TZ", "", 1);
            tzset();
            ret = mktime(&tm);
            if (!tz.empty())
                setenv("TZ", tz.c_str(), 1);
            else
                unsetenv("TZ");
            tzset();
            return ret;
        }
#else
#error unsupported compiler
#endif
        else
            return mktime(&tm);
    }

    /**
    *transfer the time string to tm
    *tm(out): result
    *tm_str(in): the time string need to be transfer
    *format(in): tm_str input format
    */
    inline static bool TimeStr2TM(struct tm &tm, const std::string &tm_str, const std::string &format = "%Y-%m-%d %H:%M:%S")
    {
        if (tm_str.size() > 1024) return false;
        return strptime(tm_str.c_str(), format.c_str(), &tm) == NULL ? false : true;
    }

    /**
    *transfer the tm to time string
    *tm(in): tm struct
    *format(in): the time string format
    */
    inline static std::string TM2TimeStr(struct tm &tm, const std::string &format = "%Y-%m-%d %H:%M:%S")
    {
        char buf[1024] = { 0 };
        strftime(buf, sizeof(buf), format.c_str(), &tm);
        return buf;
    }

    /**
    *transfer the time string to time stamp
    *tm_str(in): the time string need to be transfer
    *format(in): tm_str input format
    *from_utc(in): is utc time
    *return: -1 error
    */
    inline static time_t TimeStr2TimeStamp(const std::string &tm_str, const std::string &format = "%Y-%m-%d %H:%M:%S", const bool from_utc = false)
    {
        if (tm_str.size() > 1024) return -1;
        struct tm tm;
        if (!TimeStr2TM(tm, tm_str, format)) return -1;
        return TM2TimeStamp(tm, from_utc);
    }

    /**
    *transfer the time stamp to time string
    *time(in): time stamp
    *format(in): the time string format
    *to_utc(in): is to UTC time string
    */
    inline static std::string TimeStamp2TimeStr(const time_t ts, const std::string &format = "%Y-%m-%d %H:%M:%S", const bool to_utc = false)
    {
        struct tm tm;
        if (!TimeStamp2TM(tm, ts, to_utc)) return "";
        return TM2TimeStr(tm, format);
    }

    /**
    *Calculate if is leap year
    */
    inline static bool IsLeap(int year)
    {
        return ((year % 4 == 0 && year % 100) || year % 400 == 0);
    }

    /*
    * Calculate the week day of the first day of a year. Valid for
    * the Gregorian calendar, which began Sept 14, 1752 in the UK
    * and its colonies.
    * return: the day since Sunday
    * for example. 2018.1.1 is week 1, so return 1, 2016.1.1 is week 5, so return 5
    */
    inline static int FirstWeekDayOf(int yr)
    {
        return ((2 * (3 - (yr / 100) % 4)) + (yr % 100) + ((yr % 100) / 4) +
            (IsLeap(yr) ? 6 : 0) + 1) % 7;
    }

private:
#if defined(_MSC_VER) 
    /*
    * We do not implement alternate representations. However, we always
    * check whether a given modifier is allowed for a certain conversion.
    */
#define ALT_E            0x01
#define ALT_O            0x02
#define LEGAL_ALT(x)        { if (alt_format & ~(x)) return NULL; }

#define S_YEAR            (1 << 0)
#define S_MON             (1 << 1)
#define S_YDAY            (1 << 2)
#define S_MDAY            (1 << 3)
#define S_WDAY            (1 << 4)
#define S_HOUR            (1 << 5)

#define HAVE_MDAY(s)        (s & S_MDAY)
#define HAVE_MON(s)         (s & S_MON)
#define HAVE_WDAY(s)        (s & S_WDAY)
#define HAVE_YDAY(s)        (s & S_YDAY)
#define HAVE_YEAR(s)        (s & S_YEAR)
#define HAVE_HOUR(s)        (s & S_HOUR) 
#define delim(p)    ((p) == '\0' || isspace((unsigned char)(p)))
    /**
    *convert format string to tm
    */
    static char *strptime(const char *buf, const char *fmt, struct tm *tm)
    {
        char c;
        const char *bp;
        size_t len = 0;
        int alt_format, i, split_year = 0;

        bp = buf;

        while ((c = *fmt) != '\0') 
        {
            /* Clear `alternate' modifier prior to new conversion. */
            alt_format = 0;

            /* Eat up white-space. */
            if (isspace(c)) 
            {
                while (isspace(*bp)) bp++;
                fmt++;
                continue;
            }

            if ((c = *fmt++) != '%') goto literal;

        again:
            switch (c = *fmt++) {
            case '%': /* "%%" is converted to "%". */
        literal:
                if (c != *bp++) return (0);
                break;

                /*
                * "Alternative" modifiers. Just set the appropriate flag
                * and start over again.
                */
            case 'E': /* "%E?" alternative conversion modifier. */
                LEGAL_ALT(0);
                alt_format |= ALT_E;
                goto again;

            case 'O': /* "%O?" alternative conversion modifier. */
                LEGAL_ALT(0);
                alt_format |= ALT_O;
                goto again;

                /*
                * "Complex" conversion rules, implemented through recursion.
                */
            case 'c': /* Date and time, using the locale's format. */
                LEGAL_ALT(ALT_E);
                if (!(bp = strptime(bp, "%x %X", tm))) return (0);
                break;

            case 'D': /* The date as "%m/%d/%y". */
                LEGAL_ALT(0);
                if (!(bp = strptime(bp, "%m/%d/%y", tm))) return (0);
                break;

            case 'R': /* The time as "%H:%M". */
                LEGAL_ALT(0);
                if (!(bp = strptime(bp, "%H:%M", tm))) return (0);
                break;

            case 'r': /* The time in 12-hour clock representation. */
                LEGAL_ALT(0);
                if (!(bp = strptime(bp, "%I:%M:%S %p", tm))) return (0);
                break;

            case 'T': /* The time as "%H:%M:%S". */
                LEGAL_ALT(0);
                if (!(bp = strptime(bp, "%H:%M:%S", tm))) return (0);
                break;

            case 'X': /* The time, using the locale's format. */
                LEGAL_ALT(ALT_E);
                if (!(bp = strptime(bp, "%H:%M:%S", tm))) return (0);
                break;

            case 'x': /* The date, using the locale's format. */
                LEGAL_ALT(ALT_E);
                if (!(bp = strptime(bp, "%m/%d/%y", tm))) return (0);
                break;

                /*
                * "Elementary" conversion rules.
                */
            case 'A': /* The day of week, using the locale's form. */
            case 'a':
                LEGAL_ALT(0);
                for (i = 0; i < 7; i++)
                {
                    /* Full name. */
                    len = strlen(day[i]);
                    if (strncmp(day[i], bp, len) == 0) break;
                    /* Abbreviated name. */
                    len = strlen(abday[i]);
                    if (strncmp(abday[i], bp, len) == 0) break;
                }
                /* Nothing matched. */
                if (i == 7) return (0);
                tm->tm_wday = i;
                bp += len;
                break;

            case 'B': /* The month, using the locale's form. */
            case 'b':
            case 'h':
                LEGAL_ALT(0);
                for (i = 0; i < 12; i++)
                {
                    /* Full name. */
                    len = strlen(mon[i]);
                    if (strncmp(mon[i], bp, len) == 0) break;
                    /* Abbreviated name. */
                    len = strlen(abmon[i]);
                    if (strncmp(abmon[i], bp, len) == 0) break;
                }
                /* Nothing matched. */
                if (i == 12) return (0);
                tm->tm_mon = i;
                bp += len;
                break;

            case 'C': /* The century number. */
                LEGAL_ALT(ALT_E);
                if (!(conv_num(&bp, &i, 0, 99))) return (0);
                if (split_year)
                {
                    tm->tm_year = (tm->tm_year % 100) + (i * 100);
                }
                else
                {
                    tm->tm_year = i * 100;
                    split_year = 1;
                }
                break;

            case 'd': /* The day of month. */
            case 'e':
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_mday, 1, 31))) return (0);
                break;

            case 'k': /* The hour (24-hour clock representation). */
                LEGAL_ALT(0);
                /* FALLTHROUGH */
            case 'H':
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_hour, 0, 23))) return (0);
                break;

            case 'l': /* The hour (12-hour clock representation). */
                LEGAL_ALT(0);
                /* FALLTHROUGH */
            case 'I':
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_hour, 1, 12))) return (0);
                if (tm->tm_hour == 12) tm->tm_hour = 0;
                break;

            case 'j': /* The day of year. */
                LEGAL_ALT(0);
                if (!(conv_num(&bp, &i, 1, 366))) return (0);
                tm->tm_yday = i - 1;
                break;

            case 'M': /* The minute. */
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_min, 0, 59))) return (0);
                break;

            case 'm': /* The month. */
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &i, 1, 12))) return (0);
                tm->tm_mon = i - 1;
                break;

            case 'p': /* The locale's equivalent of AM/PM. */
                LEGAL_ALT(0);
                /* AM? */
                if (strcmp(am_pm[0], bp) == 0) 
                {
                    if (tm->tm_hour > 11)
                        return (0);

                    bp += strlen(am_pm[0]);
                    break;
                }
                /* PM? */
                else if (strcmp(am_pm[1], bp) == 0)
                {
                    if (tm->tm_hour > 11)
                        return (0);

                    tm->tm_hour += 12;
                    bp += strlen(am_pm[1]);
                    break;
                }
                /* Nothing matched. */
                return (0);

            case 'S': /* The seconds. */
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_sec, 0, 61))) return (0);
                break;

            case 'U': /* The week of year, beginning on sunday. */
            case 'W': /* The week of year, beginning on monday. */
                LEGAL_ALT(ALT_O);
                /*
                * XXX This is bogus, as we can not assume any valid
                * information present in the tm structure at this
                * point to calculate a real value, so just check the
                * range for now.
                */
                if (!(conv_num(&bp, &i, 0, 53))) return (0);
                break;

            case 'w': /* The day of week, beginning on sunday. */
                LEGAL_ALT(ALT_O);
                if (!(conv_num(&bp, &tm->tm_wday, 0, 6)))
                    return (0);
                break;

            case 'Y': /* The year. */
                LEGAL_ALT(ALT_E);
                if (!(conv_num(&bp, &i, 0, 9999)))
                    return (0);

                tm->tm_year = i - TM_YEAR_BASE;
                break;

            case 'y': /* The year within 100 years of the epoch. */
                LEGAL_ALT(ALT_E | ALT_O);
                if (!(conv_num(&bp, &i, 0, 99))) return (0);
                if (split_year)
                {
                    tm->tm_year = ((tm->tm_year / 100) * 100) + i;
                    break;
                }
                split_year = 1;
                if (i <= 68)
                    tm->tm_year = i + 2000 - TM_YEAR_BASE;
                else
                    tm->tm_year = i + 1900 - TM_YEAR_BASE;
                break;

                /*
                * Miscellaneous conversions.
                */
            case 'n': /* Any kind of white-space. */
            case 't':
                LEGAL_ALT(0);
                while (isspace(*bp))
                    bp++;
                break;

            default:  /* Unknown/unsupported conversion. */
                return (0);
            }
        }

        /* LINTED functional specification */
        return ((char *)bp);
    }

    /**
    *convert the num string to num
    *buf(in): point to the buf string address
    *dest(out): the num int
    *llim(in): low limit
    *ulim(in): up limit
    */
    static int conv_num(const char **buf, int *dest, int llim, int ulim)
    {
        int result = 0;
        /* The limit also determines the number of valid digits. */
        int rulim = ulim;
        if (**buf < '0' || **buf > '9') return (0);
        do
        {
            result *= 10;
            result += *(*buf)++ - '0';
            rulim /= 10;
        } while ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');
        if (result < llim || result > ulim) return (0);
        *dest = result;
        return (1);
    }
#endif

};

#endif