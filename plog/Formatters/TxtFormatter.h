#pragma once
#include <iomanip>
#include <plog/Util.h>

#ifdef  _WIN32
#define PLOG_ENDL "\r\n"
#else
#define PLOG_ENDL "\n"
#endif // 

namespace plog
{
    class TxtFormatter
    {
    public:
        static util::nstring header()
        {
            return util::nstring();
        }

        static util::nstring format(const Record& record)
        {
            tm t;
            util::localtime_s(&t, &record.getTime().time);

            util::nstringstream ss;
            ss << t.tm_year + 1900 << "-" << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_mon + 1 << "-" << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_mday << " ";
            ss << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_hour << ":" << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_min << ":" << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_sec << "." << std::setfill(PLOG_NSTR('0')) << std::setw(3) << record.getTime().millitm << " ";
            ss << std::setfill(PLOG_NSTR(' ')) << std::setw(5) << std::left << severityToString(record.getSeverity()) << " ";
            ss << record .getFile() << " ";
            ss << "[" << record.getTid() << "] ";
            ss << "[" << record.getFunc() << "@" << record.getLine() << "] ";
            ss << record.getMessage() << PLOG_ENDL;

            return ss.str();
        }
    };
}
