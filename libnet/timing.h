#ifndef TIMING__H_INCLUDED
#define TIMING__H_INCLUDED

#if defined(_MSC_VER)
#include <time\TimeHelper.h>
#elif defined(__GNUC__)
#include <time/TimeHelper.h>
#else
#error unsupported compiler
#endif

class scan_performance_vars;

/* Based on TCP congestion control techniques from RFC2581. */
struct ultra_timing_vals {
    double cwnd; /* Congestion window - in probes */
    int ssthresh; /* The threshold above which mode is changed from slow start
                  to congestion avoidance */
                  /* The number of replies we would expect if every probe produced a reply. This
                  is almost like the total number of probes sent but it is not incremented
                  until a reply is received or a probe times out. This and
                  num_replies_received are used to scale congestion window increments. */
    int num_replies_expected;
    /* The number of replies we've received to probes of any type. */
    int num_replies_received;
    /* Number of updates to this timing structure (generally packet receipts). */
    int num_updates;
    /* Last time values were adjusted for a drop (you usually only want
    to adjust again based on probes sent after that adjustment so a
    sudden batch of drops doesn't destroy timing.  Init to now */
    struct timeval last_drop;

    double cc_scale(const scan_performance_vars *perf);
    void ack(const scan_performance_vars *perf, double scale = 1.0);
    void drop(unsigned in_flight,
        const scan_performance_vars *perf, const struct timeval *now);
    void drop_group(unsigned in_flight,
        const scan_performance_vars *perf, const struct timeval *now);
};

/* These are mainly initializers for ultra_timing_vals. */
class scan_performance_vars {
public:
    scan_performance_vars()
    {
        init();
    }

public:
    int low_cwnd;  /* The lowest cwnd (congestion window) allowed */
    int host_initial_cwnd; /* Initial congestion window for ind. hosts */
    int group_initial_cwnd; /* Initial congestion window for all hosts as a group */
    int max_cwnd; /* I should never have more than this many probes
                  outstanding */
    int slow_incr; /* How many probes are incremented for each response
                   in slow start mode */
    int ca_incr; /* How many probes are incremented per (roughly) rtt in
                 congestion avoidance mode */
    int cc_scale_max; /* The maximum scaling factor for congestion window
                      increments. */
    int initial_ssthresh;
    double group_drop_cwnd_divisor; /* all-host group cwnd divided by this
                                    value if any packet drop occurs */
    double group_drop_ssthresh_divisor; /* used to drop the group ssthresh when
                                        any drop occurs */
    double host_drop_ssthresh_divisor; /* used to drop the host ssthresh when
                                       any drop occurs */

private:
    void init();
};

class timeout_info
{
public:
    int srtt; /* Smoothed rtt estimate (microseconds) */
    int rttvar; /* Rout trip time variance */
    int timeout; /* Current timeout threshold (microseconds) */

public:
    timeout_info()
    {
        initialize_timeout_info();
    }

    /* Same as adjust_timeouts(), except this one allows you to specify
    the receive time too (which could be because it was received a while
    back or it could be for efficiency because the caller already knows
    the current time */
    void adjust_timeouts2(const struct timeval *sent, const struct timeval *received);

    /* Adjust our timeout values based on the time the latest probe took for a
    response.  We update our RTT averages, etc. */
    void adjust_timeouts(struct timeval sent);

private:
    /* Call this function on a newly allocated struct timeout_info to
    initialize the values appropriately */
    void initialize_timeout_info();
};

#define DEFAULT_CURRENT_RATE_HISTORY 5.0

class RateMeter 
{
    /* This class measures current and lifetime average rates for some quantity. */
public:
    RateMeter(double current_rate_history = DEFAULT_CURRENT_RATE_HISTORY);

    void start(const struct timeval *now = NULL);
    void stop(const struct timeval *now = NULL);
    void update(double amount, const struct timeval *now = NULL);
    double GetOverallRate(const struct timeval *now = NULL) const;
    double GetCurrentRate(const struct timeval *now = NULL, bool update = true);
    double GetTotal(void) const;
    double ElapsedTime(const struct timeval *now = NULL) const;

private:
    static bool IsSet(const struct timeval *tv);

private:
    /* How many seconds to look back when calculating the "current" rates. */
    double current_rate_history;

    /* When this meter started recording. */
    struct timeval start_tv;
    /* When this meter stopped recording. */
    struct timeval stop_tv;
    /* The last time the current sample rates were updated. */
    struct timeval last_update_tv;

    double total;
    double current_rate;
};

class PacketRateMeter
{
    /* A specialization of RateMeter that measures packet and byte rates. */
public:
    PacketRateMeter(double current_rate_history = DEFAULT_CURRENT_RATE_HISTORY);

    void start(const struct timeval *now = NULL);
    void stop(const struct timeval *now = NULL);
    void update(unsigned int len, const struct timeval *now = NULL);
    double GetOverallPacketRate(const struct timeval *now = NULL) const;
    double GetCurrentPacketRate(const struct timeval *now = NULL, bool update = true);
    double GetOverallByteRate(const struct timeval *now = NULL) const;
    double GetCurrentByteRate(const struct timeval *now = NULL, bool update = true);
    unsigned long long GetNumPackets(void) const;
    unsigned long long GetNumBytes(void) const;

private:
    RateMeter packet_rate_meter;
    RateMeter byte_rate_meter;
};

#endif /* NMAP_TIMING_H */
