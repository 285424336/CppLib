#include "timing.h"
#include <math.h>
#include <limits>

#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif


#define MIN_CWND 1
#define MAX_CWND 300
#define INITIAL_CWND 150 /* Allow 150 packet in network */
#define MIN_RTT_TIMEOUT 100
#define MAX_RTT_TIMEOUT 10000
#define INITIAL_RTT_TIMEOUT 1000 /* Allow 1 second initially for packet responses */

template<class T> T box(T bmin, T bmax, T bnum)
{
    if (bnum >= bmax)
        return bmax;
    if (bnum <= bmin)
        return bmin;
    return bnum;
}

/* Call this function on a newly allocated struct timeout_info to
initialize the values appropriately */
void timeout_info::initialize_timeout_info()
{
    this->srtt = -1;
    this->rttvar = -1;
    this->timeout = INITIAL_RTT_TIMEOUT * 1000;
}

/* Adjust our timeout values based on the time the latest probe took for a
response.  We update our RTT averages, etc. */
void timeout_info::adjust_timeouts(struct timeval sent)
{
    struct timeval received;
    gettimeofday(&received, NULL);

    adjust_timeouts2(&sent, &received);
    return;
}

/* Same as adjust_timeouts(), except this one allows you to specify
the receive time too (which could be because it was received a while
back or it could be for efficiency because the caller already knows
the current time */
void timeout_info::adjust_timeouts2(const struct timeval *sent, const struct timeval *received)
{
    long delta = 0;

    delta = TIMEVAL_SUBTRACT(*received, *sent);

    /* Argh ... pcap receive time is sometimes a little off my
    getimeofday() results on various platforms :(.  So a packet may
    appear to be received as much as a hundredth of a second before
    it was sent.  So I will allow small negative RTT numbers */
    if (delta < 0 && delta > -50000) {
        delta = 10000;
    }

    if (this->srtt == -1 && this->rttvar == -1) {
        /* We need to initialize the sucker ... */
        this->srtt = delta;
        this->rttvar = max(5000, min(this->srtt, 2000000));
        this->timeout = this->srtt + (this->rttvar << 2);
    }
    else {
        long rttdelta;

        if (delta >= 8000000 || delta < 0) {
            return;
        }
        rttdelta = delta - this->srtt;
        /* sanity check 2*/
        if (rttdelta > 1500000 && rttdelta > 3 * this->srtt + 2 * this->rttvar) {
            return;
        }
        this->srtt += rttdelta >> 3;
        this->rttvar += (abs(rttdelta) - this->rttvar) >> 2;
        this->timeout = this->srtt + (this->rttvar << 2);
    }
    if (this->rttvar > 2300000) {
        this->rttvar = 2000000;
    }

    /* It hurts to do this ... it really does ... but otherwise we are being
    too risky */
    this->timeout = box(MIN_RTT_TIMEOUT * 1000, MAX_RTT_TIMEOUT * 1000, this->timeout);
}

/* Returns the scaling factor to use when incrementing the congestion
window. */
double ultra_timing_vals::cc_scale(const scan_performance_vars *perf) {
    double ratio;

    ratio = (double)num_replies_expected / num_replies_received;
    return min(ratio, perf->cc_scale_max);
}

/* Update congestion variables for the receipt of a reply. */
void ultra_timing_vals::ack(const scan_performance_vars *perf, double scale) {
    num_replies_received++;

    if (cwnd < ssthresh) {
        /* In slow start mode. "During slow start, a TCP increments cwnd by at most
        SMSS bytes for each ACK received that acknowledges new data." */
        cwnd += perf->slow_incr * cc_scale(perf) * scale;
        if (cwnd > ssthresh)
            cwnd = ssthresh;
    }
    else {
        /* Congestion avoidance mode. "During congestion avoidance, cwnd is
        incremented by 1 full-sized segment per round-trip time (RTT). The
        equation
        cwnd += SMSS*SMSS/cwnd
        provides an acceptable approximation to the underlying principle of
        increasing cwnd by 1 full-sized segment per RTT." */
        cwnd += perf->ca_incr / cwnd * cc_scale(perf) * scale;
    }
    if (cwnd > perf->max_cwnd) {
        cwnd = perf->max_cwnd;
    }
}

/* Update congestion variables for a detected drop. */
void ultra_timing_vals::drop(unsigned in_flight,
    const scan_performance_vars *perf, const struct timeval *now) {
    /* "When a TCP sender detects segment loss using the retransmission timer, the
    value of ssthresh MUST be set to no more than the value
    ssthresh = max (FlightSize / 2, 2*SMSS)
    Furthermore, upon a timeout cwnd MUST be set to no more than the loss
    window, LW, which equals 1 full-sized segment (regardless of the value of
    IW)." */
    cwnd = perf->low_cwnd;
    ssthresh = (int)max(in_flight / perf->host_drop_ssthresh_divisor, 2);
    last_drop = *now;
}

/* Update congestion variables for a detected drop, but less aggressively for
group congestion control. */
void ultra_timing_vals::drop_group(unsigned in_flight,
    const scan_performance_vars *perf, const struct timeval *now) {
    cwnd = max(perf->low_cwnd, cwnd / perf->group_drop_cwnd_divisor);
    ssthresh = (int)max(in_flight / perf->group_drop_ssthresh_divisor, 2);
    last_drop = *now;
}

/* Do initialization after the global NmapOps table has been filled in. */
void scan_performance_vars::init() {
    /* TODO: I should revisit these values for tuning.  They should probably
    at least be affected by -T. */
    low_cwnd = MIN_CWND;
    max_cwnd = MAX_CWND;
    group_initial_cwnd = box(low_cwnd, max_cwnd, INITIAL_CWND);
    host_initial_cwnd = group_initial_cwnd;
    slow_incr = 1;
    /* The congestion window grows faster with more aggressive timing. */
    ca_incr = 1;
    cc_scale_max = 50;
    initial_ssthresh = 75;
    group_drop_cwnd_divisor = 2.0;
    /* Change the amount that ssthresh drops based on the timing level. */
    double ssthresh_divisor;
    ssthresh_divisor = (3.0 / 2.0);
    group_drop_ssthresh_divisor = ssthresh_divisor;
    host_drop_ssthresh_divisor = ssthresh_divisor;
}

RateMeter::RateMeter(double current_rate_history)
{
    this->current_rate_history = current_rate_history;
    start_tv.tv_sec = 0;
    start_tv.tv_usec = 0;
    stop_tv.tv_sec = 0;
    stop_tv.tv_usec = 0;
    last_update_tv.tv_sec = 0;
    last_update_tv.tv_usec = 0;
    total = 0.0;
    current_rate = 0.0;
}

void RateMeter::start(const struct timeval *now)
{
    if (now == NULL) {
        gettimeofday(&start_tv, NULL);
    }
    else {
        start_tv = *now;
    }
}

void RateMeter::stop(const struct timeval *now)
{
    if (now == NULL) {
        gettimeofday(&stop_tv, NULL);
    }
    else {
        stop_tv = *now;
    }
}

void RateMeter::update(double amount, const struct timeval *now)
{
    struct timeval tv;
    double diff;
    double interval;
    double count;

    /* Update the total. */
    total += amount;

    if (now == NULL) {
        gettimeofday(&tv, NULL);
        now = &tv;
    }
    if (!IsSet(&last_update_tv)) {
        last_update_tv = start_tv;
    }

    /* Calculate the approximate moving average of how much was recorded in the
    last current_rate_history seconds. This average is what is returned as the
    "current" rate. */

    /* How long since the last update? */
    diff = TIMEVAL_SUBTRACT(*now, last_update_tv) / 1000000.0;

    if (diff < -current_rate_history) {
        /* This happened farther in the past than we care about. */
        return;
    }

    if (diff < 0.0) {
        /* If the event happened in the past, just add it into the total and don't
        change last_update_tv, as if it had happened at the same time as the most
        recent event. */
        now = &last_update_tv;
        diff = 0.0;
    }

    /* Find out how far back in time to look. We want to look back
    current_rate_history seconds, or to when the last update occurred,
    whichever is longer. However, we never look past the start. */
    struct timeval tmp;
    /* Find the time current_rate_history seconds after the start. That's our
    threshold for deciding how far back to look. */
    TIMEVAL_ADD(tmp, start_tv, (long)(current_rate_history * 1000000.0));
    if (TIMEVAL_AFTER(*now, tmp)) {
        interval = max(current_rate_history, diff);
    }
    else {
        interval = TIMEVAL_SUBTRACT(*now, start_tv) / 1000000.0;
    }
    /* If we record an amount in the very same instant that the timer is started,
    there's no way to calculate meaningful rates. Ignore it. */
    if (interval == 0.0) {
        return;
    }

    /* To calculate the approximate average of the rate over the last
    interval seconds, we assume that the rate was constant over that interval.
    We calculate how much would have been received in that interval, ignoring
    the first diff seconds' worth:
    (interval - diff) * current_rate.
    Then we add how much was received in the most recent diff seconds. Divide
    by the width of the interval to get the average. */
    count = (interval - diff) * current_rate + amount;
    current_rate = count / interval;

    last_update_tv = *now;
}

double RateMeter::GetOverallRate(const struct timeval *now) const
{
    double elapsed;

    elapsed = ElapsedTime(now);
    if (elapsed <= 0.0) {
        return 0.0;
    }
    else {
        return total / elapsed;
    }
}

double RateMeter::GetCurrentRate(const struct timeval *now, bool update)
{
    if (update) {
        this->update(0.0, now);
    }
    return current_rate;
}

double RateMeter::GetTotal(void) const
{
    return total;
}

double RateMeter::ElapsedTime(const struct timeval *now) const
{
    struct timeval tv;
    const struct timeval *end_tv;

    if (IsSet(&stop_tv)) {
        end_tv = &stop_tv;
    }
    else if (now == NULL) {
        gettimeofday(&tv, NULL);
        end_tv = &tv;
    }
    else {
        end_tv = now;
    }

    return TIMEVAL_SUBTRACT(*end_tv, start_tv) / 1000000.0;
}

bool RateMeter::IsSet(const struct timeval *tv)
{
    return tv->tv_sec != 0 || tv->tv_usec != 0;
}

PacketRateMeter::PacketRateMeter(double current_rate_history):packet_rate_meter(current_rate_history), byte_rate_meter(current_rate_history)
{

}

void PacketRateMeter::start(const struct timeval *now)
{
    packet_rate_meter.start(now);
    byte_rate_meter.start(now);
}

void PacketRateMeter::stop(const struct timeval *now)
{
    packet_rate_meter.stop(now);
    byte_rate_meter.stop(now);
}

void PacketRateMeter::update(unsigned int len, const struct timeval *now)
{
    packet_rate_meter.update(1, now);
    byte_rate_meter.update(len, now);
}

double PacketRateMeter::GetOverallPacketRate(const struct timeval *now) const
{
    return packet_rate_meter.GetOverallRate(now);
}

double PacketRateMeter::GetCurrentPacketRate(const struct timeval *now, bool update)
{
    return packet_rate_meter.GetCurrentRate(now, update);
}

double PacketRateMeter::GetOverallByteRate(const struct timeval *now) const
{
    return byte_rate_meter.GetOverallRate(now);
}

double PacketRateMeter::GetCurrentByteRate(const struct timeval *now, bool update)
{
    return byte_rate_meter.GetCurrentRate(now, update);
}

unsigned long long PacketRateMeter::GetNumPackets(void) const
{
    return (unsigned long long) packet_rate_meter.GetTotal();
}

unsigned long long PacketRateMeter::GetNumBytes(void) const
{
    return (unsigned long long) byte_rate_meter.GetTotal();
}
