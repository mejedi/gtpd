#include "lb_sampler.h"
#include <cmath>
#include <random>

// This is to ensure that LbSample is bitwize-compatible with uint64_t
// encoding of itself.
static_assert(alignof(LbSample) == alignof(uint64_t));
#if __BYTE_ORDER == __LITTLE_ENDIAN
static constexpr int LBSAMPLE_DURATIONNS_SHIFT = 0;
static constexpr int LBSAMPLE_COUNTERDELTA_SHIFT = 32;
#elif __BYTE_ORDER == __BIG_ENDIAN
static constexpr int LBSAMPLE_DURATIONNS_SHIFT = 32;
static constexpr int LBSAMPLE_COUNTERDELTA_SHIFT = 0;
#else
#error
#endif

static uint64_t encode(LbSample s) {
    return (uint64_t(s.duration_ns) << LBSAMPLE_DURATIONNS_SHIFT)
           | (uint64_t(s.counter_delta) << LBSAMPLE_COUNTERDELTA_SHIFT);
}

static LbSample decode(LbSample, uint64_t v) {
    return {
        .duration_ns = uint32_t(v >> LBSAMPLE_DURATIONNS_SHIFT),
        .counter_delta = uint32_t(v >> LBSAMPLE_COUNTERDELTA_SHIFT)
    };
}

std::unique_ptr<LbSampler> LbSampler::create(unsigned k) {
    return std::unique_ptr<LbSampler>(::new (
        alloc(sizeof(LbSampler) + k*sizeof(std::atomic<uint64_t>))
    ) LbSampler(k));
}

template<typename Callback>
void LbSampler::for_each_sample(const Callback &cb) const {
    if (activation_index.load(std::memory_order_acquire) == 0) return;
    for (unsigned i = 0; i != k; ++i) {
        auto s = decode(LbSample{}, sample(i)->load(std::memory_order_relaxed));
        if (s.counter_delta) cb(s);
    }
}

void LbSampler::copy_samples(std::vector<LbSample> *result) const {
    result->clear();
    for_each_sample([result] (LbSample s) { result->push_back(s); });
}

void LbSampler::copy_samples(std::vector<double> *result) const {
    result->clear();
    for_each_sample([result] (LbSample s) {
        result->push_back(double(s.duration_ns) / s.counter_delta);
    });
}

namespace {

using RandomGen = std::mt19937_64;

// random integer in [0, k) range
unsigned random_i(RandomGen &g, unsigned k) {
    static_assert(std::numeric_limits<unsigned>::max() == std::numeric_limits<uint32_t>::max());
    return ((g() & 0xffffffff) * k) >> 32;
}

// log of a random float in (0, 1) range
double log_random_f01(RandomGen &g) {
    uint64_t r;
    do {
        r = g();
    } while (__builtin_expect(r == 0, false));
    // 1.0 never produced as (2^64 - 1) turns into 2^64 when converted to double
    double v = double(r) / double(std::numeric_limits<uint64_t>::max());
    return log(v);
}

} // namespace {

detail::OpenLbSample LbSampler::begin_capture_sample_slowpath(uint64_t counter) {

    static __thread RandomGen g { std::random_device()() };

    unsigned act_idx = activation_index.load(std::memory_order_relaxed);
    assert(current_index >= act_idx);
    if (__builtin_expect(act_idx == 0, false)) {
        // concurrent reset
        for (unsigned i = 0; i != k; ++i) {
            sample(i)->store(0, std::memory_order_relaxed);
        }
        current_index = 0;
    }
    std::atomic<uint64_t> *p;
    // Reservoir sampling
    // https://en.wikipedia.org/wiki/Reservoir_sampling#An_optimal_algorithm
    // Modifications: instead of w (see article) accumulate log_w as it
    // loses precision slower.  Also use log1p(x) which is essentially
    // log(1+x) with significantly better accuracy when x approaches 0.
    unsigned next_act_idx;
    if (__builtin_expect(current_index < k, false)) {
        p = sample(current_index);
        if (current_index + 1 == k) {
            log_w = 0.0;
            goto calc_log_w_and_next_act_idx;
        }
        next_act_idx = current_index + 1;
    } else {
        p = sample(random_i(g, k));
calc_log_w_and_next_act_idx:
        log_w += log_random_f01(g) / k;
        double jump = floor(log_random_f01(g) / log1p(-exp(log_w))) + 1;
        static constexpr auto max = std::numeric_limits<decltype(current_index)>::max();
        static_assert(decltype(max)(double(max)) == max, "no precision lost");
        next_act_idx = __builtin_expect(jump > double(max - current_index), false)
                       ? max : current_index + decltype(current_index)(jump);
    }
    // assume fewer than 4 B samples are ever evaluated (no overflow)
    ++current_index;
    // mo_release pairs with mo_acquire in copy_samples;
    // we don't care if CAS failed, happens on concurrent reset
    std::atomic_compare_exchange_strong_explicit(
        &activation_index, &act_idx, next_act_idx,
        std::memory_order_release, std::memory_order_release
    );
    return { p, counter };
}

namespace detail {

OpenLbSample::OpenLbSample(std::atomic<uint64_t> *dest, uint64_t counter)
    : dest(dest), begin_counter(counter) {

    clock_gettime(CLOCK_MONOTONIC, &begin_ts);
}

void OpenLbSample::end_capture_slowpath(uint64_t counter) {
    assert(dest_cell);

    timespec end_ts;
    clock_gettime(CLOCK_MONOTONIC, &end_ts);

    // For durations exceeding 500 years the calculation will overflow.
    // The expected duration is sub-second.
    uint64_t duration_ns = std::min<uint64_t>(
        uint64_t(end_ts.tv_sec - begin_ts.tv_sec)*uint64_t(1e9)
        + uint64_t(end_ts.tv_nsec) - uint64_t(begin_ts.tv_nsec),
        std::numeric_limits<uint32_t>::max()
    );

    uint64_t counter_delta = std::min<uint64_t>(
        counter - begin_counter, std::numeric_limits<uint32_t>::max()
    );

    dest->store(
        encode(LbSample{
            .duration_ns = uint32_t(duration_ns),
            .counter_delta = uint32_t(counter_delta)
        }),
        std::memory_order_relaxed
    );
}

} // namespace detail
