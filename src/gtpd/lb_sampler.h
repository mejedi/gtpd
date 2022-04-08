#pragma once

#include "cache_line_aligned.h"
#include <cassert>
#include <atomic>
#include <memory>
#include <vector>

struct alignas(uint64_t) LbSample {
    uint32_t duration_ns;
    uint32_t counter_delta;
};

namespace detail {
template<typename T>
struct alignas(T) AlignedBase {};
class OpenLbSample;
} // namespace detail

// We'd like to estimate how much CPU time certain task takes for proper
// load balancing.  Tasks execute in cooperative multitasking model,
// each doing a little processing before switching to the next one.  We
// could've measured every invocation of the task function, but that's
// inherently noisy.  An interrupt could arrive when the task function
// executes.  If we are (un)lucky, the thread could even get preempted!
//
// Instead, we are doing *sampling*.  Each invocation of the task
// function produces a sample, but only a small subset is retained in a
// statistically-sound way.  After eliminating outliers, we find the
// average execution time per invocation, and multiply that by the
// number of invocations, giving us an aproximate total running time.
//
// LbSampler implements the sampling.  Samples are collected using
// sampler.begin_capture_sample() / sample.end_capture().  Ensure that
// samples aren't collected concurrently using the same sampler as this
// interface is not thread-safe.
//
// However, it's perfectly valid to invoke copy_samples() and reset()
// concurrently.
struct LbSampler final: private detail::AlignedBase<std::atomic<uint64_t>>,
                        public CacheLineAligned<LbSampler> {

    static std::unique_ptr<LbSampler> create(unsigned k);

    // Discard samples collected so far.
    void reset() {
        activation_index.store(0, std::memory_order_relaxed);
    }

    // Copy samples collected so far.
    void copy_samples(std::vector<LbSample> *result) const;
    void copy_samples(std::vector<double> *result) const;

    // Begin sample capture.  Call .end_capture() on the result to
    // complete capture.
    detail::OpenLbSample begin_capture_sample(uint64_t counter);

private:
    const unsigned k;           // number of samples stored
    unsigned current_index = 0; // NEXT sample index (stream order)
    std::atomic<unsigned> activation_index = 0; // trigger capture when
                                                // current_index exceeds
                                                // activation_index
    double log_w;
    // followed by atomic<uint64_t> samples[k]

private:
    LbSampler(unsigned k): k(k) {}

    detail::OpenLbSample begin_capture_sample_slowpath(uint64_t counter);

    std::atomic<uint64_t> *sample(unsigned index) const {
        assert(index < k);
        return reinterpret_cast<std::atomic<uint64_t> *>(
            const_cast<LbSampler *>(this) + 1
        ) + index;
        // LbSampler is immediately followed by atomic<uint64_t> samples[k]
    }

    template<typename Callback>
    void for_each_sample(const Callback &cb) const;
};

namespace detail {
class OpenLbSample {
    std::atomic<uint64_t> *dest;
    uint64_t begin_counter;
    timespec begin_ts;
public:
    OpenLbSample(): dest(nullptr) {}
    OpenLbSample(std::atomic<uint64_t> *, uint64_t);
    void end_capture(uint64_t counter) {
        if (__builtin_expect(dest != nullptr, false)) {
            end_capture_slowpath(counter);
        }
    }
private:
    void end_capture_slowpath(uint64_t counter);
};
} // namespace detail

inline detail::OpenLbSample LbSampler::begin_capture_sample(uint64_t counter) {
    if (__builtin_expect(current_index
                         < activation_index.load(std::memory_order_relaxed),
                         true)) {
        ++current_index;
        return {};
    }
    return begin_capture_sample_slowpath(counter);
}
