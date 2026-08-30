/*
 * sys-zerotier -- stub for <prometheus/histogram.h>.
 *
 * node/Metrics.hpp includes this unconditionally but only uses Histogram and
 * CustomFamily behind #ifndef ZT_NO_PEER_METRICS, which the sysmodule build
 * defines. See simpleapi.h in this directory for the rationale.
 */
#pragma once

#include <stdint.h>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

namespace prometheus {

    template <typename T>
    class Histogram {
      public:
        void Observe(T) { }
    };

    template <typename Metric>
    class CustomFamily {
      public:
        using Labels = std::initializer_list<std::pair<const std::string, const std::string>>;
        Metric &Add(Labels) { static Metric m; return m; }
        Metric &Add(Labels, const std::vector<uint64_t> &) { static Metric m; return m; }
    };

    template <typename Metric>
    class Builder {
      public:
        Builder &Name(const char *) { return *this; }
        Builder &Help(const char *) { return *this; }
        template <typename R> CustomFamily<Metric> &Register(R &) {
            static CustomFamily<Metric> f; return f;
        }
    };

}  // namespace prometheus
