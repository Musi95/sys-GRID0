/*
 * sys-zerotier -- stub replacement for ext/prometheus-cpp-lite.
 *
 * WHY THIS EXISTS
 *
 * node/Metrics.hpp includes <prometheus/simpleapi.h> unconditionally -- the
 * ZT_NO_PEER_METRICS switch only removes the *per-peer* metrics, not the
 * dependency itself. The bundled prometheus-cpp-lite uses dynamic_cast, so a
 * core built with -fno-rtti does not compile, and even with RTTI enabled it
 * drags a registry of std::map<std::string,std::string> label sets into a
 * sysmodule that will never be scraped by anything.
 *
 * Putting this directory ahead of ext/ on the include path replaces the whole
 * library with counters that are structurally identical and cost nothing. The
 * ~78 `Metrics::something++` sites throughout node/ keep compiling and keep
 * being readable at a debugger prompt; nothing is exported.
 *
 * If you ever do want real metrics off the console, delete this directory and
 * build the core with RTTI enabled -- nothing else changes.
 */
#pragma once

#include <stdint.h>
#include <initializer_list>
#include <memory>   /* node/Metrics.hpp declares a std::shared_ptr<Registry> and
                        * relied on the real header to pull this in */
#include <string>
#include <utility>

namespace prometheus {

    /* Referenced by node/Metrics.cpp when it instantiates the registry. */
    class Registry { };
    class SaveToFile { };

    namespace simpleapi {

        class counter_metric_t {
          public:
            counter_metric_t() = default;
            /* Metrics are declared both standalone and as family.Add(...). */
            counter_metric_t(const char *, const char *) { }
            counter_metric_t(const counter_metric_t &) = default;
            counter_metric_t &operator=(const counter_metric_t &) = default;

            counter_metric_t &operator++()    { ++m_value; return *this; }
            counter_metric_t  operator++(int) { counter_metric_t t = *this; ++m_value; return t; }
            counter_metric_t &operator+=(uint64_t n) { m_value += n; return *this; }

            uint64_t value() const { return m_value; }

          private:
            uint64_t m_value = 0;
        };

        class gauge_metric_t {
          public:
            gauge_metric_t() = default;
            gauge_metric_t(const char *, const char *) { }
            gauge_metric_t(const gauge_metric_t &) = default;
            gauge_metric_t &operator=(const gauge_metric_t &) = default;

            gauge_metric_t &operator++()    { ++m_value; return *this; }
            gauge_metric_t  operator++(int) { gauge_metric_t t = *this; ++m_value; return t; }
            gauge_metric_t &operator--()    { --m_value; return *this; }
            gauge_metric_t  operator--(int) { gauge_metric_t t = *this; --m_value; return t; }
            gauge_metric_t &operator+=(int64_t n) { m_value += n; return *this; }
            gauge_metric_t &operator-=(int64_t n) { m_value -= n; return *this; }
            gauge_metric_t &operator=(int64_t n)  { m_value  = n; return *this; }

            int64_t value() const { return m_value; }

          private:
            int64_t m_value = 0;
        };

        /* Label sets are accepted and discarded. std::string rather than
         * const char* because some call sites pass OSUtils::nodeIDStr(). */
        using Labels = std::initializer_list<std::pair<const std::string, const std::string>>;

        template <typename Metric>
        class family_t {
          public:
            family_t(const char *, const char *) { }
            Metric Add(Labels) { return Metric{}; }
        };

        using counter_family_t = family_t<counter_metric_t>;
        using gauge_family_t   = family_t<gauge_metric_t>;

        extern Registry &registry;

    }  // namespace simpleapi
}  // namespace prometheus
