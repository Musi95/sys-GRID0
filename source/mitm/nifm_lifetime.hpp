#pragma once

#include <cstdint>

namespace ztnx::mitm {
    /* libnx Service is a plain C value: destroying it does not close the
     * underlying session. Own each manually forwarded NIFM child explicitly.
     * No allocation, and no copies that could close the same handle twice. */
    template<typename T, void (*Close)(T *)>
    class NifmServiceOwner {
        T m_service;
      public:
        explicit NifmServiceOwner(T service) : m_service(service) { }
        ~NifmServiceOwner() { Close(&m_service); }
        NifmServiceOwner(const NifmServiceOwner &) = delete;
        NifmServiceOwner &operator=(const NifmServiceOwner &) = delete;
        T *get() { return &m_service; }
    };

    /* A request may be submitted/cancelled repeatedly, or lose availability
     * during a radio transition without being destroyed. Each new cycle gets
     * one bounded recovery wait; ordinary repeated polls do not keep waiting. */
    class NifmReadinessBarrier {
        bool m_complete = false;
      public:
        void Reset() { m_complete = false; }
        bool Observe(std::uint32_t state)
        {
            if (state != 3) {
                Reset();
                return false;
            }
            if (m_complete) { return false; }
            m_complete = true;
            return true;
        }
    };
}
