#include "../source/mitm/nifm_lifetime.hpp"

#include <cstdio>
#include <type_traits>

namespace {
    int failures = 0;
    int checks = 0;
    void expect(bool value, const char *message) {
        ++checks;
        if (!value) { ++failures; std::printf("FAIL: %s\n", message); }
    }

    struct FakeService { int handle; };
    int active = 0;
    int closed = 0;
    void closeService(FakeService *service) {
        expect(service->handle != 0, "service is closed exactly once");
        service->handle = 0;
        --active;
        ++closed;
    }
    FakeService openService() { return {++active}; }
    using Owner = ztnx::mitm::NifmServiceOwner<FakeService, closeService>;

    void test_service_lifetime() {
        static_assert(!std::is_copy_constructible_v<Owner>);
        static_assert(!std::is_copy_assignable_v<Owner>);
        static_assert(!std::is_move_constructible_v<Owner>);
        static_assert(sizeof(Owner) == sizeof(FakeService));
        for (int launch = 0; launch < 100; ++launch) {
            {
                Owner general(openService());
                for (int cycle = 0; cycle < 10; ++cycle) {
                    {
                        Owner request(openService());
                        expect(request.get()->handle != 0, "forwarding uses a live request");
                        expect(active == 2, "one general session and one request");
                    }
                    expect(active == 1, "leaving a request releases its session");
                }
                expect(general.get()->handle != 0, "general service survives child teardown");
            }
            expect(active == 0, "closing a game leaves no owned sessions");
        }
        expect(closed == 1100, "all sessions from 100 launches and 1000 requests released");
    }

    void test_repeated_radio_cycles() {
        ztnx::mitm::NifmReadinessBarrier barrier;
        expect(!barrier.Observe(1), "offline request does not wait");
        expect(barrier.Observe(3), "first LAN availability gets a recovery wait");
        for (int poll = 0; poll < 100; ++poll) {
            expect(!barrier.Observe(3), "steady LAN polls do not repeatedly block");
        }
        for (int cycle = 0; cycle < 100; ++cycle) {
            expect(!barrier.Observe(1), "radio loss rearms without waiting");
            expect(!barrier.Observe(2), "pending recovery does not wait");
            expect(barrier.Observe(3), "each return to LAN gets its own recovery wait");
            expect(!barrier.Observe(3), "each cycle waits only once");
        }
        barrier.Reset(); // successful Cancel, even if no unavailable state was polled
        expect(barrier.Observe(3), "cancel/reuse rearms the existing request");
        barrier.Reset(); // successful Submit of the same request
        expect(barrier.Observe(3), "resubmit rearms without an intermediate state poll");
        expect(!barrier.Observe(3), "timeout/completed wait remains bounded within a cycle");
    }
}

int main() {
    test_service_lifetime();
    test_repeated_radio_cycles();
    std::printf("NIFM lifecycle: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
