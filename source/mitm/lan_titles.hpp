/* Native Nintendo Switch LAN-mode applications supported by the packet MITM. */
#pragma once

#include <stratosphere.hpp>

namespace ztnx::mitm {
    constexpr u64 Splatoon3ProgramId = 0x0100C2500FC20000ull;

    struct LanTitle {
        u64 id;
        const char *name;
    };

    /* Ryujinx/Ryubing's LAN-mode list, plus Nintendo Switch Sports (added
     * later) and Civilization VI, which was already in this project's native
     * LAN research. Region-specific releases have distinct program ids and
     * therefore each need an entry. Keep this explicit: nifm:u is a deliberately
     * small proxy and must never be placed in front of arbitrary applications. */
    constexpr LanTitle LanTitles[] = {
        { 0x01009B500007C000ull, "ARMS" },
        { 0x01007960049A0000ull, "Bayonetta 2" },
        { 0x010044500C182000ull, "Civilization VI" },
        { 0x01007EF00CB88000ull, "Duke Nukem 3D: 20th Anniversary" },

        { 0x010002C00C270000ull, "Mario & Sonic Tokyo 2020 (JP)" },
        { 0x010003000E146000ull, "Mario & Sonic Tokyo 2020 (US)" },
        { 0x010086000E148000ull, "Mario & Sonic Tokyo 2020 (EU)" },
        { 0x010012700F232000ull, "Mario & Sonic Tokyo 2020 (CN)" },

        { 0x0100152000022000ull, "Mario Kart 8 Deluxe" },
        { 0x0100BDE00862A000ull, "Mario Tennis Aces" },
        { 0x0100D2F00D5C0000ull, "Nintendo Switch Sports" },
        { 0x0100B3F000BE2000ull, "Pokken Tournament DX" },
        { 0x0100ABF008968000ull, "Pokemon Sword" },
        { 0x01008DB008C2C000ull, "Pokemon Shield" },
        { 0x0100DE600BEEE000ull, "Saints Row: The Third" },
        { 0x01008D100D43E000ull, "Saints Row IV: Re-Elected" },

        { 0x01003C700009C000ull, "Splatoon 2 (JP)" },
        { 0x01003BC0000A0000ull, "Splatoon 2 (US/CN)" },
        { 0x0100F8F0000A2000ull, "Splatoon 2 (EU)" },
        { Splatoon3ProgramId, "Splatoon 3" },
        { 0x0100605008268000ull, "Titan Quest" },
    };

    constexpr const LanTitle *FindLanTitle(u64 id) {
        for (const auto &title : LanTitles) {
            if (title.id == id) { return std::addressof(title); }
        }
        return nullptr;
    }

    constexpr bool IsSplatoon2ProgramId(u64 id) {
        return id == 0x01003C700009C000ull ||
               id == 0x01003BC0000A0000ull ||
               id == 0x0100F8F0000A2000ull;
    }

    constexpr bool UsesRyujinxNifmRequestModel(u64 id) {
        return id == Splatoon3ProgramId;
    }
}
