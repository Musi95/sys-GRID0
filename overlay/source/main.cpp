#define NDEBUG
#define STBTT_STATIC
#define TESLA_INIT_IMPL

#include <exception_wrap.hpp>
#include <tesla.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr const char *ConfigDir = "sdmc:/config/sys-zerotier/";
constexpr const char *ConfigPath = "sdmc:/config/sys-zerotier/config.ini";
constexpr const char *NetworksPath = "sdmc:/config/sys-zerotier/networks.ini";
constexpr const char *StatusPath = "sdmc:/config/sys-zerotier/status.txt";
constexpr const char *BootFlag =
    "sdmc:/atmosphere/contents/4200000000005A54/flags/boot2.flag";
constexpr const char *DisabledBootFlag =
    "sdmc:/atmosphere/contents/4200000000005A54/flags/boot2.flag.disabled";

bool IsHexNetworkId(const std::string &value)
{
    if (value.size() != 16) { return false; }
    bool nonzero = false;
    for (const char c : value) {
        const bool hex = (c >= '0' && c <= '9') ||
                         (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F');
        if (!hex) { return false; }
        nonzero |= c != '0';
    }
    return nonzero;
}

std::string UpperHex(std::string value)
{
    for (char &c : value) {
        if (c >= 'a' && c <= 'f') { c = static_cast<char>(c - 'a' + 'A'); }
    }
    return value;
}

std::string StatusValue(const char *wanted)
{
    FILE *file = std::fopen(StatusPath, "r");
    if (file == nullptr) { return {}; }
    char line[512];
    std::string result;
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        char *p = line;
        while (*p == ' ' || *p == '\t') { ++p; }
        const size_t key_len = std::strlen(wanted);
        if (std::strncmp(p, wanted, key_len) != 0 ||
            (p[key_len] != ' ' && p[key_len] != '\t')) {
            continue;
        }
        p += key_len;
        while (*p == ' ' || *p == '\t') { ++p; }
        char *end = p + std::strlen(p);
        while (end > p && (end[-1] == '\n' || end[-1] == '\r' ||
                           end[-1] == ' ' || end[-1] == '\t')) {
            --end;
        }
        result.assign(p, static_cast<size_t>(end - p));
        break;
    }
    std::fclose(file);
    return result;
}

bool FileExists(const char *path)
{
    struct stat st = {};
    return ::stat(path, &st) == 0;
}

bool ConfigSwitch(const char *key, bool default_value)
{
    const std::string value =
        ult::parseValueFromIniSection(ConfigPath, "sys-zerotier", key);
    return value.empty() ? default_value : value != "0";
}

std::string SelectedNetwork()
{
    return ult::parseValueFromIniSection(NetworksPath, "sys-zerotier", "selected");
}

std::string InitialNetworkId()
{
    const std::string selected = SelectedNetwork();
    if (!selected.empty()) {
        const std::string saved =
            ult::parseValueFromIniSection(NetworksPath, selected, "nwid");
        if (IsHexNetworkId(saved)) { return UpperHex(saved); }
    }
    const std::string active = StatusValue("network");
    return IsHexNetworkId(active) ? UpperHex(active) : "0000000000000000";
}

void SelectNetwork(const std::string &section)
{
    ult::createDirectory(ConfigDir);
    ult::setIniFileValue(NetworksPath, "sys-zerotier", "selected", section);
}

void SaveAndSelectNetwork(const std::string &nwid)
{
    /* The ID itself is a stable, collision-free saved-network name. Users can
     * still rename the section in networks.ini later without changing its ID. */
    const std::string lower = [&] {
        std::string out = nwid;
        for (char &c : out) {
            if (c >= 'A' && c <= 'F') { c = static_cast<char>(c - 'A' + 'a'); }
        }
        return out;
    }();
    ult::createDirectory(ConfigDir);
    ult::setIniFileValue(NetworksPath, lower, "nwid", lower);
    SelectNetwork(lower);
}

void SetBootEnabled(bool enabled)
{
    if (enabled) {
        if (FileExists(DisabledBootFlag)) {
            (void)std::rename(DisabledBootFlag, BootFlag);
        } else if (!FileExists(BootFlag)) {
            FILE *file = std::fopen(BootFlag, "w");
            if (file != nullptr) { std::fclose(file); }
        }
    } else if (FileExists(BootFlag)) {
        (void)std::rename(BootFlag, DisabledBootFlag);
    }
}

class NetworkEditorGui final : public tsl::Gui {
public:
    NetworkEditorGui()
    {
        m_value = InitialNetworkId();
    }

    tsl::elm::Element *createUI() override
    {
        auto *frame = new tsl::elm::OverlayFrame("Network ID", "Type all 16 digits");
        auto *list = new tsl::elm::List();
        list->addItem(new tsl::elm::CategoryHeader(
            "Keyboard types whole ID   A: keypad digit"));
        m_id = new tsl::elm::ListItem("ZeroTier network ID", DisplayValue());
        list->addItem(m_id);
        m_key_rows[0] = new tsl::elm::CategoryHeader(KeypadRow(0), false);
        m_key_rows[1] = new tsl::elm::CategoryHeader(KeypadRow(1), false);
        list->addItem(m_key_rows[0]);
        list->addItem(m_key_rows[1]);
        m_result = new tsl::elm::CategoryHeader(
            "+: save   X: erase   Y: clear", false);
        list->addItem(m_result);
        frame->setContent(list);
        return frame;
    }

    bool handleInput(u64 keys_down, u64, const HidTouchState &,
                     HidAnalogStickState, HidAnalogStickState) override
    {
        // Keyboard Enter is latched by update() and consumed here so the
        // overlay is not torn down while the framework is iterating it.
        if (m_keyboard_commit) {
            m_keyboard_commit = false;
            return Commit();
        }
        if (keys_down & KEY_LEFT) {
            m_key = (m_key + 15) % 16;
        } else if (keys_down & KEY_RIGHT) {
            m_key = (m_key + 1) % 16;
        } else if (keys_down & (KEY_UP | KEY_DOWN)) {
            m_key ^= 8;
        } else if (keys_down & KEY_A) {
            AppendHex(Hex[m_key]);
        } else if (keys_down & KEY_X) {
            EraseHex();
        } else if (keys_down & KEY_Y) {
            ClearHex();
        } else if (keys_down & KEY_PLUS) {
            return Commit();
        } else {
            return false;
        }

        RefreshEditor();
        return true;
    }

    void update() override
    {
        HidKeyboardState current{};
        if (hidGetKeyboardStates(&current, 1) == 0) { return; }

        bool changed = false;
        if (!m_keyboard_ready || current.sampling_number != m_keyboard_previous.sampling_number) {
            static constexpr struct { HidKeyboardKey key; char value; } HexKeys[] = {
                {HidKeyboardKey_D0, '0'}, {HidKeyboardKey_D1, '1'},
                {HidKeyboardKey_D2, '2'}, {HidKeyboardKey_D3, '3'},
                {HidKeyboardKey_D4, '4'}, {HidKeyboardKey_D5, '5'},
                {HidKeyboardKey_D6, '6'}, {HidKeyboardKey_D7, '7'},
                {HidKeyboardKey_D8, '8'}, {HidKeyboardKey_D9, '9'},
                {HidKeyboardKey_A, 'A'}, {HidKeyboardKey_B, 'B'},
                {HidKeyboardKey_C, 'C'}, {HidKeyboardKey_D, 'D'},
                {HidKeyboardKey_E, 'E'}, {HidKeyboardKey_F, 'F'},
            };
            for (const auto &entry : HexKeys) {
                if (hidKeyboardStateGetKey(&current, entry.key) &&
                    (!m_keyboard_ready || !hidKeyboardStateGetKey(&m_keyboard_previous, entry.key))) {
                    AppendHex(entry.value);
                    changed = true;
                }
            }
            if (hidKeyboardStateGetKey(&current, HidKeyboardKey_Backspace) &&
                (!m_keyboard_ready || !hidKeyboardStateGetKey(&m_keyboard_previous, HidKeyboardKey_Backspace))) {
                EraseHex();
                changed = true;
            }
            if (hidKeyboardStateGetKey(&current, HidKeyboardKey_Return) &&
                (!m_keyboard_ready || !hidKeyboardStateGetKey(&m_keyboard_previous, HidKeyboardKey_Return))) {
                m_keyboard_commit = true;
            }
        }
        m_keyboard_previous = current;
        m_keyboard_ready = true;
        if (changed) { RefreshEditor(); }
    }

private:
    static constexpr char Hex[] = "0123456789ABCDEF";

    std::string DisplayValue() const
    {
        std::string display = m_value;
        display.append(16 - display.size(), '_');
        for (size_t pos = 12; pos > 0; pos -= 4) { display.insert(pos, " "); }
        return display;
    }

    std::string KeypadRow(size_t row) const
    {
        std::string out;
        const size_t first = row * 8;
        for (size_t i = first; i < first + 8; ++i) {
            if (!out.empty()) { out += "  "; }
            if (i == m_key) { out += '['; }
            else { out += ' '; }
            out += Hex[i];
            if (i == m_key) { out += ']'; }
            else { out += ' '; }
        }
        return out;
    }

    void SetMessage(const std::string &message)
    {
        if (m_result != nullptr) { m_result->setText(message); }
    }

    void AppendHex(char value)
    {
        if (m_replace_on_type) {
            m_value.clear();
            m_replace_on_type = false;
        }
        if (m_value.size() >= 16) {
            SetMessage("16 digits maximum");
            return;
        }
        m_value.push_back(value);
    }

    void EraseHex()
    {
        m_replace_on_type = false;
        if (!m_value.empty()) { m_value.pop_back(); }
    }

    void ClearHex()
    {
        m_value.clear();
        m_replace_on_type = false;
    }

    bool Commit()
    {
        if (!IsHexNetworkId(m_value)) {
            SetMessage(m_value.size() == 16 ? "ID cannot be all zero"
                                            : "Enter exactly 16 digits");
            return true;
        }
        SaveAndSelectNetwork(m_value);
        tsl::goBack();
        return true;
    }

    void RefreshEditor()
    {
        m_id->setValue(DisplayValue());
        m_key_rows[0]->setText(KeypadRow(0));
        m_key_rows[1]->setText(KeypadRow(1));
        SetMessage("+: save   X: erase   Y: clear");
    }

    std::string m_value;
    size_t m_key = 0;
    bool m_replace_on_type = true;
    bool m_keyboard_ready = false;
    bool m_keyboard_commit = false;
    HidKeyboardState m_keyboard_previous{};
    tsl::elm::ListItem *m_id = nullptr;
    tsl::elm::CategoryHeader *m_key_rows[2] = {};
    tsl::elm::CategoryHeader *m_result = nullptr;
};

class MainGui final : public tsl::Gui {
public:
    tsl::elm::Element *createUI() override
    {
        auto *frame = new tsl::elm::OverlayFrame("sys-zerotier", APP_VERSION);
        auto *list = new tsl::elm::List();

        list->addItem(new tsl::elm::CategoryHeader("Connection"));
        m_status = new tsl::elm::ListItem("Status", "Starting...");
        list->addItem(m_status);
        m_address = new tsl::elm::ListItem("Managed IP", "Not assigned", true);
        list->addItem(m_address);
        m_active = new tsl::elm::ListItem("Active network", "None", true);
        list->addItem(m_active);

        auto *enter = new tsl::elm::ListItem("Enter network ID");
        enter->setClickListener([](u64 keys) {
            if (!(keys & KEY_A)) { return false; }
            tsl::changeTo<NetworkEditorGui>();
            return true;
        });
        list->addItem(enter);

        const std::string selected = SelectedNetwork();
        const std::vector<std::string> sections = ult::parseSectionsFromIni(NetworksPath);
        bool have_saved = false;
        for (const std::string &section : sections) {
            if (section == "sys-zerotier") { continue; }
            const std::string nwid =
                ult::parseValueFromIniSection(NetworksPath, section, "nwid");
            if (!IsHexNetworkId(nwid)) { continue; }
            if (!have_saved) {
                list->addItem(new tsl::elm::CategoryHeader("Saved networks"));
                have_saved = true;
            }
            auto *item = new tsl::elm::ListItem(
                section, section == selected ? "Selected" : UpperHex(nwid), true);
            item->setClickListener([this, section](u64 keys) {
                if (!(keys & KEY_A)) { return false; }
                SelectNetwork(section);
                m_status->setValue("Switching...");
                return true;
            });
            list->addItem(item);
        }

        list->addItem(new tsl::elm::CategoryHeader("Services (next reboot)"));
        const bool module_enabled = FileExists(BootFlag) || !FileExists(DisabledBootFlag);
        auto *module = new tsl::elm::ToggleListItem("sys-zerotier", module_enabled);
        module->setStateChangedListener([](bool state) { SetBootEnabled(state); });
        list->addItem(module);

        auto *bsd = new tsl::elm::ToggleListItem(
            "BSD LAN bridge", ConfigSwitch("bsd_mitm", true));
        bsd->setStateChangedListener([](bool state) {
            ult::setIniFileValue(ConfigPath, "sys-zerotier", "bsd_mitm", state ? "1" : "0");
        });
        list->addItem(bsd);

        auto *nifm = new tsl::elm::ToggleListItem(
            "NIFM IP bridge", ConfigSwitch("nifm_mitm", true));
        nifm->setStateChangedListener([](bool state) {
            ult::setIniFileValue(ConfigPath, "sys-zerotier", "nifm_mitm", state ? "1" : "0");
        });
        list->addItem(nifm);

        auto *debug = new tsl::elm::ToggleListItem(
            "Detailed diagnostics", ConfigSwitch("debug_logging", false));
        debug->setStateChangedListener([](bool state) {
            ult::setIniFileValue(ConfigPath, "sys-zerotier", "debug_logging", state ? "1" : "0");
        });
        list->addItem(debug);

        frame->setContent(list);
        RefreshStatus();
        return frame;
    }

    void update() override
    {
        const u64 now = armGetSystemTick();
        if (m_last_refresh == 0 || armTicksToNs(now - m_last_refresh) >= 1000000000ULL) {
            m_last_refresh = now;
            RefreshStatus();
        }
    }

    bool handleInput(u64 keys_down, u64, const HidTouchState &,
                     HidAnalogStickState, HidAnalogStickState) override
    {
        if (!(keys_down & KEY_B)) { return false; }

        /* This is the root page. Hiding it leaves this overlay process alive,
         * so Ultrahand's launch recall opens the same page again. Hand control
         * explicitly back to the launcher instead. */
        tsl::setNextOverlay(ult::OVERLAY_PATH + "ovlmenu.ovl");
        tsl::Overlay::get()->close();
        return true;
    }

private:
    void RefreshStatus()
    {
        if (m_status == nullptr) { return; }
        const std::string online = StatusValue("online");
        const std::string netstatus = StatusValue("netstatus");
        const std::string address = StatusValue("address");
        const std::string network = StatusValue("network");
        m_status->setValue(online == "yes" ? (netstatus.empty() ? "Online" : netstatus)
                                            : "Connecting");
        m_address->setValue(address.empty() || address.rfind("0.0.0.0", 0) == 0
                                ? "Not assigned" : address);
        m_active->setValue(IsHexNetworkId(network) ? UpperHex(network) : "None");
    }

    u64 m_last_refresh = 0;
    tsl::elm::ListItem *m_status = nullptr;
    tsl::elm::ListItem *m_address = nullptr;
    tsl::elm::ListItem *m_active = nullptr;
};

class Overlay final : public tsl::Overlay {
public:
    void initServices() override
    {
        ult::createDirectory(ConfigDir);
        /* A normal release already ships boot2.flag. This also makes a manual
         * first install of the overlay self-healing, while preserving the
         * explicit .disabled marker written by the toggle. */
        if (!FileExists(BootFlag) && !FileExists(DisabledBootFlag)) {
            SetBootEnabled(true);
        }
    }
    void exitServices() override {}
    std::unique_ptr<tsl::Gui> loadInitialGui() override { return initially<MainGui>(); }
};

}  // namespace

int main(int argc, char **argv)
{
    return tsl::loop<Overlay, tsl::impl::LaunchFlags::CloseOnExit>(argc, argv);
}
