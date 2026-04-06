// ============================================================================
// IcarusDumper - Auto Offset & AOB Finder
// Made by CyberSnake
//
// 1. UE4SS CXXHeaderDump -> class field offsets
// 2. PDB Symbols -> function addresses
// 3. Binary .text -> AOB for every write instruction + function prologue
// ============================================================================

#include <Windows.h>
#include <DbgHelp.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <fstream>

#pragma comment(lib, "dbghelp.lib")

// ── SDK Fields to find ──
struct FQ { const char *cls, *field, *key; };
static const FQ FIELDS[] = {
    {"UActorState","Health","health"}, {"UActorState","MaxHealth","maxHealth"},
    {"UActorState","Armor","armor"}, {"UActorState","MaxArmor","maxArmor"},
    {"UActorState","Shelter","shelter"}, {"UActorState","CurrentAliveState","aliveState"},
    {"UCharacterState","Stamina","stamina"}, {"UCharacterState","MaxStamina","maxStamina"},
    {"UCharacterState","TotalExperience","totalXP"}, {"UCharacterState","Level","level"},
    {"USurvivalCharacterState","OxygenLevel","oxygen"},
    {"USurvivalCharacterState","WaterLevel","water"},
    {"USurvivalCharacterState","FoodLevel","food"},
    {"USurvivalCharacterState","MaxOxygen","maxOxygen"},
    {"USurvivalCharacterState","MaxWater","maxWater"},
    {"USurvivalCharacterState","MaxFood","maxFood"},
    {"USurvivalCharacterState","InternalTemperature","internalTemp"},
    {"USurvivalCharacterState","RadiationLevel","radiation"},
    {"AIcarusCharacter","ActorState","charActorState"},
    {"AIcarusCharacter","StatContainer","charStatContainer"},
    {"UWorld","GameInstance","worldGameInstance"},
    {"UWorld","GameState","worldGameState"},
    {"UGameInstance","LocalPlayers","giLocalPlayers"},
    {"UPlayer","PlayerController","playerController"},
    {"AController","Character","ctrlCharacter"},
    {"AIcarusGameStateSurvival","TimeOfDay","gsTimeOfDay"},
    {"AActor","CustomTimeDilation","actorTimeDilation"},
    {"ACharacter","CharacterMovement","charMovement"},
    {"UCharacterMovementComponent","MaxWalkSpeed","maxWalkSpeed"},
    {"UCharacterMovementComponent","MovementMode","movementMode"},
    {"UCharacterMovementComponent","MaxFlySpeed","maxFlySpeed"},
    {"UInventory","CurrentWeight","invCurrentWeight"},
    {"UInventory","Slots","invSlots"},
};
static constexpr int NF = sizeof(FIELDS) / sizeof(FIELDS[0]);

// ── Functions to find via PDB ──
struct FnQ { const char *cls, *func, *key; };
static const FnQ FUNCS[] = {
    {"UCraftingFunctionLibrary","GetScaledRecipeInputCount","fnScaledInputCount"},
    {"UCraftingFunctionLibrary","GetScaledRecipeResourceItemCount","fnScaledResourceCount"},
    {"UCraftingFunctionLibrary","GetStatBasedResourceCostMultiplier","fnCostMultiplier"},
    {"UInventory","FindItemCountByType","fnFindItemCount"},
    {"UInventory","ConsumeItem","fnConsumeItem"},
    {"UInventory","RemoveItem","fnRemoveItem"},
    {"UInventory","GetItemCount","fnGetItemCount"},
    {"UInventoryComponent","GetTotalWeight","fnGetTotalWeight"},
    {"UActorState","SetHealth","fnSetHealth"},
    {"UActorState","TakeDamage","fnTakeDamage"},
    {"UActorState","SetArmor","fnSetArmor"},
    {"UCharacterState","SetStamina","fnSetStamina"},
    {"UCharacterState","AddStamina","fnAddStamina"},
    {"USurvivalCharacterState","SetOxygen","fnSetOxygen"},
    {"USurvivalCharacterState","SetWater","fnSetWater"},
    {"USurvivalCharacterState","SetFood","fnSetFood"},
    {"UProcessorComponent","CanSatisfyRecipeInput","fnCanSatisfyInput"},
    {"UProcessorComponent","CanQueueItem","fnCanQueueItem"},
    {"UProcessorComponent","HasSufficientResource","fnHasSufficient"},
    {"AIcarusCharacter","TryApplyFallDamage","fnFallDamage"},
};
static constexpr int NFn = sizeof(FUNCS) / sizeof(FUNCS[0]);

// ── Known AOBs to verify ──
struct AQ { const char *name, *pat, *key; };
static const AQ AOBS[] = {
    {"GWorld", "48 8B 1D ?? ?? ?? ?? 48 85 DB 74", "aobGWorld"},
    {"SetHealth", "79 04 33 ?? EB 09 41 8B ?? 41 3B ?? 0F 4C ?? 89 ?? D8 01 00 00", "aobSetHealth"},
    {"ConsumeItem", "48 3B F9 75 F2 44 29 66 04 E9", "aobConsumeItem"},
    {"SetStamina", "85 ?? 79 04 33 ?? EB 05 3B ?? 0F 4C ?? 89 ?? 78 02 00 00", "aobSetStamina"},
    {"GNames", "48 8D 05 ?? ?? ?? ?? EB ?? 48 8D 0D ?? ?? ?? ?? E8", "aobGNames"},
};
static constexpr int NA = sizeof(AOBS) / sizeof(AOBS[0]);

// ── Global binary data ──
static std::vector<uint8_t> g_text;

// ============================================================================
// 1. Parse UE4SS Headers
// ============================================================================
std::map<std::string, uint64_t> parseHeaders(const std::string& dir) {
    std::map<std::string, uint64_t> r;
    const char* files[] = {"Icarus.hpp", "Engine.hpp", "CoreUObject.hpp"};
    for (auto fn : files) {
        std::ifstream f(dir + "/" + fn);
        if (!f) continue;
        std::string line, cls;
        while (std::getline(f, line)) {
            if (line.find("class ") == 0 || line.find("class ") == 1) {
                size_t s = line.find("class ") + 6;
                size_t e = line.find_first_of(" :", s);
                if (e != std::string::npos) cls = line.substr(s, e - s);
            }
            if (line.find("struct ") == 0) {
                size_t s = 7, e = line.find_first_of(" :", s);
                if (e != std::string::npos) cls = line.substr(s, e - s);
            }
            if (!cls.empty() && line.find("// 0x") != std::string::npos) {
                size_t sc = line.find(';');
                if (sc == std::string::npos) continue;
                size_t ls = line.substr(0, sc).find_last_of(" *&");
                if (ls == std::string::npos) continue;
                std::string fld = line.substr(0, sc).substr(ls + 1);
                size_t op = line.find("// 0x") + 5;
                std::string os = line.substr(op);
                size_t oe = os.find_first_of(" (");
                if (oe != std::string::npos) os = os.substr(0, oe);
                uint64_t off = strtoull(os.c_str(), nullptr, 16);
                for (int i = 0; i < NF; i++)
                    if (cls == FIELDS[i].cls && fld == FIELDS[i].field)
                        r[FIELDS[i].key] = off;
            }
            if (line.find("};") == 0) cls.clear();
        }
    }
    return r;
}

// ============================================================================
// 2. PDB Symbol Loading
// ============================================================================
struct SC { std::map<std::string, uint64_t>* r; };

BOOL CALLBACK SymCB(PSYMBOL_INFO si, ULONG, PVOID ctx) {
    auto* c = (SC*)ctx;
    std::string n(si->Name);
    for (int i = 0; i < NFn; i++) {
        std::string t = std::string(FUNCS[i].cls) + "::" + FUNCS[i].func;
        if (n.find(t) != std::string::npos &&
            n.find("exec") == std::string::npos &&
            n.find("Z_Construct") == std::string::npos &&
            n.find("dtor") == std::string::npos &&
            n.find("Statics") == std::string::npos &&
            n.find("NewProp") == std::string::npos) {
            if (c->r->find(FUNCS[i].key) == c->r->end())
                (*c->r)[FUNCS[i].key] = si->Address - 0x10000000;
        }
    }
    return TRUE;
}

std::map<std::string, uint64_t> loadPDB(const std::string& exe) {
    std::map<std::string, uint64_t> r;
    HANDLE h = GetCurrentProcess();
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
    if (!SymInitialize(h, nullptr, FALSE)) return r;
    DWORD64 b = SymLoadModuleEx(h, nullptr, exe.c_str(), nullptr, 0x10000000, 0, nullptr, 0);
    if (!b) { SymCleanup(h); return r; }
    SC ctx = {&r};
    SymEnumSymbols(h, b, "*", SymCB, &ctx);
    SymUnloadModule64(h, b);
    SymCleanup(h);
    return r;
}

// ============================================================================
// 3. Binary Scanner
// ============================================================================
bool loadText(const std::string& exe) {
    FILE* f = fopen(exe.c_str(), "rb");
    if (!f) return false;
    uint8_t hdr[4096];
    fread(hdr, 1, 4096, f);
    uint32_t pe = *(uint32_t*)(hdr + 0x3C);
    uint16_t ns = *(uint16_t*)(hdr + pe + 6);
    uint16_t os = *(uint16_t*)(hdr + pe + 0x14);
    uint32_t so = pe + 0x18 + os;
    for (int i = 0; i < ns; i++) {
        uint8_t* s = hdr + so + i * 40;
        if (memcmp(s, ".text", 5) == 0) {
            uint32_t rsz = *(uint32_t*)(s + 16);
            uint32_t ro = *(uint32_t*)(s + 20);
            g_text.resize(rsz);
            fseek(f, ro, SEEK_SET);
            fread(g_text.data(), 1, rsz, f);
            fclose(f);
            return true;
        }
    }
    fclose(f);
    return false;
}

int64_t scanAOB(const char* pat) {
    std::vector<uint8_t> by;
    std::vector<bool> mk;
    const char* p = pat;
    while (*p) {
        if (*p == ' ') { p++; continue; }
        if (*p == '?') {
            by.push_back(0); mk.push_back(false);
            p++; if (*p == '?') p++;
        } else {
            char h[3] = {p[0], p[1], 0};
            by.push_back((uint8_t)strtoul(h, nullptr, 16));
            mk.push_back(true);
            p += 2;
        }
    }
    for (size_t i = 0; i + by.size() <= g_text.size(); i++) {
        bool ok = true;
        for (size_t j = 0; j < by.size(); j++)
            if (mk[j] && g_text[i + j] != by[j]) { ok = false; break; }
        if (ok) return (int64_t)i;
    }
    return -1;
}

// Try to make a unique AOB from bytes at offset
std::string makeUniqueAOB(size_t offset, int minLen, int maxLen) {
    for (int len = minLen; len <= maxLen; len++) {
        if (offset + len > g_text.size()) break;
        int matches = 0;
        for (size_t j = 0; j + len <= g_text.size() && matches < 2; j++) {
            bool ok = true;
            for (int k = 0; k < len; k++)
                if (g_text[offset + k] != g_text[j + k]) { ok = false; break; }
            if (ok) matches++;
        }
        if (matches == 1) {
            std::string aob;
            for (int k = 0; k < len; k++) {
                char h[4];
                sprintf(h, "%02X ", g_text[offset + k]);
                aob += h;
            }
            if (!aob.empty()) aob.pop_back();
            return aob;
        }
    }
    return "";
}

// Find write instruction AOB for a field offset
// Searches for: mov [reg+disp32], reg32 = 89 ModRM disp32
std::string findWriteAOB(uint64_t fieldOff) {
    if (fieldOff > 0xFFFF) return "";
    uint8_t lo = fieldOff & 0xFF;
    uint8_t hi = (fieldOff >> 8) & 0xFF;

    for (size_t i = 0; i + 6 < g_text.size(); i++) {
        // 89 XX lo hi 00 00 = mov [reg+offset], r32
        if (g_text[i] == 0x89 && g_text[i + 2] == lo && g_text[i + 3] == hi &&
            g_text[i + 4] == 0x00 && g_text[i + 5] == 0x00) {
            uint8_t modrm = g_text[i + 1];
            if (((modrm >> 6) & 3) != 2 || (modrm & 7) == 4) continue;

            // Build unique AOB starting 8 bytes before
            size_t start = (i >= 8) ? i - 8 : 0;
            std::string aob = makeUniqueAOB(start, 14, 24);
            if (!aob.empty()) return aob;
        }
    }

    // Also try float write: F3 0F 11 XX lo hi 00 00 = movss [reg+offset], xmm
    for (size_t i = 0; i + 8 < g_text.size(); i++) {
        if (g_text[i] == 0xF3 && g_text[i + 1] == 0x0F && g_text[i + 2] == 0x11 &&
            g_text[i + 4] == lo && g_text[i + 5] == hi &&
            g_text[i + 6] == 0x00 && g_text[i + 7] == 0x00) {
            uint8_t modrm = g_text[i + 3];
            if (((modrm >> 6) & 3) != 2 || (modrm & 7) == 4) continue;

            size_t start = (i >= 6) ? i - 6 : 0;
            std::string aob = makeUniqueAOB(start, 14, 24);
            if (!aob.empty()) return aob;
        }
    }
    return "";
}

// Find function prologue AOB
std::string findFuncAOB(uint64_t funcOff) {
    if (funcOff >= g_text.size() || funcOff == 0) return "";
    return makeUniqueAOB(funcOff, 12, 24);
}

// ============================================================================
// JSON Output
// ============================================================================
void writeJSON(const std::string& path,
    const std::map<std::string, uint64_t>& sdk,
    const std::map<std::string, uint64_t>& funcs,
    const std::map<std::string, std::string>& sigs,
    const std::map<std::string, std::string>& wAOBs,
    const std::map<std::string, std::string>& fAOBs) {

    std::ofstream o(path);
    o << "{\n";
    o << "  \"game\": \"Icarus\",\n";
    o << "  \"timestamp\": \"" << __DATE__ << " " << __TIME__ << "\",\n";

    // SDK
    o << "\n  \"sdk\": {\n";
    int i = 0;
    for (auto& [k, v] : sdk) {
        char h[32]; sprintf(h, "\"0x%X\"", (unsigned)v);
        o << "    \"" << k << "\": " << h;
        if (++i < (int)sdk.size()) o << ",";
        o << "\n";
    }
    o << "  },\n";

    // Functions
    o << "\n  \"functions\": {\n";
    i = 0;
    for (auto& [k, v] : funcs) {
        char h[32]; sprintf(h, "\"0x%X\"", (unsigned)v);
        o << "    \"" << k << "\": " << h;
        if (++i < (int)funcs.size()) o << ",";
        o << "\n";
    }
    o << "  },\n";

    // Known signatures
    o << "\n  \"signatures\": {\n";
    i = 0;
    for (auto& [k, v] : sigs) {
        o << "    \"" << k << "\": \"" << v << "\"";
        if (++i < (int)sigs.size()) o << ",";
        o << "\n";
    }
    o << "  },\n";

    // Write AOBs
    o << "\n  \"writeAOBs\": {\n";
    i = 0;
    for (auto& [k, v] : wAOBs) {
        o << "    \"" << k << "\": \"" << v << "\"";
        if (++i < (int)wAOBs.size()) o << ",";
        o << "\n";
    }
    o << "  },\n";

    // Function AOBs
    o << "\n  \"functionAOBs\": {\n";
    i = 0;
    for (auto& [k, v] : fAOBs) {
        o << "    \"" << k << "\": \"" << v << "\"";
        if (++i < (int)fAOBs.size()) o << ",";
        o << "\n";
    }
    o << "  }\n";
    o << "}\n";
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    printf("============================================================\n");
    printf("  IcarusDumper - Auto Offset & AOB Finder\n");
    printf("  Made by CyberSnake\n");
    printf("============================================================\n\n");

    std::string gp = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Icarus\\Icarus\\Binaries\\Win64";
    std::string dp = gp + "\\ue4ss\\CXXHeaderDump";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--game-path") && i + 1 < argc) gp = argv[++i];
        if (!strcmp(argv[i], "--dump-path") && i + 1 < argc) dp = argv[++i];
    }

    std::string exe = gp + "\\Icarus-Win64-Shipping.exe";

    // Step 1: SDK
    printf("[1/4] Parsing UE4SS headers...\n");
    auto sdk = parseHeaders(dp);
    printf("  Found %zu/%d offsets\n", sdk.size(), NF);
    for (auto& [k, v] : sdk)
        printf("  %-28s = 0x%X\n", k.c_str(), (unsigned)v);

    // Step 2: PDB
    printf("\n[2/4] Loading PDB symbols...\n");
    auto funcs = loadPDB(exe);
    printf("  Found %zu/%d functions\n", funcs.size(), NFn);
    for (auto& [k, v] : funcs)
        printf("  %-28s = 0x%X\n", k.c_str(), (unsigned)v);

    // Step 3: Binary
    printf("\n[3/4] Verifying known AOBs...\n");
    if (!loadText(exe)) {
        printf("  ERROR: Cannot load binary\n");
        system("pause");
        return 1;
    }
    printf("  .text: %.1f MB\n", g_text.size() / 1048576.0);

    std::map<std::string, std::string> sigs;
    for (int q = 0; q < NA; q++) {
        int64_t pos = scanAOB(AOBS[q].pat);
        sigs[AOBS[q].key] = (pos >= 0) ? AOBS[q].pat : "BROKEN";
        printf("  %-20s %s", AOBS[q].name, pos >= 0 ? "OK" : "BROKEN");
        if (pos >= 0) printf(" (at +0x%llX)", (unsigned long long)pos);
        printf("\n");
    }

    // Step 4: Generate AOBs
    printf("\n[4/4] Generating AOBs...\n");

    printf("\n  Write instruction AOBs:\n");
    std::map<std::string, std::string> wAOBs;
    for (auto& [k, off] : sdk) {
        std::string a = findWriteAOB(off);
        if (!a.empty()) {
            wAOBs[k] = a;
            printf("    %-25s %s\n", k.c_str(), a.c_str());
        }
    }

    printf("\n  Function prologue AOBs:\n");
    std::map<std::string, std::string> fAOBs;
    for (auto& [k, off] : funcs) {
        std::string a = findFuncAOB(off);
        if (!a.empty()) {
            fAOBs[k] = a;
            printf("    %-25s %.55s%s\n", k.c_str(), a.c_str(), a.size() > 55 ? "..." : "");
        }
    }

    // Output
    writeJSON("offsets.json", sdk, funcs, sigs, wAOBs, fAOBs);

    // Summary
    printf("\n============================================================\n");
    printf("  SUMMARY\n");
    printf("============================================================\n");
    printf("  SDK offsets:     %zu / %d\n", sdk.size(), NF);
    printf("  Functions:       %zu / %d\n", funcs.size(), NFn);
    printf("  Known sigs:      %zu / %d\n", sigs.size(), NA);
    printf("  Write AOBs:      %zu generated\n", wAOBs.size());
    printf("  Function AOBs:   %zu generated\n", fAOBs.size());

    int broken = 0;
    for (auto& [k, v] : sigs) if (v == "BROKEN") broken++;
    printf("  %s\n", broken ? "WARNING: Some signatures BROKEN!" : "All signatures valid!");
    printf("============================================================\n");
    printf("\n  Output: offsets.json\n\n");
    system("pause");
    return 0;
}
