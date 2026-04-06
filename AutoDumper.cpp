// ============================================================================
// ZeusMod Auto Dumper
// Automatically finds all offsets and signatures after game updates
//
// Methods:
//   1. Parse UE4SS CXXHeaderDump for class field offsets
//   2. Load PDB symbols for function offsets
//   3. Scan binary for AOB signatures
//   4. Output offsets.json used by the trainer at runtime
//
// Usage: AutoDumper.exe [--game-path "C:\...\Icarus"] [--dump-path "C:\...\CXXHeaderDump"]
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
#include <filesystem>

#pragma comment(lib, "dbghelp.lib")

namespace fs = std::filesystem;

// ============================================================================
// Config
// ============================================================================

struct GameConfig {
    std::string gamePath;
    std::string dumpPath;
    std::string exeName = "Icarus-Win64-Shipping.exe";
    std::string pdbName = "Icarus-Win64-Shipping.pdb";
};

// ============================================================================
// Offset definitions - what we need to find
// ============================================================================

struct FieldQuery {
    const char* className;
    const char* fieldName;
    const char* jsonKey;
};

static const FieldQuery FIELD_QUERIES[] = {
    // UActorState
    {"UActorState", "Health", "health"},
    {"UActorState", "MaxHealth", "maxHealth"},
    {"UActorState", "Armor", "armor"},
    {"UActorState", "MaxArmor", "maxArmor"},
    {"UActorState", "Shelter", "shelter"},
    {"UActorState", "CurrentAliveState", "aliveState"},

    // UCharacterState
    {"UCharacterState", "Stamina", "stamina"},
    {"UCharacterState", "MaxStamina", "maxStamina"},
    {"UCharacterState", "TotalExperience", "totalXP"},
    {"UCharacterState", "Level", "level"},

    // USurvivalCharacterState
    {"USurvivalCharacterState", "OxygenLevel", "oxygen"},
    {"USurvivalCharacterState", "WaterLevel", "water"},
    {"USurvivalCharacterState", "FoodLevel", "food"},
    {"USurvivalCharacterState", "MaxOxygen", "maxOxygen"},
    {"USurvivalCharacterState", "MaxWater", "maxWater"},
    {"USurvivalCharacterState", "MaxFood", "maxFood"},

    // AIcarusCharacter
    {"AIcarusCharacter", "ActorState", "charActorState"},
    {"AIcarusCharacter", "StatContainer", "charStatContainer"},

    // UWorld
    {"UWorld", "GameInstance", "worldGameInstance"},
    {"UWorld", "GameState", "worldGameState"},

    // UGameInstance
    {"UGameInstance", "LocalPlayers", "giLocalPlayers"},

    // UPlayer
    {"UPlayer", "PlayerController", "playerController"},

    // AController
    {"AController", "Character", "ctrlCharacter"},

    // AIcarusGameStateSurvival
    {"AIcarusGameStateSurvival", "TimeOfDay", "gsTimeOfDay"},

    // AActor
    {"AActor", "CustomTimeDilation", "actorTimeDilation"},

    // ACharacter
    {"ACharacter", "CharacterMovement", "charMovement"},

    // UCharacterMovementComponent
    {"UCharacterMovementComponent", "MaxWalkSpeed", "maxWalkSpeed"},
    {"UCharacterMovementComponent", "MovementMode", "movementMode"},
};

static const int NUM_FIELDS = sizeof(FIELD_QUERIES) / sizeof(FIELD_QUERIES[0]);

struct FuncQuery {
    const char* className;
    const char* funcName;
    const char* jsonKey;
};

static const FuncQuery FUNC_QUERIES[] = {
    {"UCraftingFunctionLibrary", "GetScaledRecipeInputCount", "fnScaledInputCount"},
    {"UCraftingFunctionLibrary", "GetScaledRecipeResourceItemCount", "fnScaledResourceCount"},
    {"UInventory", "FindItemCountByType", "fnFindItemCount"},
    {"UInventoryComponent", "GetTotalWeight", "fnGetTotalWeight"},
    {"UInventory", "ConsumeItem", "fnConsumeItem"},
    {"UActorState", "SetHealth", "fnSetHealth"},
    {"UCharacterState", "SetStamina", "fnSetStamina"},
};

static const int NUM_FUNCS = sizeof(FUNC_QUERIES) / sizeof(FUNC_QUERIES[0]);

// ============================================================================
// 1. Parse UE4SS CXXHeaderDump
// ============================================================================

std::map<std::string, uint64_t> parseUE4SSHeaders(const std::string& dumpDir) {
    std::map<std::string, uint64_t> offsets;

    // Files to parse
    std::vector<std::string> files = {"Icarus.hpp", "Engine.hpp", "CoreUObject.hpp"};

    for (auto& filename : files) {
        std::string filepath = dumpDir + "/" + filename;
        std::ifstream file(filepath);
        if (!file.is_open()) {
            printf("[WARN] Cannot open %s\n", filepath.c_str());
            continue;
        }

        std::string line;
        std::string currentClass;

        while (std::getline(file, line)) {
            // Detect class definition: "class UActorState : public ..."
            if (line.find("class ") == 0 || line.find("class ") == 1) {
                size_t nameStart = line.find("class ") + 6;
                size_t nameEnd = line.find_first_of(" :", nameStart);
                if (nameEnd != std::string::npos) {
                    currentClass = line.substr(nameStart, nameEnd - nameStart);
                }
            }

            // Detect struct definition
            if (line.find("struct ") == 0) {
                size_t nameStart = 7;
                size_t nameEnd = line.find_first_of(" :", nameStart);
                if (nameEnd != std::string::npos) {
                    currentClass = line.substr(nameStart, nameEnd - nameStart);
                }
            }

            // Detect field with offset: "    type name;    // 0xXXXX (size: 0xY)"
            if (!currentClass.empty() && line.find("// 0x") != std::string::npos) {
                // Extract field name
                size_t semicolon = line.find(';');
                if (semicolon == std::string::npos) continue;

                std::string beforeSemicolon = line.substr(0, semicolon);
                // Field name is the last word before semicolon
                size_t lastSpace = beforeSemicolon.find_last_of(" *&");
                if (lastSpace == std::string::npos) continue;
                std::string fieldName = beforeSemicolon.substr(lastSpace + 1);

                // Extract offset
                size_t offsetPos = line.find("// 0x");
                if (offsetPos == std::string::npos) continue;
                std::string offsetStr = line.substr(offsetPos + 5);
                size_t offsetEnd = offsetStr.find_first_of(" (");
                if (offsetEnd != std::string::npos) offsetStr = offsetStr.substr(0, offsetEnd);

                uint64_t offset = strtoull(offsetStr.c_str(), nullptr, 16);

                // Check if this matches any query
                for (int i = 0; i < NUM_FIELDS; i++) {
                    if (currentClass == FIELD_QUERIES[i].className &&
                        fieldName == FIELD_QUERIES[i].fieldName) {
                        offsets[FIELD_QUERIES[i].jsonKey] = offset;
                        printf("  [SDK] %s::%s = 0x%llX\n",
                            FIELD_QUERIES[i].className,
                            FIELD_QUERIES[i].fieldName,
                            (unsigned long long)offset);
                    }
                }
            }

            // Reset class on closing brace
            if (line.find("};") == 0) {
                currentClass.clear();
            }
        }
    }

    return offsets;
}

// ============================================================================
// 2. Find function offsets via PDB symbols
// ============================================================================

struct SymbolContext {
    std::map<std::string, uint64_t>* results;
};

BOOL CALLBACK EnumSymbolsCallback(PSYMBOL_INFO pSymInfo, ULONG, PVOID UserContext) {
    auto* ctx = static_cast<SymbolContext*>(UserContext);
    std::string name(pSymInfo->Name);

    for (int i = 0; i < NUM_FUNCS; i++) {
        std::string target = std::string(FUNC_QUERIES[i].className) + "::" + FUNC_QUERIES[i].funcName;

        // Check for exact match (not exec variant)
        if (name.find(target) != std::string::npos &&
            name.find("exec") == std::string::npos &&
            name.find("Z_Construct") == std::string::npos) {

            // Check it's not already found (prefer shorter/exact match)
            if (ctx->results->find(FUNC_QUERIES[i].jsonKey) == ctx->results->end()) {
                uint64_t offset = pSymInfo->Address - 0x10000000;
                (*ctx->results)[FUNC_QUERIES[i].jsonKey] = offset;
                printf("  [PDB] %s = 0x%llX\n", target.c_str(), (unsigned long long)offset);
            }
        }
    }
    return TRUE;
}

std::map<std::string, uint64_t> findFunctionOffsets(const std::string& exePath) {
    std::map<std::string, uint64_t> offsets;

    // Load the exe as a data file for symbol enumeration
    HANDLE hProcess = GetCurrentProcess();
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);

    if (!SymInitialize(hProcess, nullptr, FALSE)) {
        printf("[ERROR] SymInitialize failed: %lu\n", GetLastError());
        return offsets;
    }

    DWORD64 baseAddr = SymLoadModuleEx(hProcess, nullptr, exePath.c_str(), nullptr,
        0x10000000, 0, nullptr, 0);

    if (!baseAddr) {
        printf("[ERROR] SymLoadModuleEx failed: %lu\n", GetLastError());
        printf("[HINT] Make sure the .pdb file is next to the .exe\n");
        SymCleanup(hProcess);
        return offsets;
    }

    printf("  [PDB] Module loaded at base 0x%llX\n", (unsigned long long)baseAddr);

    SymbolContext ctx = { &offsets };
    SymEnumSymbols(hProcess, baseAddr, "*", EnumSymbolsCallback, &ctx);

    // Offsets are already relative from SymEnumSymbols
    // pSymInfo->Address is virtual, ModBase is our fake base
    // The offset = Address - ModBase, which is what we stored

    SymUnloadModule64(hProcess, baseAddr);
    SymCleanup(hProcess);

    return offsets;
}

// ============================================================================
// 3. AOB signature verification
// ============================================================================

struct AOBQuery {
    const char* name;
    const char* pattern;
    const char* jsonKey;
};

static const AOBQuery AOB_QUERIES[] = {
    {"GWorld", "48 8B 1D ?? ?? ?? ?? 48 85 DB 74", "aobGWorld"},
    {"SetHealth write", "79 04 33 ?? EB 09 41 8B ?? 41 3B ?? 0F 4C ?? 89 ?? D8 01 00 00", "aobSetHealth"},
    {"ConsumeItem sub", "48 3B F9 75 F2 44 29 66 04 E9", "aobConsumeItem"},
};

static const int NUM_AOBS = sizeof(AOB_QUERIES) / sizeof(AOB_QUERIES[0]);

std::map<std::string, std::string> verifyAOBs(const std::string& exePath) {
    std::map<std::string, std::string> results;

    // Read .text section
    FILE* f = fopen(exePath.c_str(), "rb");
    if (!f) return results;

    uint8_t hdr[4096];
    fread(hdr, 1, sizeof(hdr), f);

    uint32_t peOff = *(uint32_t*)(hdr + 0x3C);
    uint16_t numSec = *(uint16_t*)(hdr + peOff + 6);
    uint16_t optSize = *(uint16_t*)(hdr + peOff + 0x14);
    uint32_t secOff = peOff + 0x18 + optSize;

    for (int i = 0; i < numSec; i++) {
        uint8_t* s = hdr + secOff + i * 40;
        if (memcmp(s, ".text", 5) == 0) {
            uint32_t rawSize = *(uint32_t*)(s + 16);
            uint32_t rawOff = *(uint32_t*)(s + 20);

            std::vector<uint8_t> text(rawSize);
            fseek(f, rawOff, SEEK_SET);
            fread(text.data(), 1, rawSize, f);
            fclose(f);

            for (int q = 0; q < NUM_AOBS; q++) {
                // Parse pattern
                std::vector<uint8_t> bytes;
                std::vector<bool> mask;
                const char* p = AOB_QUERIES[q].pattern;
                while (*p) {
                    if (*p == ' ') { p++; continue; }
                    if (*p == '?') {
                        bytes.push_back(0); mask.push_back(false);
                        p++; if (*p == '?') p++;
                    } else {
                        char h[3] = {p[0], p[1], 0};
                        bytes.push_back((uint8_t)strtoul(h, 0, 16));
                        mask.push_back(true);
                        p += 2;
                    }
                }

                // Scan
                bool found = false;
                for (size_t j = 0; j + bytes.size() <= rawSize; j++) {
                    bool ok = true;
                    for (size_t k = 0; k < bytes.size(); k++) {
                        if (mask[k] && text[j + k] != bytes[k]) { ok = false; break; }
                    }
                    if (ok) {
                        results[AOB_QUERIES[q].jsonKey] = AOB_QUERIES[q].pattern;
                        printf("  [AOB] %s: FOUND at +0x%llX\n", AOB_QUERIES[q].name, (unsigned long long)j);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    printf("  [AOB] %s: NOT FOUND - pattern may need updating\n", AOB_QUERIES[q].name);
                    results[AOB_QUERIES[q].jsonKey] = "BROKEN";
                }
            }
            return results;
        }
    }

    fclose(f);
    return results;
}

// ============================================================================
// 4. Output JSON
// ============================================================================

void writeOffsetsJson(const std::string& outputPath,
    const std::map<std::string, uint64_t>& sdkOffsets,
    const std::map<std::string, uint64_t>& funcOffsets,
    const std::map<std::string, std::string>& aobResults) {

    std::ofstream out(outputPath);
    out << "{\n";
    out << "  \"version\": \"auto-generated\",\n";
    out << "  \"game\": \"Icarus\",\n";
    out << "  \"timestamp\": \"" << __DATE__ << " " << __TIME__ << "\",\n";

    // SDK offsets (hex strings for readability)
    out << "\n  \"sdk\": {\n";
    int i = 0;
    for (auto& [key, val] : sdkOffsets) {
        char hex[32];
        sprintf(hex, "\"0x%X\"", (unsigned)val);
        out << "    \"" << key << "\": " << hex;
        if (++i < (int)sdkOffsets.size()) out << ",";
        out << "\n";
    }
    out << "  },\n";

    // Function offsets (hex strings)
    out << "\n  \"functions\": {\n";
    i = 0;
    for (auto& [key, val] : funcOffsets) {
        char hex[32];
        sprintf(hex, "\"0x%X\"", (unsigned)val);
        out << "    \"" << key << "\": " << hex;
        if (++i < (int)funcOffsets.size()) out << ",";
        out << "\n";
    }
    out << "  },\n";

    // AOB signatures
    out << "\n  \"signatures\": {\n";
    i = 0;
    for (auto& [key, val] : aobResults) {
        out << "    \"" << key << "\": \"" << val << "\"";
        if (++i < (int)aobResults.size()) out << ",";
        out << "\n";
    }
    out << "  }\n";

    out << "}\n";
    out.close();

    printf("\n[DONE] Offsets written to: %s\n", outputPath.c_str());
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    printf("============================================================\n");
    printf("  ZeusMod Auto Dumper\n");
    printf("  Finds all offsets and signatures automatically\n");
    printf("============================================================\n\n");

    GameConfig cfg;
    cfg.gamePath = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Icarus\\Icarus\\Binaries\\Win64";
    cfg.dumpPath = cfg.gamePath + "\\ue4ss\\CXXHeaderDump";

    // Parse args
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--game-path") == 0 && i + 1 < argc) cfg.gamePath = argv[++i];
        if (strcmp(argv[i], "--dump-path") == 0 && i + 1 < argc) cfg.dumpPath = argv[++i];
    }

    std::string exePath = cfg.gamePath + "\\" + cfg.exeName;

    printf("[1/3] Parsing UE4SS SDK dump...\n");
    printf("  Path: %s\n", cfg.dumpPath.c_str());
    auto sdkOffsets = parseUE4SSHeaders(cfg.dumpPath);
    printf("  Found %zu SDK offsets\n\n", sdkOffsets.size());

    printf("[2/3] Loading PDB symbols...\n");
    printf("  Exe: %s\n", exePath.c_str());
    auto funcOffsets = findFunctionOffsets(exePath);
    printf("  Found %zu function offsets\n\n", funcOffsets.size());

    printf("[3/3] Verifying AOB signatures...\n");
    auto aobResults = verifyAOBs(exePath);
    printf("  Verified %zu signatures\n\n", aobResults.size());

    // Output
    std::string outputPath = "offsets.json";
    writeOffsetsJson(outputPath, sdkOffsets, funcOffsets, aobResults);

    // Summary
    printf("\n============================================================\n");
    printf("  SUMMARY\n");
    printf("============================================================\n");
    printf("  SDK offsets:  %zu / %d\n", sdkOffsets.size(), NUM_FIELDS);
    printf("  Functions:    %zu / %d\n", funcOffsets.size(), NUM_FUNCS);
    printf("  Signatures:   %zu / %d\n", aobResults.size(), NUM_AOBS);

    int broken = 0;
    for (auto& [k, v] : aobResults) if (v == "BROKEN") broken++;
    if (broken > 0) {
        printf("\n  WARNING: %d signature(s) BROKEN - need manual update!\n", broken);
    } else {
        printf("\n  All signatures valid!\n");
    }

    printf("============================================================\n");
    system("pause");
    return 0;
}
