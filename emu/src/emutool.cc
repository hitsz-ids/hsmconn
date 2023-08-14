// Copyright (C) 2021 Institute of Data Security, HIT
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "CLI/CLI.hpp"
#include "absl/strings/str_format.h"
#include "absl/strings/escaping.h"
#include "yaml-cpp/yaml.h"
#include <openssl/rand.h>

void command_genkek(CLI::App &app) {
    auto cmd = app.add_subcommand("genkek",
                                  "generate kek");

    static std::string emu_config;
    cmd->add_option("-c,--config", emu_config,
                    "HSM Emulator configure file")
        ->required();

    static std::tuple<int, int> index_range;
    cmd->add_option("-i,--index", index_range,
                    "The index range (or slot) of kek to generate")
        ->required();

    cmd->callback([&]() {
        auto origin = YAML::LoadFile(emu_config);
        if (!origin) {
            fprintf(stderr, "fail to load `%s`\n", emu_config.c_str());
            exit(EXIT_FAILURE);
        }

        YAML::Node root(origin);

        auto start = std::get<0>(index_range);
        auto end = std::get<1>(index_range);

        if (start > end) {
            fprintf(stderr, "index range invalid\n");
            exit(EXIT_FAILURE);
        }

        YAML::Node kekNode;
        for (int i = start; i <= end; i++) {
            auto k = std::to_string(i);

            unsigned char keybuf[16];
            if (1 != RAND_bytes(keybuf, 16)) {
                fprintf(stderr, "fail to generate random for kek#%d\n", i);
                exit(EXIT_FAILURE);
            }

            absl::string_view keyCipher(reinterpret_cast<const char *>(keybuf), 16);
            kekNode[k] = absl::Base64Escape(keyCipher);
        }

        root["kek"] = kekNode;

        YAML::Emitter yout;
        yout.SetIndent(2);
        yout << root;

        std::ofstream fout(emu_config);
        fout << yout.c_str();
        fout.close();
    });

}

int main(int argc, char **argv) {
    auto app_desc = absl::StrFormat("%s - An utility tool for HSM-Emulator", argv[0]);
    CLI::App app{app_desc};
    app.require_subcommand(1);

    command_genkek(app);

    CLI11_PARSE(app, argc, argv);

    return 0;
}