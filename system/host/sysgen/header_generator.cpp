// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#import "header_generator.h"

using std::map;
using std::string;

static const string add_attribute(map<string, string> attributes,
                                  const string& attribute) {
    auto ft = attributes.find(attribute);
    return (ft == attributes.end()) ? string() : ft->second;
}

bool HeaderGenerator::syscall(std::ofstream& os, const Syscall& sc) {
    constexpr uint32_t indent_spaces = 4u;

    for (const auto& name_prefix : name_prefixes_) {
        if (name_prefix.second(sc))
            continue;

        auto syscall_name = name_prefix.first + sc.name;

        os << function_prefix_;

        write_syscall_signature_line(
            os, sc, name_prefix.first, "\n", "\n" + string(indent_spaces, ' '),
            allow_pointer_wrapping_ && !sc.is_no_wrap() && !sc.is_vdso(),
            no_args_type_);

        os << " ";

        // Writes attributes after arguments.
        for (const auto& attr : sc.attributes) {
            auto a = add_attribute(attributes_, attr);
            if (!a.empty())
                os << a << " ";
        }

        if (sc.ret_spec.size() > 0)
            write_argument_annotation(os, sc.ret_spec[0]);

        os.seekp(-1, std::ios_base::end);

        os << ";\n\n";
    }

    return os.good();
}
