// Copyright 2024 The Kyua Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
// * Neither the name of Google Inc. nor the names of its contributors
//   may be used to endorse or promote products derived from this software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "engine/rr/rr.hpp"

#include "engine/rr/rr_all.hpp"

namespace rr = engine::rr;


/// List of registered execution environments, except default host one.
///
/// Use register_execenv() to add an entry to this global list.
static std::vector< std::shared_ptr< rr::interface > > _resolvers = {
    std::shared_ptr< rr::interface >(new rr::rr_all())
};


void
rr::register_resolver(const std::shared_ptr< interface > resolver)
{
    _resolvers.push_back(resolver);
}


const std::vector< std::shared_ptr< rr::interface > >
rr::resolvers()
{
    return _resolvers;
}


int
rr::run(const std::vector< std::string >& resolver_names,
        cmdline::ui* ui,
        const cmdline::parsed_cmdline& cmdline,
        const config::tree& user_config)
{
    for (auto rname : resolver_names) {
        std::shared_ptr< rr::interface > resolver = nullptr;
        for (auto r : rr::resolvers())
            if (r->name() == rname) {
                resolver = r;
                break;
            }

        if (resolver == nullptr) {
            ui->out(F("Unknown requirement resolver: %s") % rname);
            return EXIT_FAILURE;
        }

        if (resolver->exec(ui, cmdline, user_config) != EXIT_SUCCESS)
            // suppress the actual code -- main limits possible exit codes
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
