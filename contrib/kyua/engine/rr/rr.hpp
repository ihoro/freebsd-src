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

/// \file engine/rr/rr.hpp
/// Requirement resolver subsystem interface.

#if !defined(ENGINE_RR_RR_HPP)
#define ENGINE_RR_RR_HPP

#include <string>
#include <vector>

#include "utils/cmdline/parser.ipp"
#include "utils/cmdline/ui.hpp"
#include "utils/config/tree.ipp"

namespace cmdline = utils::cmdline;
namespace config = utils::config;


namespace engine {
namespace rr {


/// Abstract interface of a requirement resolver.
class interface {
public:
    /// Constructor.
    interface() {}

    /// Destructor.
    virtual ~interface() {}

    /// Returns name of the resolver.
    virtual const std::string& name() const = 0;

    /// Returns short description of the resolver.
    virtual const std::string& description() const = 0;

    /// Runs the requirement resolver.
    ///
    /// \param ui Object to interact with the I/O of the program.
    /// \param cmdline Representation of the command line to the subcommand.
    /// \param user_config The runtime configuration of the program.
    ///
    /// \return 0 to indicate success.
    virtual int exec(cmdline::ui* ui,
                     const cmdline::parsed_cmdline& cmdline,
                     const config::tree& user_config) const = 0;
};


/// Registers a requirement resolver.
///
/// \param resolver A requirement resolver.
void register_resolver(const std::shared_ptr< interface > resolver);


/// Returns the list of registered requirement resolvers.
///
/// \return A vector of pointers to requirement resolvers.
const std::vector< std::shared_ptr< interface > > resolvers();


/// Run named resolvers.
///
/// \param resolver_names Names of resolvers to run.
/// \param ui Object to interact with the I/O of the program.
/// \param cmdline Representation of the command line to the subcommand.
/// \param user_config The runtime configuration of the program.
///
/// \return 0 to indicate success.
int run(const std::vector< std::string >& resolver_names,
        cmdline::ui* ui,
        const cmdline::parsed_cmdline& cmdline,
        const config::tree& user_config);


}  // namespace rr
}  // namespace engine

#endif  // !defined(ENGINE_RR_RR_HPP)
