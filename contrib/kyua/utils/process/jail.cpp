// Copyright (c) 2023 Igor Ostapenko <pm@igoro.pro>
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

#include "utils/process/jail.hpp"

extern "C" {
#include <unistd.h>
#include <sys/stat.h>
}
#define JAIL_MAX 999999 // <sys/jail.h>

#include <fstream>
#include <iostream>

#include "utils/fs/path.hpp"
#include "utils/process/child.ipp"
#include "utils/format/macros.hpp"
#include "utils/process/operations.hpp"
#include "utils/process/status.hpp"

namespace fs = utils::fs;
namespace process = utils::process;
namespace jail = utils::process::jail;

using utils::process::args_vector;
using utils::process::child;


namespace {


static std::vector< std::string >
parse_jail_params_string(const std::string& str)
{
    std::vector< std::string > params;
    std::string p;
    char quote = 0;

    for (const char& c : str) {
        // whitespace delimited parameter
        if (quote == 0) {
            if (std::isspace(c)) {
                if (p.empty())
                    continue;
                params.push_back(p);
                p = "";
            }
            else if (c == '"' || c == '\'') {
                if (!p.empty())
                    params.push_back(p);
                p = "";
                quote = c;
            }
            else
                p += c;
        }

        // quoted parameter
        else {
            if (c == quote) {
                if (!p.empty())
                    params.push_back(p);
                p = "";
                quote = 0;
            }
            else
                p += c;
        }
    }

    // leftovers
    if (!p.empty())
        params.push_back(p);

    return params;
}


/// Functor to run a program.
class run {
    /// Program binary absolute path.
    const utils::fs::path& _program;

    /// Program arguments.
    const args_vector& _args;

public:
    /// Constructor.
    ///
    /// \param program Program binary absolute path.
    /// \param args Program arguments.
    run(
        const utils::fs::path& program,
        const args_vector& args) :
        _program(program),
        _args(args)
    {
    }

    /// Body of the subprocess.
    void
    operator()(void)
    {
        process::exec(_program, _args);
    }
};


}  // anonymous namespace


/// Create a jail with a given name and params string.
///
/// A new jail will always be 'persist', thus the caller is expected to remove
/// the jail eventually via jail::remove().
///
/// It's expected to be run in a subprocess.
///
/// \param jail_name Name of a new jail.
/// \param jail_params String of jail parameters.
void
jail::create(const std::string& jail_name, const std::string& jail_params)
{
    args_vector av;

    // creation flag
    av.push_back("-qc");

    // jail name
    av.push_back(F("name=%s") % jail_name);

    // some obvious defaults to ease test authors' life
    av.push_back(F("children.max=%d") % JAIL_MAX);

    // test defined jail params
    const std::vector< std::string > params = parse_jail_params_string(jail_params);
    for (const std::string& p : params)
        av.push_back(p);

    // it must be persist
    av.push_back("persist");

    // invoke jail
    std::auto_ptr< process::child > child = child::fork_capture(
        run(fs::path("/usr/sbin/jail"), av));
    process::status status = child->wait();

    // expect success
    if (status.exited() && status.exitstatus() == EXIT_SUCCESS)
        return;

    // otherwise, let us know what jail thinks and fail fast
    char err[330];
    child->output().getline(err, 330);
    std::cerr << err << "\n";
    std::exit(EXIT_FAILURE);
}


/// Executes an external binary in a jail and replaces the current process.
///
/// This function must not use any of the logging features so that the output
/// of the subprocess is not "polluted" by our own messages.
///
/// \param jail_name Name of the jail to run within.
/// \param program The test program binary absolute path.
/// \param args The arguments to pass to the binary, without the program name.
void
jail::exec(const std::string& jail_name,
           const fs::path& program,
           const args_vector& args) throw()
{
    args_vector av(args);
    av.insert(av.begin(), program.str());

    // get our work dir
    char cwd[256];
    if (getcwd(cwd, 256) == NULL) {
        std::cerr << "process::jail::exec: getcwd() errors: "
            << strerror(errno) << ".\n";
        std::exit(EXIT_FAILURE);
    }

    // prepare a script to run in a jail to change back to the work dir
    // and exec the program
    std::string cd_exec_path = std::string(cwd) + "/kyua_cd_exec.sh";
    std::ofstream f(cd_exec_path);
    if (f.fail()) {
        std::cerr << "process::jail::exec: cannot create kyua_cd_exec.sh file: "
            << strerror(errno) << ".\n";
        std::exit(EXIT_FAILURE);
    }
    f << "#!/bin/sh\n"
      << "cd \"$1\" && shift && exec $*";
    f.close();
    if (chmod(cd_exec_path.c_str(),
              S_IRUSR|S_IXUSR | S_IRGRP|S_IXGRP | S_IROTH|S_IXOTH) != 0) {
        std::cerr << "process::jail::exec: chmod() errors: "
            << strerror(errno) << ".\n";
        std::exit(EXIT_FAILURE);
    }

    // change current work dir inside a jail back to kyua work dir
    av.insert(av.begin(), cwd);
    av.insert(av.begin(), cd_exec_path);

    av.insert(av.begin(), jail_name);

    process::exec(fs::path("/usr/sbin/jexec"), av);
}


/// Removes a jail with a given name.
///
/// It's expected to be run in a subprocess.
///
/// \param jail_name Name of a jail to remove.
void
jail::remove(const std::string& jail_name)
{
    args_vector av;

    // removal flag
    av.push_back("-r");

    // jail name
    av.push_back(jail_name);

    // invoke jail
    std::auto_ptr< process::child > child = child::fork_capture(
        run(fs::path("/usr/sbin/jail"), av));
    process::status status = child->wait();

    // expect success
    if (status.exited() && status.exitstatus() == EXIT_SUCCESS)
        std::exit(EXIT_SUCCESS);

    // otherwise, let us know what jail thinks and fail fast
    char err[330];
    child->output().getline(err, 330);
    std::cerr << err << "\n";
    std::exit(EXIT_FAILURE);
}
