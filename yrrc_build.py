# Copyright 2020 Wesley Shields <wxs@atarininja.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import argparse
import json
import os
import subprocess


def parse_args():
    parser = argparse.ArgumentParser(description="Clone and build YARA repo")
    parser.add_argument(
        "-c", "--config", type=open, default="config.json", help="Config file"
    )
    return parser.parse_args()


def fetch_repo(git_bin, git_repo_url, git_tag, build_dir):
    if not os.path.exists(os.path.join(build_dir, ".git")):
        print(f"{build_dir} doesn't look like a git repo, performing checkout...")
        subprocess.check_call([git_bin, "clone", git_repo_url, build_dir])
    else:
        print(f"{build_dir} looks like a repo already. Updating to master...")
        subprocess.check_call([git_bin, "checkout", "master"], cwd=build_dir)
        subprocess.check_call([git_bin, "pull"], cwd=build_dir)

    if git_tag != "master":
        print(f"Checking out {git_tag}")
        subprocess.check_call([git_bin, "checkout", git_tag], cwd=build_dir)


def do_build(build_dir):
    subprocess.check_call(["./bootstrap.sh"], cwd=build_dir)
    subprocess.check_call(["./configure"], cwd=build_dir)
    subprocess.check_call(["make"], cwd=build_dir)


def main():
    args = parse_args()
    try:
        config = json.loads(args.config.read())
        git_bin = config["git_bin"]
        git_repo = config["git_repo_url"]
        git_tag = config["git_tag"]
        build_dir = config["build_dir"]
    except json.JSONDecodeError as e:
        print(f"Error decoding config: {e}")
        return
    except KeyError as e:
        print(f"Error reading config: {e}")
        return

    fetch_repo(git_bin, git_repo, git_tag, build_dir)
    do_build(build_dir)


if __name__ == "__main__":
    main()
