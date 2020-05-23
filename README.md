# yrrc
YRRC (YARA Regression Checker, or YARA Regular Regression Checker, pronounced
"yar-kuh) is a tool to automate the testing of YARA signatures using a
continuously built YARA repository.

## Why?
Over years of development, YARA has gained a good number of tests which attempt
to make sure there are no regressions, but they are never complete enough. This
project is an attempt to collect signatures from the community and automate the
testing of these signatures using the most bleeding edge YARA code. The goal is
to leverage the extensive signature base of the community in order to catch
regressions in YARA before they make it into a release.

A good example of a regression which should have been caught is
https://github.com/VirusTotal/yara/pull/1269, but there were no unit tests which
covered this case at the time. Had YRRC existed back then and we had signatures
which exercised this code on packed samples we could have caught this
regression, fixed it before the release and even added a unit test to ensure
it stays fixed in the future.

## Design Goals
0. Avoid yara-python. This one may seem not-obvious but using yara-python comes
with some problems which are just easier to avoid in this environment. One of
the major problems from using yara-python here is building it. yara-python
ships with it's own bundled version of YARA, which may or may not be behind
the official repository. If I were to attempt to always build the python
bindings with the official repository master branch there may be API changes
made in master that have not been reflected in the python-bindings yet. It is
easier to avoid yara-python entirely and just write my own C program to work
with libyara directly.
1. Have a small series of tools which are loosely coupled together. I'm not
interested in a monolithic testing application. I'm willing to glue together
small pieces.
2. Make it as easy as possible to run. You should be able to edit config.json
to suit your needs, kick off a single script and have the system run completely.
This single script should just be calling a bunch of other scripts, so you can
still run the individual pieces if you want.
3. Automate as much as possible, including producing reports visible on a
webpage somewhere.

## How Does It Work (High Level)?
YRRC works in a multi-step process.

1. Fetch and build YARA (by default it builds whatever is in master).
2. Build yrrc binary, linking against the libyara built in step 1.
3. Run yrrc in collect mode (more on this later).
4. Fetch as many samples as possible from VirusTotal.
5. Run yrrc in scan mode (more on this later).
6. Process the output into a presentable report.

## Details

### yrrc_build.py
The first step is to fetch and build YARA. This is done with the `yrrc_build.py`
script. This script assumes you have everything you need to build YARA and just
does a bunch of subprocess calls to pull down the repository (into the current
working directory) and build YARA for you.

### make
Once you have YARA built you can build yrrc by running make. This will build
the yrrc binary using the version of YARA you built in the previous step.

### yrrc collect
With yrrc built you can now run it in "collect" mode.

```
wxs@wxs-mbp yrrc % DYLD_LIBRARY_PATH=/Users/wxs/src/yara/libyara/.libs ./yrrc -c config.json -m collect | jq .
{
  "c5c1ca4382f397481174914b1931e851a9c61f029e6b3eb8a65c9e92ddf7aa4c": {
    "expected": [
      "APT_MAL_DTRACK_Oct19_1"
    ]
  }
}
wxs@wxs-mbp yrrc %
```

This mode parses the YARA rules, looking for any metadata key named "sample"
and where the value looks like a valid hash, then generates some JSON on
stdout, which is useful to redirect to a file - I suggest "hashes.json" for
now. ;)

NOTE: I'm building this on OS X and am not static linking yrrc yet, so I have to
set DYLD_LIBRARY_PATH when running yrrc. This will change in the future.

### yrrc_fetch.py
Now that we know which hashes we need to fetch we can use yrrc_fetch.py to
retrieve them from VT. It will store them in a directory called "_cache" and
will only retrieve hashes it does not already have.

For this step you will need to provide your own VT API key that can download
samples. Just set the path to it in config.json.

```
@wxs-mbp yrrc % mkdir _cache
wxs@wxs-mbp yrrc % python3 ./yrrc_fetch.py
c5c1ca4382f397481174914b1931e851a9c61f029e6b3eb8a65c9e92ddf7aa4c 200
wxs@wxs-mbp yrrc %
```

### yrrc scan
With the files retrieved from VT you can now run yrrc in scan mode.

```
wxs@wxs-mbp yrrc % DYLD_LIBRARY_PATH=/Users/wxs/src/yara/libyara/.libs ./yrrc -c config.json -m scan | jq .
{
  "c5c1ca4382f397481174914b1931e851a9c61f029e6b3eb8a65c9e92ddf7aa4c": {
    "expected": [
      "APT_MAL_DTRACK_Oct19_1"
    ],
    "matches": [
      "APT_MAL_DTRACK_Oct19_1"
    ],
    "yara_error": 0
  }
}
wxs@wxs-mbp yrrc %
```

# ISSUES
There are so many issues with this code right now I almost don't want to publish
it.

1. The YARA build process is so janky, with no sane error handling.
2. The Makefile assumes you don't change the YARA build location and doesn't
support static linking of yrrc.
3. The yrrc code itself is very ugly. I need to make a pass through all of it
and clean it up, making error handling better and just make it more well
designed.
4. The fetch script is OK but could probably be a little better when it comes
to error handling.
5. There is nothing which processes the output from yrrc in scan mode to tell
you which rules caused regressions. I need to add that. ;)
6. I want to build a nice web front end for the reports and run it for the
community.

# Contributions
It is my hope that the YARA community will find value in this project and make
the YARA developers more confident in their changes. Besides improvements to the
code the biggest area for contributions is in YARA rules. If you want to
contribute YARA rules to this project I am more than happy to take them,
provided they can be accepted. To be accepted, the rules must meet the following
criteria:

1. They MUST be publicly available, and the pull request MUST come with a link
to a website where I can verify they are available.
2. They MUST include a hash in the metadata section of the rule and it MUST
use the key "sample" - this will likely change in the future to support things
other than key, but I haven't got to that yet.

I'm not interested in making judgements on the quality of any submitted rules.
I am purely interested in collecting as many rules as possible that exercise
different functionality of YARA and the modules, so that I can help out the
developers be more confident in changes they are making.

