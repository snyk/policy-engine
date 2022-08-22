import os
import datetime
import sys


license_text = """Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


def license_file(path, comment_prefix):
    # Parse Copyright statements
    with open(path, "r") as f:
        lines = list(f.readlines())
    copyrights = {}
    copyrights_end = None
    for i in range(len(lines)):
        words = lines[i].split()
        if len(words) > 4 and words[0] == comment_prefix and words[1] == "Copyright":
            years = words[2]
            start_year = years
            end_year = years
            if "-" in years:
                [start_year, end_year] = years.split("-")
            holder = " ".join(words[3:])
            copyrights[holder] = (start_year, end_year)
        elif len(copyrights) > 0 and copyrights_end is None:
            copyrights_end = i

    # Insert Snyk copyright
    snyk = "Snyk Ltd"
    year = str(datetime.datetime.today().year)
    changed = False
    if snyk in copyrights:
        if copyrights[snyk][1] != year:
            copyrights[snyk] = (copyrights[snyk][0], year)
            changed = True
    else:
        copyrights[snyk] = (year, year)
        changed = True

    # Skip rewriting file
    if not changed:
        print(f"{path}: up to date, skipping", file=sys.stderr)
        return

    # Rewrite file:
    new_lines = []
    copyrights_list = reversed(sorted(list(copyrights.items()), key=lambda x: x[1][1]))
    for (holder, (start_year, end_year)) in copyrights_list:
        years = start_year if start_year == end_year else f"{start_year}-{end_year}"
        new_lines.append(f"{comment_prefix} Copyright {years} {holder}\n")
    if copyrights_end is not None:
        new_lines += lines[copyrights_end:]
    else:
        new_lines.append(f"{comment_prefix}\n")
        for line in license_text.splitlines():
            if line == "":
                new_lines.append(f"{comment_prefix}\n")
            else:
                new_lines.append(f"{comment_prefix} {line}\n")
        new_lines.append("\n")
        new_lines += lines
    with open(path, "w") as f:
        f.write("".join(new_lines))
    print(f"{path}: updated", file=sys.stderr)


ignores = [
    "pkg/internal/terraform",
    "pkg/models",
]


def license_tree(dir):
    for root, dirs, files in os.walk(dir):
        for name in files:
            path = os.path.join(root, name)

            if any(path.startswith(ignore) for ignore in ignores):
                continue

            _, ext = os.path.splitext(name)
            if ext == ".go":
                license_file(path, "//")
            elif ext == ".rego":
                license_file(path, "#")
            elif ext == ".tf":
                license_file(path, "#")
            elif ext == ".yaml" or ext == ".yml":
                license_file(path, "#")


license_tree("pkg")
license_tree("cmd")
license_tree("rego")
license_file("swagger.yaml", "#")
