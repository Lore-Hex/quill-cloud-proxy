"""Union duplicate Go -coverpkg blocks across test binaries; require 90% per new code file."""
from collections import defaultdict
from pathlib import Path
import sys

source = Path(sys.argv[1])
blocks = {}
for line in source.read_text().splitlines()[1:]:
    location, statements, count = line.split()
    key = (location, int(statements))
    blocks[key] = max(blocks.get(key, 0), int(count))
merged = source.with_name(source.stem + "-merged.out")
merged.write_text("mode: set\n" + "".join(f"{loc} {n} {int(count > 0)}\n" for (loc, n), count in sorted(blocks.items())))
files = defaultdict(lambda: [0, 0])
for (location, statements), count in blocks.items():
    filename = location.split(":")[0].split("/enclave-go/")[-1]
    if filename.startswith(("internal/shadowcoord/", "internal/shadowobserve/")) or filename in ("cmd/enclave/speculation.go", "internal/trustedrouter/shadow.go", "internal/speculation/shadow_refresh.go"):
        files[filename][0] += statements
        files[filename][1] += statements * (count > 0)
for filename, (total, covered) in sorted(files.items()):
    print(f"{filename}: {covered}/{total} = {100*covered/total:.1f}%")
print("merged=" + str(merged))
if not files or any(covered / total < .9 for total, covered in files.values()):
    raise SystemExit(1)
