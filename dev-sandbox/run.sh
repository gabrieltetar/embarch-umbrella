#!/usr/bin/env bash
# Build the sandbox image (once, cached after) and drop into a shell
# inside it with the three code repos bind-mounted read-write. Nothing
# that happens in that shell touches the real host: this container has
# its own /root, its own /var/lib, and no WSL2 interop / /mnt/c — see
# ../../embarch-doc/embarch-dev-workflow.md §5 for what that does and
# doesn't cover, and the Dockerfile's own comments for why it stops short
# of a real init system.
#
# Usage: ./run.sh [path-to-the-embarch-parent-directory]
#   Defaults to two directories up from this script — i.e. the `embarch/`
#   parent that holds embarch-core/embarch-api/embarch-umbrella as
#   siblings (embarch-doc/DOC-PROTOCOL.md §2's layout).
#
# NOT YET VERIFIED — see the Dockerfile's own header note.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT="${1:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

for repo in embarch-core embarch-api embarch-umbrella; do
    if [[ ! -d "$PARENT/$repo" ]]; then
        echo "error: expected $PARENT/$repo to exist (embarch-doc/DOC-PROTOCOL.md §2's sibling layout)" >&2
        exit 1
    fi
done

docker build -t embarch-dev-sandbox "$SCRIPT_DIR"

docker run --rm -it \
    -v "$PARENT/embarch-core:/work/embarch-core" \
    -v "$PARENT/embarch-api:/work/embarch-api" \
    -v "$PARENT/embarch-umbrella:/work/embarch-umbrella" \
    -w /work/embarch-umbrella \
    embarch-dev-sandbox \
    bash
