#!/usr/bin/env bash
# Downloads every spec file pinned in specs.csv, refuses any whose SHA-256 differs
# from its pin, and generates the Java, Python and TypeScript clients into build/.
# Nothing under build/ is committed.
#
# Usage: clients/generate.sh            all specs, all languages
#        ONLY=dc-9.2.4 clients/generate.sh
#        LANGS="python" clients/generate.sh
# Needs: bash, curl, sha256sum, java 11+, python 3 (compile check of the Python clients).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
build="$here/build"
GEN_VERSION=7.26.0
GEN_SHA256=1760050094997b9cc790cc1350be095f15da8c08a996b184d3eadc4ccda5e35e
GEN_URL="https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/$GEN_VERSION/openapi-generator-cli-$GEN_VERSION.jar"
LANGS=${LANGS:-"java python typescript-axios"}
ONLY=${ONLY:-}

for tool in curl sha256sum java python; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done

mkdir -p "$build/specs" "$build/tools"
jar="$build/tools/openapi-generator-cli-$GEN_VERSION.jar"
[ -f "$jar" ] || curl -fsSL -o "$jar" "$GEN_URL"
if ! echo "$GEN_SHA256  $jar" | sha256sum -c --quiet -; then
  echo "REFUSED generator jar: SHA-256 $(sha256sum "$jar" | cut -d' ' -f1) is not the pinned $GEN_SHA256" >&2
  exit 1
fi

failed=()
while IFS=, read -r id product version url sha; do
  sha=${sha%$'\r'}
  [ -n "$ONLY" ] && [ "$id" != "$ONLY" ] && continue
  spec="$build/specs/$id.json"
  echo "== $id ($product $version)"
  curl -fsSL -o "$spec.part" "$url" || { echo "   download failed: $url" >&2; failed+=("$id:download"); continue; }
  actual=$(sha256sum "$spec.part" | cut -d' ' -f1)
  if [ "$actual" != "$sha" ]; then
    # Never generate from an unpinned file; the pin changes only by reviewed pull request.
    mv "$spec.part" "$build/specs/$id.rejected.json"
    echo "   REFUSED: SHA-256 $actual, pinned $sha" >&2
    failed+=("$id:hash")
    continue
  fi
  mv "$spec.part" "$spec"
  echo "   hash ok"

  pkg="client_${id//[.-]/_}"
  for lang in $LANGS; do
    out="$build/$lang/$id"
    rm -rf "$out"
    props="hideGenerationTimestamp=true"
    extra=()
    case "$lang" in
      # Cloud v1 has a cache-busting query parameter named "_", which the Python generator leaves without a name.
      python) props="$props,packageName=$pkg"; extra=(--parameter-name-mappings _=underscore_param) ;;
      java) props="$props,invokerPackage=aerie.lab.$pkg,apiPackage=aerie.lab.$pkg.api,modelPackage=aerie.lab.$pkg.model,artifactId=$pkg" ;;
      typescript-axios) props="$props,npmName=$pkg,supportsES6=true" ;;
    esac
    # The DC files declare some unused RestList* schemas as "type: array" with properties; without the
    # normalizer the Python generator writes models that do not compile.
    if java -jar "$jar" generate -i "$spec" -g "$lang" -o "$out" --additional-properties="$props" \
         --openapi-normalizer REMOVE_PROPERTIES_FROM_TYPE_OTHER_THAN_OBJECT=true "${extra[@]}" \
         >"$build/$lang-$id.log" 2>&1 \
       && { [ "$lang" != python ] || python -m compileall -q "$out/$pkg" >>"$build/$lang-$id.log" 2>&1; }; then
      echo "   $lang ok"
    else
      echo "   $lang FAILED, log: $build/$lang-$id.log" >&2
      failed+=("$id:$lang")
    fi
  done
done < <(tail -n +2 "$here/specs.csv")

if [ ${#failed[@]} -gt 0 ]; then
  echo "FAILED: ${failed[*]}" >&2
  exit 1
fi
echo "all clients generated in $build"
