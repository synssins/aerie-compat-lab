#!/usr/bin/env bash
# Downloads every spec file pinned in specs.csv, refuses any whose SHA-256 differs
# from its pin, generates the Java, Python and TypeScript clients into build/ and
# builds each one (Python compile check, Maven package, npm install + tsc).
# Nothing under build/ is committed.
#
# A pinned address may name a member inside a .tar.gz release asset as <url>#<member>;
# the archive is pinned, then the member is taken from it. YAML members are converted
# to JSON for the suite runner. The optional langs column narrows the languages for one row.
#
# Usage: clients/generate.sh            all specs, all languages
#        ONLY=dc-9.2.4 clients/generate.sh
#        LANGS="python" clients/generate.sh
# Needs: bash, curl, sha256sum, tar, java 11+, python 3; mvn for java, npm for typescript-axios.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
build="$here/build"
GEN_VERSION=7.26.0
GEN_SHA256=1760050094997b9cc790cc1350be095f15da8c08a996b184d3eadc4ccda5e35e
GEN_URL="https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/$GEN_VERSION/openapi-generator-cli-$GEN_VERSION.jar"
LANGS=${LANGS:-"java python typescript-axios"}
ONLY=${ONLY:-}

need=(curl sha256sum tar java python)
[[ " $LANGS " == *" java "* ]] && need+=(mvn)
[[ " $LANGS " == *" typescript-axios "* ]] && need+=(npm)
for tool in "${need[@]}"; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done

mkdir -p "$build/specs" "$build/tools"
jar="$build/tools/openapi-generator-cli-$GEN_VERSION.jar"
[ -f "$jar" ] || curl -fsSL -o "$jar" "$GEN_URL"
if ! echo "$GEN_SHA256  $jar" | sha256sum -c --quiet -; then
  echo "REFUSED generator jar: SHA-256 $(sha256sum "$jar" | cut -d' ' -f1) is not the pinned $GEN_SHA256" >&2
  exit 1
fi

# Builds one generated client; output goes to the language's log.
build_client() {
  local lang=$1 out=$2 pkg=$3
  case "$lang" in
    python) python -m compileall -q "$out/$pkg" ;;
    # -parameters keeps parameter names, which the Java runner matches by name.
    java) (cd "$out" && mvn -q -B -Dmaven.repo.local="$build/m2" -DskipTests -Dmaven.javadoc.skip=true -Dmaven.source.skip=true \
             -Dmaven.compiler.parameters=true package dependency:copy-dependencies -DincludeScope=runtime -DoutputDirectory=target/lib) ;;
    # The generated package.json builds dist/ with tsc on install ("prepare").
    typescript-axios) (cd "$out" && npm install --no-audit --no-fund --loglevel=error --cache "$build/npm-cache") && [ -f "$out/dist/index.js" ] ;;
  esac
}

failed=()
while IFS=, read -r id product version url sha langs; do
  sha=${sha%$'\r'}; langs=${langs%$'\r'}
  [ -n "$ONLY" ] && [ "$id" != "$ONLY" ] && continue
  spec="$build/specs/$id.json"
  echo "== $id ($product $version)"
  fetch=${url%%#*}
  member=; [[ "$url" == *"#"* ]] && member=${url#*#}
  curl -fsSL -o "$build/specs/$id.part" "$fetch" || { echo "   download failed: $fetch" >&2; failed+=("$id:download"); continue; }
  actual=$(sha256sum "$build/specs/$id.part" | cut -d' ' -f1)
  if [ "$actual" != "$sha" ]; then
    # Never generate from an unpinned file; the pin changes only by reviewed pull request.
    mv "$build/specs/$id.part" "$build/specs/$id.rejected"
    echo "   REFUSED: SHA-256 $actual, pinned $sha" >&2
    failed+=("$id:hash")
    continue
  fi
  echo "   hash ok"
  if [ -n "$member" ]; then
    x="$build/specs/$id.extract"; rm -rf "$x"; mkdir -p "$x"
    tar -xzf "$build/specs/$id.part" -C "$x"
    rm -f "$build/specs/$id.part"
    if [[ "$member" == *.yaml || "$member" == *.yml ]]; then
      java -jar "$jar" generate -i "$x/$member" -g openapi -o "$x/json" >"$build/specs/$id.convert.log" 2>&1
      mv "$x/json/openapi.json" "$spec"
    else
      mv "$x/$member" "$spec"
    fi
    rm -rf "$x"
  else
    mv "$build/specs/$id.part" "$spec"
  fi

  pkg="client_${id//[.-]/_}"
  for lang in $LANGS; do
    [ -n "$langs" ] && [[ " $langs " != *" $lang "* ]] && continue
    out="$build/$lang/$id"
    rm -rf "$out"
    props="hideGenerationTimestamp=true"
    extra=()
    case "$lang" in
      # Cloud v1 has a cache-busting query parameter named "_", which the Python generator leaves without a name.
      python) props="$props,packageName=$pkg"; extra=(--parameter-name-mappings _=underscore_param) ;;
      # Models with both "links" and "_links" would get two fields named links.
      # A schema without additionalProperties allows fields it does not list (OpenAPI's default), so the models
      # do too: the vendor files list "links" but real servers send "_links" and "_expandable". Declared fields
      # are still checked by type and requiredness.
      java) props="$props,invokerPackage=aerie.lab.$pkg,apiPackage=aerie.lab.$pkg.api,modelPackage=aerie.lab.$pkg.model,artifactId=$pkg"
            props="$props,disallowAdditionalPropertiesIfNotPresent=false"
            extra=(--name-mappings _links=underscoreLinks) ;;
      # One request object per call, so the TypeScript runner passes parameters by name. A parameter named
      # "key" (DC 10.x+ watch operations) is shadowed by the generated loop variable of the same name.
      typescript-axios) props="$props,npmName=$pkg,supportsES6=true,useSingleRequestParameter=true"
            extra=(--parameter-name-mappings key=keyParam) ;;
    esac
    log="$build/$lang-$id.log"
    input="$spec"
    if [ "$lang" = java ]; then
      # Cloud v2 declares a property with enum: [null], which becomes an empty Java enum that does not
      # compile; the Java client is generated from a copy without such enums (nullable stays).
      input="$build/specs/$id.java.json"
      python - "$spec" "$input" <<'PY'
import json, sys
def strip(o):
    if isinstance(o, dict):
        return {k: strip(v) for k, v in o.items() if not (k == "enum" and v == [None])}
    return [strip(v) for v in o] if isinstance(o, list) else o
json.dump(strip(json.load(open(sys.argv[1], encoding="utf-8"))), open(sys.argv[2], "w", encoding="utf-8"))
PY
    fi
    # The DC files declare some unused RestList* schemas as "type: array" with properties; without the
    # normalizer the Python generator writes models that do not compile.
    if java -jar "$jar" generate -i "$input" -g "$lang" -o "$out" --additional-properties="$props" \
         --openapi-normalizer REMOVE_PROPERTIES_FROM_TYPE_OTHER_THAN_OBJECT=true "${extra[@]}" >"$log" 2>&1 \
       && build_client "$lang" "$out" "$pkg" >>"$log" 2>&1; then
      echo "   $lang ok"
    else
      echo "   $lang FAILED, log: $log" >&2
      failed+=("$id:$lang")
    fi
  done
done < <(tail -n +2 "$here/specs.csv")

if [ ${#failed[@]} -gt 0 ]; then
  echo "FAILED: ${failed[*]}" >&2
  exit 1
fi
echo "all clients generated and built in $build"
