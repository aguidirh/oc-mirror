#!/bin/bash

usage() {
    echo "Usage: $0 [-f flow] [-m] [-c] [-d diff_base_file1 diff_base_file2]"
    echo "  -f flow  Specify the flow to run (m2d, d2m, m2m, no-run)"
    echo "  -m       Enable memory profiling (--mem-prof)"
    echo "  -c       Enable CPU profiling (--cpu-prof)"
    echo "  -d diff_base_file1 diff_base_file2"
    echo "                         Specify two files for comparison with -diff_base"
    exit 1
}

cleanup() {
    if [[ ! -z $MEM_PROF_PID ]]; then
        kill $MEM_PROF_PID
        wait $MEM_PROF_PID 2>/dev/null
    fi
    if [[ ! -z $CPU_PROF_PID ]]; then
        kill $CPU_PROF_PID
        wait $CPU_PROF_PID 2>/dev/null
    fi
    if [[ ! -z $PROF_DIFF_PID ]]; then
        kill $PROF_DIFF_PID
        wait $PROF_DIFF_PID 2>/dev/null
    fi
}

trap cleanup EXIT

FLOW=""
MEM_PROF=""
CPU_PROF=""
PROF_DIFF_FILES=()

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -f)
            FLOW="$2"
            shift
            shift 
            ;;
        -m)
            MEM_PROF="--mem-prof"
            shift
            ;;
        -c)
            CPU_PROF="--cpu-prof"
            shift
            ;;
        -d)
            PROF_DIFF_FILES=("$2" "$3")
            if [ ${#PROF_DIFF_FILES[@]} -ne 2 ]; then
                usage
            fi
            PROF_DIFF="-diff_base=${PROF_DIFF_FILES[0]} ${PROF_DIFF_FILES[1]}"
            shift 
            shift
            shift
            ;;
        *)
            usage
            ;;
    esac
done

if [[ -z $FLOW ]]; then
    usage
fi

CONFIG="./isc.yaml"
WORKSPACE="file://pprof"
DEST="docker://localhost:6000"
COMMON_OPTS="--v2 $MEM_PROF $CPU_PROF"

case $FLOW in
    m2d)
        ../../bin/oc-mirror -c $CONFIG $WORKSPACE $COMMON_OPTS
        ;;
    d2m)
        ../../bin/oc-mirror -c $CONFIG --from $WORKSPACE $DEST --dest-tls-verify=false $COMMON_OPTS
        ;;
    m2m)
        ../../bin/oc-mirror -c $CONFIG --workspace $WORKSPACE $DEST --dest-tls-verify=false $COMMON_OPTS
        ;;
    no-run)
        echo "Skipping all flows."
        ;;
    *)
        usage
        ;;
esac

if [[ ! -z $MEM_PROF ]]; then
    go tool pprof -http=:6775 mem.prof &
    MEM_PROF_PID=$!
fi

if [[ ! -z $CPU_PROF ]]; then
    go tool pprof -http=:6776 cpu.prof &
    CPU_PROF_PID=$!
fi

if [[ ! -z $PROF_DIFF ]]; then
    go tool pprof -http=:6777 $PROF_DIFF &
    PROF_DIFF_PID=$!
fi

wait