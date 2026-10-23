import json
import sys
import time

from probeapp.core import evaluate


def dispatch(request):
    start = time.perf_counter_ns()
    try:
        answer = evaluate(request)
    except (ValueError, TypeError, KeyError) as error:
        answer = {"error": type(error).__name__, "message": str(error)}
    return {"answer": answer, "elapsed_ns": time.perf_counter_ns() - start}


if __name__ == "__main__":
    for line in sys.stdin:
        print(json.dumps(dispatch(json.loads(line)), sort_keys=True), flush=True)
