import importlib
import json
import pkgutil
import time

from .nested.arithmetic import rotate


class MeridianInputError(ValueError):
    pass


class MeridianMixer:
    def __init__(self, seed, parameters):
        self.state = seed & 0xffffffff
        self.parameters = parameters

    def transform(self, values):
        output = []
        for index, value in enumerate(values):
            self.state = (self.state * self.parameters["multiplier"] +
                          self.parameters["increment"] + value + index) & 0xffffffff
            output.append(rotate(self.state ^ self.parameters["salt"], (index % 31) + 1))
        return output


def evaluate(request):
    values = request["values"]
    seed = request.get("seed", 0)
    if type(values) is not list or len(values) > 4096:
        raise MeridianInputError("MERIDIAN_PRIVATE_INPUT_LIMIT")
    if type(seed) is not int or any(type(value) is not int for value in values):
        raise TypeError("integer inputs required")
    parameters = json.loads(pkgutil.get_data("probeapp", "resources/model.json"))
    start = time.perf_counter_ns()
    result = MeridianMixer(seed, parameters).transform(values)
    transform_ns = time.perf_counter_ns() - start
    mode = request.get("plugin", "twist")
    if mode not in {"twist", "identity"}:
        raise MeridianInputError("unsupported plugin")
    plugin = importlib.import_module("probeapp.plugins." + mode)
    result = plugin.apply(result)
    answer = {"values": result, "checksum": sum(result) & 0xffffffff}
    if request.get("_benchmark"):
        answer["transform_ns"] = transform_ns
    return answer
