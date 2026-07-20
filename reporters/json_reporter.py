import json
from pathlib import Path


class JsonReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, results: list, name: str = "vulnerability_report") -> str:
        data = [r.to_dict() for r in results]
        out_path = self.output_dir / f"{name}.json"
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)
        return str(out_path)
