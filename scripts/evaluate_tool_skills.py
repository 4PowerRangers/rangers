

import json

from ranger.agent.tool_skills import offline_tool_metrics


if __name__ == "__main__":
    print(json.dumps(offline_tool_metrics(), indent=2, sort_keys=True))