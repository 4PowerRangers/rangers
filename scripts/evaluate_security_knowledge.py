

import json

from ranger.agent.security_knowledge import offline_routing_metrics


if __name__ == "__main__":
    print(json.dumps(offline_routing_metrics(), indent=2, sort_keys=True))