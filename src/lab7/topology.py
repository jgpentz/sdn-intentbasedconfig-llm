"""Live lab topology used to turn host names into OpenFlow match fields.

Ports follow the link order in mininet/topo_lab7.py: h1 is OpenFlow port 1.
"""

HOSTS = {
    "h1": {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "port": 1},
    "h2": {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "port": 2},
    "h3": {"ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "port": 3},
    "h4": {"ip": "10.0.0.4", "mac": "00:00:00:00:00:04", "port": 4},
}

SWITCH = "s1"
DPID = 1
CONTROLLER_REST = "http://10.0.0.211:8080"
