# BNG Blaster PPPoE back-to-back test in containerlab

One BNG Blaster node with `eth1` connected to `eth2`. The A10NSP interface
`eth1` emulates the PPPoE server and `eth2` the PPPoE clients, so no device
under test is required. The test starts automatically once both links are
attached.

| File | Content |
|---|---|
| `pppoe-linux.clab.yml` | Topology with the BNG Blaster as `kind: linux` node |
| `bngblaster/clab/config.json` | BNG Blaster configuration (10 PPPoE sessions, session traffic and streams) |
| `bngblaster/clab/run.json` | Start arguments (report with session and stream details, logging) |

The directory `bngblaster` is the instance directory of the node
(`/var/bngblaster`), where the BNG Blaster controller also stores the logs
and the report (`bngblaster/clab/run_report.json`) of the test.

```sh
sudo containerlab deploy -t pppoe-linux.clab.yml

# Results while the test is running
docker exec clab-bngblaster-pppoe-bngblaster \
    bngblaster-cli /var/bngblaster/clab/run.sock session-counters

# Stop the node first, so that the sessions are torn down and the
# report is written while the links still exist.
docker stop clab-bngblaster-pppoe-bngblaster
sudo containerlab destroy -t pppoe-linux.clab.yml
```

The REST API and web UI of the controller are available on port 8001 of the
node, e.g. `http://clab-bngblaster-pppoe-bngblaster:8001` from the lab host.
