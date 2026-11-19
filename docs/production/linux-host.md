# Production on a Linux host

One host runs the agent, the Fabric Node (with ingress groups and the content
store) and the eBPF sensor in production mode, with Docker Compose.

1. **Prerequisites and layout:** [what you need](../reference/manual-setup/production-setup.md#1-what-you-need).
2. **Keys, tokens and certificates:** [generate them](../reference/manual-setup/production-setup.md#2-keys-tokens-and-certificates),
   one token per ingress group, files readable by the Node's user only.
3. **The Node:** [configure and start it](../reference/manual-setup/production-setup.md#3-the-node)
   behind the preflight check, with a destination of your own
   ([destinations](destinations.md)).
4. **The sensor:** [the eBPF emitter in production mode](../reference/manual-setup/production-setup.md#4-the-ebpf-emitter),
   bound to its own ingress group.
5. **The agent:** [its settings](../reference/manual-setup/production-setup.md#5-the-agent):
   https to the Node with its CA, its token as a headers file, the capture
   policy, an encrypted spool. `fabric run --print-env --format systemd`
   prints a launcher's settings once `fabric.yaml` names the Node.
6. **Read a run:** [the reader](../reference/manual-setup/production-setup.md#6-read-a-run).

Docker Desktop differs in file ownership and the sensor's view:
[Docker Desktop](../reference/manual-setup/production-setup.md#docker-desktop).
