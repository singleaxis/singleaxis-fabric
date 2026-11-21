# Kubernetes

In a cluster Fabric installs once per cluster with Helm, makes every key,
token and certificate itself, and turns capture on for the pods you
annotate: [Get started with Kubernetes](../get-started/kubernetes.md) is the
whole path.

- **Agents:** the injector adds Fabric's settings and read-only mounts to an
  annotated pod when your own rollout creates it; it never changes the image
  or command, and a pod starts unchanged when the injector is down.
- **Host evidence:** the sensor runs on each Linux node as a DaemonSet and
  watches the selected pods only. gVisor and Kata pods are reported
  `unsupported_runtime`, never silently unscoped.
- **GitOps:** render the Secrets instead of creating them, and apply them
  with your own tool:

<!-- fabric-docs-test: path=shape-kubernetes step=1 kind=install -->
```bash
pip install "singleaxis-fabric[cli]"
```

<!-- fabric-docs-test: path=shape-kubernetes step=2 -->
```bash
fabric init --kubernetes --render ./fabric-manifests --agent-namespace agents
# expect: created Secret agents/fabric-agent
```

The files hold secret values: encrypt them with your GitOps tool before they
reach a repository.

What Fabric can see in a cluster before you install: `fabric plan
--kubernetes` (it reads the current context and changes nothing).
