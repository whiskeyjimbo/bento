# Manifest per agent class, not per job

An orchestrator that runs many agent jobs under Bento does not need one approved
manifest per job. It needs one per *class* of agent - the test runner, the
docs writer, the dependency bumper - reused across every checkout those agents
are pointed at. That works because of two properties that are easy to miss, and
this page states them so a fleet can be built on them deliberately.

## Why one manifest covers every checkout

**Grants may be relative, and are anchored to the manifest.** `read: [./src]`
means the `src` next to the manifest, wherever the manifest currently sits.

**Approval happens before resolution.** The approval fingerprint
(`policy.Fingerprint`) hashes the manifest's permission fields *as written*.
Anchoring relative grants to an absolute directory (`manifest.Resolve`) is a
separate step that runs after the fingerprint is checked, deliberately so.

Together: a manifest carrying only relative grants has one fingerprint no matter
where it is copied. A fleet reviews and stamps N manifests once, then drops the
right one into each job's checkout - N approvals total, not one per job. Nothing
in the run path restamps, and no job has authority to approve anything.

The same property has an edge worth knowing. The fingerprint attests the text, so
a `~`-rooted grant is portable across *users* too: the same stamped manifest
opens whichever user's home it runs as. That is usually what you want for a fleet
of identical workers, and it is a hazard if a manifest crosses from a service
account to a person. `ShieldedGrants` in `enforce.Result` names each lifted
shield by its home-expanded absolute path, so the run reports whose home it
opened - one more reason to read the `Report` rather than the exit code, as in
[denial-shapes.md](denial-shapes.md).

## Two auth modes, both permanent

An agent needs credentials to talk to its model provider. There are two ways to
supply them, and neither is a stepping stone to the other. The criterion for
choosing is whether a human is watching the run - not how serious the deployment
is.

### Monitored: the operator's own subscription

A human is at the keyboard and the agent bills to their existing subscription.
The manifest names the credential file exactly:

```yaml
read:
  - ~/.claude/.credentials.json
```

A shield is lifted only by a grant naming it exactly. `read: ~` does not lift it,
and neither does `read: ~/.claude` - the match is literal against the shielded
path. Treat that exactness as the feature: opting a credential store in is one
visible line, it sits inside the approval fingerprint, and it cannot get there
without a human reading it. A manifest that broadens its grants toward `$HOME`
gains nothing; the shield holds until someone types the store's own name.

The run reports it back, too. `ShieldedGrants` names the shields the policy
lifted, so a supervisor can log which jobs were handed a credential.

### Unattended: a per-job API key

No human is watching, so the key should not be a person's. Allowlist the name in
the manifest and supply the value at launch:

```yaml
env: [ANTHROPIC_API_KEY]
```

```sh
bento run --env ANTHROPIC_API_KEY="$JOB_KEY" ./agent.py.manifest.yaml
```

`env:` is an allowlist of names, and the fingerprint hashes those names, not
their values. Keys rotate without restamping a single manifest. `--env` supplies
a value but does not grant one: a name it names that the manifest does not list
is refused, so a secret reaching the sandbox is a stamped decision either way.

What that buys, beyond not exposing a person's subscription: per-job spend
attribution, single-key revocation as a kill switch for one runaway job, and an
identity that does not belong to anybody.
