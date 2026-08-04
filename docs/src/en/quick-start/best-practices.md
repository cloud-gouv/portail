# Best Practices

## Policy ordering

Policies are evaluated **in declaration order**, top to bottom. The first policy
whose conditions are satisfied has its action executed, and evaluation stops.

Always place **specific cases before** general cases.

```portail
# Correct: specific rules first
policy admin_access {
  when host =~ "(horizon|auth).cloud.example.com"
  action allow
}

policy allowed_sites {
  when host in ["github.com", "google.com"]
  action allow
}

policy default_deny {
  action deny
}
```

```portail
# Incorrect: general rule captures everything before specifics
policy allow_all {
  action allow
}

policy block_unapproved_llm_usage {
  when host in ["chatgpt.com", "deepseek.com", "anthropic.com"]
  action deny  # never reached!
}
```

## Explicit default policy

Portail applies an implicit *default deny* if no policy produces an `allow`.
To keep your files readable and predictable, **always add an explicit `default deny`**
at the very end.

```portail
policy default_deny {
  action deny
}
```

## Using `route.local` for failover

On a workstation, you can allow restricted traffic in standalone (failover) mode
while requiring the remote proxy in normal mode:

```portail
# Standalone mode: limited access to a few sites
policy failover_sites {
  when host in ["github.com", "google.com"] and route.local == true
  action allow
}

# Chaining mode: trust the remote proxy
policy delegate_to_remote {
  when route.local == false
  action allow
}

policy default_deny {
  action deny
}
```

This pattern is useful when the remote proxy infrastructure is being deployed
and you want a safety net without compromising productivity.

## Naming conventions

Use descriptive `snake_case` names. Prefix with numbers if you want to control
ordering across separate files.

When using the NixOS module, ACL rules are declared as an attribute set under
`services.portail.acl.filter.rules`. Attribute keys are sorted lexicographically,
so numeric prefixes let you control the evaluation order:

```nix
services.portail.acl.filter.rules = {
  "10-admin" = ''policy admin_access { ... }'';
  "20-intranet" = ''route cloud_console { ... }'';
  "50-failover" = ''policy failover_sites { ... }'';
  "99-default-deny" = ''policy default_deny { action deny }'';
};
```

If you manage ACLs as plain files instead, use `filter-acl-rules-path` in your
settings. The file is read top-to-bottom with no lexicographic sorting.
