# permission-auditor

[![Go Reference](https://pkg.go.dev/badge/github.com/theluckystrike/permission-auditor.svg)](https://pkg.go.dev/github.com/theluckystrike/permission-auditor)

A dependency-free Go library that audits the permissions and host match
patterns declared by a Chromium extension (Manifest V2 or V3) and returns a
per-permission risk breakdown, an aggregate score, and an overall risk level.

It powers the extension safety review engine at
**[zovo.one](https://zovo.one)**, and pairs naturally with
[`crx-manifest-parser`](https://pkg.go.dev/github.com/theluckystrike/crx-manifest-parser)
— though it takes plain string slices so it works standalone too.

## Install

```sh
go get github.com/theluckystrike/permission-auditor@latest
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/theluckystrike/permission-auditor"
)

func main() {
	r := permissionauditor.Audit(
		[]string{"tabs", "cookies", "storage"},
		[]string{"https://*/*"},
	)
	fmt.Printf("Overall: %s (score %d)\n", r.Overall, r.TotalScore)
	fmt.Println(r.Summary)
	for _, f := range r.Permissions {
		fmt.Printf("  %-12s %-9s %s\n", f.Permission, f.Level, f.Reason)
	}
}
```

## Why

The safety review tools at [zovo.one](https://zovo.one) need a deterministic,
explainable way to rank extension permissions by risk. This module exposes that
scoring engine — a built-in catalog of common permissions plus host-pattern
breadth analysis — so the same verdicts can run in CLIs, CI checks, and review
dashboards.

## License

MIT
