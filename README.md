NixAudit
========

* Author: geoff.jones@cyberis.co.uk
* Copyright: Cyberis Limited 2013
* License: GPLv3 (See LICENSE)

'Expect' scripts to assist in auditing Linux and Unix hosts. Automatically logs into a *nix host, collects files required for a host build audit, tar/gzips and scp's everything back to your audit host for offline analysis.

Usage
-----
Below is an example of a small bash script wrapper to run NixAudit across a number of hosts:

```bash
#!/bin/bash
while read line
do
  ./linux-audit.sh $line username mysecretpassword
done
```
Dependencies
------------
Expect, ssh/scp and bash. An account on the target hosts.

Issues
------
Kindly report all issues via https://github.com/cyberisltd/NixAudit/issues
