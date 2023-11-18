 #!/bin/bash
 
cd `dirname $0` || exit 1

find ./data -type f \( -name "*.json" -o -name "*.csv" -o -name "*.csv.*" -o -name "*.sqlite3" \) -exec rm -f {} \;
find ./fetcher -name "*.sh" | xargs -I % -P4 bash %

