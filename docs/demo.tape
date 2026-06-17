# vhs tape for docs/demo.gif — render with:  vhs docs/demo.tape
# (run from the repo root with a `c2pa-mcp` binary on PATH, e.g. `go build -o c2pa-mcp .`)

Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1180
Set Height 760
Set Padding 22
Set Theme "Dracula"

# Setup: put the freshly built binary on PATH, hidden from the recording.
Hide
Type "export PATH=$PWD:$PATH PS1='$ '" Enter
Type "clear" Enter
Show

Sleep 600ms
Type "# detect — what the file CLAIMS (fast, unverified)" Enter
Sleep 800ms
Type "c2pa-mcp detect testdata/c2pa_signed.jpg" Sleep 400ms Enter
Sleep 2200ms

Type "# verify — full validation; exits non-zero when invalid" Enter
Sleep 800ms
Type "c2pa-mcp verify testdata/c2pa_signed.jpg" Sleep 400ms Enter
Sleep 3200ms
