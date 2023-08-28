# We need this because foundry `ffi`
# does not allow chaining commands.
cd circuits && nargo prove -p "$1"
