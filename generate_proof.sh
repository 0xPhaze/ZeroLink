# We need this because foundry `ffi`
# does not allow chaining commands such as `cd`.
cd circuits && nargo prove -p "$1" && echo "$(<proofs/ZeroLink.proof)" && cd ..
