
# function that divides string into parts of size 2characters, and adding the prefix '0x' to each part.
# then it returns a concatenation of the parts, with ' ,' as a separator.
def divide(string):
    parts = [string[i:i+2] for i in range(0, len(string), 2)]
    for i in range(len(parts)):
        parts[i] = '0x' + parts[i]
    return ', '.join(parts)

print(divide('a485a894be48e52c245a3efaaee3ff0ad0156aa4f1285e643f18b8a315ef6bf7'))