import os
import re

# Instruction sets
memory = {
    'and': '000', 'add': '001', 'lda': '010', 'sta': '011',
    'bun': '100', 'bsa': '101', 'isz': '110'
}
register = {
    'cla': '0111100000000000', 'cle': '0111010000000000', 'cma': '0111001000000000',
    'cme': '0111000100000000', 'cir': '0111000010000000', 'cil': '0111000001000000',
    'inc': '0111000000100000', 'spa': '0111000000010000', 'sna': '0111000000001000',
    'sza': '0111000000000100', 'sze': '0111000000000010', 'hlt': '0111000000000001'
}
inp_out = {
    'inp': '1111100000000000', 'out': '1111010000000000', 'ski': '1111001000000000',
    'sko': '1111000100000000', 'ion': '1111000010000000', 'iof': '1111000001000000'
}

# Globals
asmlist = []
address_symbol_table = {}
bin_out = {}


def read_file(filename):
    """Reads assembly code from a file."""
    global asmlist
    try:
        with open(filename, 'r') as file:
            for line in file.readlines():
                line = line.strip().lower()
                line = re.sub(r';.*', '', line)
                matches = re.findall(r'\S+', line)
                matches = [token.rstrip(',') for token in matches]
                if matches:
                    asmlist.append(matches)
        print("Assembly List:")
        print(asmlist)
        print()
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
    except Exception as e:
        print(f"Unexpected error while reading the file: {e}")


def is_label(operand):
    """Checks if a token is a label."""
    return operand.endswith(':')


def binary_from_hex(hex_number, bit_width=16):
    """Converts a hexadecimal number to binary."""
    n = int(hex_number, 16)
    if n >= (1 << (bit_width - 1)):
        n -= (1 << bit_width)
    if n < 0:
        n = (1 << bit_width) + n
    return bin(n)[2:].zfill(bit_width)


def binary_from_dec(integer_number, bit_width=16):
    """Converts a decimal number to binary."""
    if integer_number < 0:
        integer_number = (1 << bit_width) + integer_number
    return bin(integer_number)[2:].zfill(bit_width)


def first_pass():
    """Builds the symbol table."""
    try:
        lc = 0
        for line in asmlist:
            if line[0] == 'org':
                lc = int(line[1], 16)
            elif is_label(line[0]):
                label = line[0][:-1]
                address_symbol_table[label] = lc
                lc += 1
            elif line[0] == 'end':
                break
            else:
                lc += 1
        print("Symbol Table:")
        print(address_symbol_table)
        print()
    except Exception as e:
        print(f"Unexpected error in first pass: {e}")


def second_pass():
    """Generates the machine code."""
    try:
        lc = 0
        for line in asmlist:
            if line[0] == 'org':
                lc = int(line[1], 16)
            elif line[0] == 'end':
                break
            elif len(line) > 2 and is_label(line[0]):
                if line[1] == 'dec':
                    bin_out[lc] = binary_from_dec(int(line[2]))
                    lc += 1
                elif line[1] == 'hex':
                    bin_out[lc] = binary_from_hex(line[2])
                    lc += 1
            elif not is_label(line[0]):
                instruction = line[0]
                bit_15 = "1" if len(line) > 1 and line[-1] == 'i' else "0"

                if instruction in memory:
                    address = address_symbol_table.get(line[1], 0)
                    address_binary = bin(address)[2:].zfill(12)
                    op_code = memory[instruction]
                    bin_out[lc] = bit_15 + op_code + address_binary
                    lc += 1

                elif instruction in register:
                    bin_out[lc] = register[instruction]
                    lc += 1

                elif instruction in inp_out:
                    bin_out[lc] = inp_out[instruction]
                    lc += 1

        # Ensure all labels have machine codes
        for label, addr in address_symbol_table.items():
            if addr not in bin_out:
                bin_out[addr] = "0000000000000000"

        print("Machine Code:")
        for addr, code in sorted(bin_out.items()):
            print(f"{addr:03x}: {code}")
        print()
    except Exception as e:
        print(f"Unexpected error in second pass: {e}")


def write_output():
    """Writes output to a file."""
    try:
        with open('output.txt', 'w') as file:
            file.write("Symbol Table:\n")
            # Convert decimal to hexadecimal without '0x' prefix
            for label, addr in sorted(address_symbol_table.items(), key=lambda x: x[1]):
                file.write(f"{label}: {hex(addr)[2:]}\n")  # Convert to hex and strip '0x'
            file.write("\nMachine Code:\n")
            for addr, code in sorted(bin_out.items()):
                file.write(f"{hex(addr)[2:]}: {code}\n")  # Print address in hex
        print("Output written to 'output.txt'")
    except Exception as e:
        print(f"Unexpected error while writing to the file: {e}")


def main():
    try:
        asm_file = 'assembly3.txt'  # Automatically opens this file
        print(f"Opening file: {asm_file}")
        read_file(asm_file)
        first_pass()
        second_pass()
        write_output()
    except Exception as e:
        print(f"Unexpected error in main function: {e}")


if __name__ == "__main__":
    main()
