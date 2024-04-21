import difflib


def compare(s1: str, s2: str):
    matcher = difflib.SequenceMatcher(None, s1, s2)

    # Get a list of differences between the two strings
    diffs = matcher.get_opcodes()

    # Print the differences to the console
    for opcode, i1, i2, j1, j2 in diffs:
        if opcode == 'equal':
            print('\033[0;92m' + s1[i1:i2] + '\033[0m', end='')
        elif opcode == 'insert':
            print('\033[0;93m' + s2[j1:j2] + '\033[0m', end='')
        elif opcode in ['replace', 'delete']:
            print('\033[91m' + s1[i1:i2] + '\033[0m', end='')
