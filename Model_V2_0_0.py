"""
Model version 2.00
Model 2.00 is an improved version of model 1.50. Like its predecessor, it incorporates the parsing function with a tweak.
Instead of appending the marked character in the static list, it creates a separate list to contain the marked character.
This will ensure that my original static character list does not grow exponentially large. Upgrades also include the
marked character list to be included side by side with the static list, along with other parameters. In the previous model
the static list becomes long, and iterating the entire list takes significant amount of time, specially if the list
is long enough. By keeping the tagged list separate, it ensures that the character list is not parsed, rather
just the marked list. Another thing that was included is that the entire encrypted text is compressed before returning.
This ensures that the file size do not grow exponentially large on a small input. Though this a robust model, it has
some drawbacks.

Upgrades:
1) Algorithmic approach for parsing the text.
2) Slight Optimizations to the encrypt function and parsing function.
2) Key file now contains 'Tagged' list for unknown characters.

Drawbacks:
1) The file size grows:
    Although the file size is shortened by the compression, it still shows a large growth in the encrypted file.
    For example: A plain text file of size 39 KB have grown to 1085 KB after encryption. Tough it is better than the
    previous model, on which a file of size 39 KB grows to 8.19 MB after encrypting.

2) Dictionary enlarges:
    In this model, the static dictionary does not grow, but the tagged list does. This means the more unknown characters
    are introduced, the tagged list will grow more, which may cause the encryption and decryption time to rise up
    significantly.

3) Text grows:
    Marking unknown character is still a robust way of encrypting text, but it does have side effects. The original text,
    after converting to marked text, grows which causes the algorithm to encrypt more characters than the original text.
    This might cause the encryption and decryption time to rise up.

Comment: Future improvements are still required
> Reduce encrypted file size more.
> Reduce Encryption time.

Code written and modified by : Arnab Pramanik
"""

import gc
import hashlib
import random as rd
import string as s
import zlib
import ast
import os
from tqdm import tqdm


# =============================== Custom Error Types ==========================================


class BARSDirectionError(Exception):
    def __init__(self, message):
        super().__init__(message)


class BARSError(Exception):
    def __init__(self, message):
        super().__init__(message)


class DecryptionError(Exception):
    def __init__(self, message):
        super().__init__(message)


class IntegrityViolation(Exception):
    def __init__(self, message):
        super().__init__(message)


class ArgumentError(Exception):
    def __init__(self, message):
        super().__init__(message)


# =============================== Custom Error Types ==========================================


class BARS:
    def __init__(self, usr_key, _contents, ecr: bool = True, output_file: bool = True):
        self.key = usr_key
        self.text = _contents
        self.output_file = output_file
        self.get = self._encrypt() if ecr else self._decrypt() if not ecr else self._raise_error()

    def _raise_error(self):
        raise BARSError("ERC Argument Can Only Take TRUE Or FALSE")

    @staticmethod
    def _compress(string):
        return zlib.compress(string.encode())

    @staticmethod
    def _decompress(compressed):
        decompressed = zlib.decompress(compressed)
        return decompressed.decode()

    @staticmethod
    def _seed(u_key, val_len):
        if not isinstance(u_key, str):
            raise ValueError("Input must be a string")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(u_key.encode('utf-8'))
        hex_digest = sha256_hash.hexdigest()
        max_value = 10 ** val_len
        sid = int(hex_digest[:val_len], 16) % max_value
        return sid

    @staticmethod
    def _rotate(chr_lst, direction):
        if direction == 1:  # rotate right
            return chr_lst[-1:] + chr_lst[:-1]
        elif direction == -1:  # rotate left
            return chr_lst[1:] + chr_lst[:1]
        raise BARSDirectionError("Direction must be defined")

    @staticmethod
    def _generate():
        min_value = 10 ** (16 - 1)
        max_value = (10 ** 16) - 1
        rand_key = rd.randint(min_value, max_value)
        string_val = str(rand_key)
        ascii_string_val = "".join(chr(int(_)) for _ in string_val)
        return rand_key, ascii_string_val

    @staticmethod
    def _safe_delete(file_path):
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError('File Does Not Exists')
            file_size = os.path.getsize(file_path)
            with open(file_path, 'wb') as f:
                for _ in range(3):
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())

            os.remove(file_path)
        except Exception as e:
            print(f"Error occurred while deleting the key file: {e}")

    @staticmethod
    def _static_list():
        filler_symbols = ("áçéôüɑəɪʃʊʋʰˈːαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώϏϐϑϒϓϔϕϖϗϘϙϚϛϜϝϞϟϠϡϢϣϤϥϦϧϨϩϪϫϬϭϮϯϰϱϲϳϴϵ϶ϷϸϹϺϻϼϽ"
                          "ϾϿ“”∀∃∄∈∉∋∌∍∎∏∐∑−∓∔∕∖∗∘∙√∛∜∝∞∟∠∡∢∣∤∥∦∧∨∩∪∫∬∭∮∯∰∱∲∳∴∵∶∷∸∹∺∻∼∽∾∿≀≁≂≃≄≅≆≇≈≉≊≋≌≍≎≏≐≑≒≓≔≕≖"
                          "≗≘≙≚≛≜≝≞≟≠≡≢≣≤≥≦≧≨≩≪≫≬≭≮≯≰≱≲≳≴≵≶≷≸≹≺≻≼≽≾≿⊀⊁⊂⊃⊄⊅⊆⊇⊈⊉⊊⊋⊌⊍⊎⊏⊐⊑⊒⊓⊔⊕⊖⊗⊘⊙⊚⊛⊜⊝⊞⊟⊠⊡⊢⊣⊤⊥⊦⊧⊨⊩⊪⊫⊬⊭"
                          "⊮⊯⊰⊱⊲⊳⊴⊵⊶⊷⊸⊹⊺⊻⊼⊽⊾⊿⋀⋁⋂⋃⋄⋅⋆⋇⋈⋉⋊⋋⋌⋍⋎⋏⋐⋑⋒⋓⋔⋕⋖⋗⋘⋙⋚⋛⋜⋝⋞⋟⋠⋡⋢⋣⋤⋥⋦⋧⋨⋩⋪⋫⋬⋭⋮⋯⋰⋱⋲⋳⋴⋵⋶⋷⋸⋹⋺⋻⋼⋽⋾⋿⌀"
                          "⌁⌂⌃⌄⌅⌆⌇⌈⌉⌊⌋⌌⌍⌎⌏⌐⌑⌒⌓⌔⌕⌖⌗⌘⌙⌚⌛⌜⌝⌞⌟⌠⌡⌢⌣⌤⌥⌦⌧⌨〈〉⌫⌬⌭⌮⌯⌰⌱⌲⌳⌴⌵⌶⌷⌸⌹⌺⌻⌼⌽⌾⌿⍀⍁⍂⍃⍄⍅⍆⍇⍈⍉⍊⍋⍌⍍⍎⍏⍐⍑⍒⍓⍔⍕⍖⍗"
                          "⍘⍙⍚⍛⍜⍝⍞⍟⍠⍡⍢⍣⍤⍥⍦⍧⍨⍩⍪⍫⍬⍭⍮⍯⍰⍱⍲⍳⍴⍵⍶⍷⍸⍹⍺⍻⍼⍽⍾⍿⎀⎁⎂⎃⎄⎅⎆⎇⎈⎉⎊⎋⎌⎍⎎⎏⎐⎑⎒⎓⎔⎕⎖⎗⎘⎙⎚⎛⎜⎝⎞⎟⎠⎡⎢⎣⎤⎥⎦⎧⎨⎩⎪"
                          "⎫⎬⎭⎮⎯⎰⎱⎲⎳⎴⎵⎶⎷⎸⎹⎺⎻⎼⎽⎾⎿⏀⏁⏂⏃⏄⏅⏆⏇⏈⏉⏊⏋⏌⏍⏎⏏⏐⏑⏒⏓⏔⏕⏖⏗⏘⏙⏚⏛⏜⏝⏞⏟⏠⏡⏢⏣⏤⏥⏦⏧⏨⏩⏪⏫⏬⏭⏮⏯⏰⏱⏲⏳⏴⏵⏶⏷⏸⏹⏺"
                          "⏻⏼⏽⏾⏿␀␁␂␃␄␅␆␇␈␉␊␋␌␍␎␏␐␑␒␓␔␕␖␗␘␙␚␛␜␝␞␟␠␡␢␣␤☀♡")
        lst = list(
            s.ascii_uppercase + s.punctuation + filler_symbols + s.digits + s.ascii_lowercase + '\n' + s.whitespace)
        return lst

    def _parse_text(self, text, revert=False, tagged_dict=None):
        converted_text = text
        text = list(set(text))
        if not revert:
            tagged_lists = []
            definitive_chars = self._static_list()
            rabbit = 0
            hare = 1
            if len(text) % 2 == 0:
                text = list(text)
                for _ in range(len(text) // 2):
                    if text[rabbit] not in definitive_chars:
                        converted_text = converted_text.replace(text[rabbit], f'⌈~{ord(text[rabbit]) - 9849}~⌉')
                        tagged_lists.append(f'⌈~{ord(text[rabbit]) - 9849}~⌉')
                    if text[hare] not in definitive_chars:
                        converted_text = converted_text.replace(text[hare], f'⌈~{ord(text[hare]) - 9849}~⌉')
                        tagged_lists.append(f'⌈~{ord(text[hare]) - 9849}~⌉')
                    rabbit += 2
                    hare += 2
                del rabbit, hare, text
                gc.collect()
                for _ in range(3):
                    rd.shuffle(definitive_chars)
                # print(tagged_lists)
                return list(converted_text), definitive_chars, tagged_lists

            text = list(text)
            for _ in range(len(text) // 2 + 1):
                if text[rabbit] not in definitive_chars:
                    converted_text = converted_text.replace(text[rabbit], f'⌈~{ord(text[rabbit]) - 9849}~⌉')
                    tagged_lists.append(f'⌈~{ord(text[rabbit]) - 9849}~⌉')
                if hare < len(text):
                    if text[hare] not in definitive_chars:
                        converted_text = converted_text.replace(text[hare], f'⌈~{ord(text[hare]) - 9849}~⌉')
                        tagged_lists.append(f'⌈~{ord(text[hare]) - 9849}~⌉')
                rabbit += 2
                hare += 2
            del rabbit, hare, text
            gc.collect()
            for _ in range(3):
                rd.shuffle(definitive_chars)
            # print(tagged_lists)
            return list(converted_text), definitive_chars, tagged_lists

        if revert and tagged_dict is not None:
            for items in tagged_dict:
                partial = items.replace('⌈~', '')
                partial = partial.replace('~⌉', '')
                extracted_character = chr(int(partial) + 9849)
                converted_text = converted_text.replace(items, extracted_character)
            return converted_text
        raise ArgumentError('Revert argument should be followed by "Tagged_dict" argument')

    def _dump_key(self, *args):
        tup_str = str(args)
        static_list = self._static_list()
        encoded = str("-".join(str(static_list.index(_)) for _ in tup_str))
        compressed_key = self._compress(encoded)
        with open('BARS.key', 'wb') as key_file:
            key_file.write(compressed_key)

    def _encrypt(self):
        converted_text, shuffled_list, tagged_list = self._parse_text(text=self.text)
        rd_key, ascii_val = self._generate()
        spc_key = self._seed(u_key=self.key, val_len=10)
        new_seed = self._seed(str(rd_key * spc_key), 16) * spc_key
        bottom_level_integrity = 0
        surface_level_integrity = 0
        encrypted = ''

        h_index = 0
        e_index = 1

        if len(converted_text) % 2 == 0:
            for _ in tqdm(range(len(converted_text) // 2), desc='Encrypting'):
                dic_idx = ((shuffled_list.index(converted_text[h_index])) * rd_key) + new_seed
                bottom_level_integrity += self._seed(str(dic_idx), 8)
                binary = format(int(dic_idx), 'b')
                surface_level_integrity += self._seed(str(binary), 12)
                encrypted += binary + ' '
                shuffled_list = self._rotate(shuffled_list, 1)

                dic_idx = ((shuffled_list.index(converted_text[e_index])) * rd_key) + new_seed
                bottom_level_integrity += self._seed(str(dic_idx), 8)
                binary = format(int(dic_idx), 'b')
                surface_level_integrity += self._seed(str(binary), 12)
                encrypted += binary + ' '
                shuffled_list = self._rotate(shuffled_list, 1)

                h_index += 2
                e_index += 2
        else:
            for _ in tqdm(range(len(converted_text) // 2 + 1), desc='Encrypting'):
                dic_idx = ((shuffled_list.index(converted_text[h_index])) * rd_key) + new_seed
                bottom_level_integrity += self._seed(str(dic_idx), 8)
                binary = format(int(dic_idx), 'b')
                surface_level_integrity += self._seed(str(binary), 12)
                encrypted += binary + ' '
                shuffled_list = self._rotate(shuffled_list, 1)

                if e_index < len(converted_text):
                    dic_idx = ((shuffled_list.index(converted_text[e_index])) * rd_key) + new_seed
                    bottom_level_integrity += self._seed(str(dic_idx), 8)
                    binary = format(int(dic_idx), 'b')
                    surface_level_integrity += self._seed(str(binary), 12)
                    encrypted += binary + ' '
                    shuffled_list = self._rotate(shuffled_list, 1)

                h_index += 2
                e_index += 2

        del converted_text, rd_key, new_seed, h_index, e_index
        gc.collect()

        self._dump_key(shuffled_list, tagged_list, ascii_val, surface_level_integrity, bottom_level_integrity)

        encrypted = self._compress(encrypted)
        if self.output_file:
            with open('Encrypted.bar', 'wb') as dump_ecr_file:
                dump_ecr_file.write(encrypted)
        return encrypted

    def _load_key(self):
        if 'BARS.key' not in os.listdir():
            raise FileNotFoundError('Decryption process requires a BARS.key file, but none is found.')
        static_list = self._static_list()
        with open('BARS.key', 'rb') as key_file:
            decompressed_key = self._decompress(key_file.read()).split('-')
            definitive_key = ''.join(static_list[int(_)] for _ in decompressed_key)
            shuffled_list, tagged_list, rd_key, integrity_s, integrity_b = ast.literal_eval(definitive_key)
            rd_key = int("".join(str(ord(_)) for _ in rd_key))
            return rd_key, shuffled_list, tagged_list, integrity_s, integrity_b

    def _check_integrity(self, data, surface_level_integrity, bottom_level_integrity):
        bottom_level_integrity_sum = 0
        surface_level_integrity_sum = 0
        for items in data:
            surface_level_integrity_sum += self._seed(u_key=items, val_len=12)
            bottom_level_integrity_sum += self._seed(u_key=str(int(items, 2)), val_len=8)
        if bottom_level_integrity_sum != bottom_level_integrity or surface_level_integrity_sum != surface_level_integrity:
            return False
        return True

    def _decrypt(self):
        if not isinstance(self.text, bytes):
            raise DecryptionError(f'Bytes class data type is required, but provided {type(self.text)}')

        data = self._decompress(self.text).split()
        data.reverse()

        rd_key, shuffled_list, tagged_list, integrity_s, integrity_b = self._load_key()

        if self._check_integrity(data, integrity_s, integrity_b):
            self._safe_delete('BARS.key')
            spc_key = self._seed(self.key, 10)
            seed = self._seed(str(rd_key * spc_key), 16) * spc_key
            decrypted = ""
            shuffled_list = self._rotate(shuffled_list, -1)
            try:
                for items in tqdm(data, desc='Decrypting'):
                    decimal_index = int((int(items, 2) - seed) // rd_key)
                    decrypted += shuffled_list[decimal_index]
                    shuffled_list = self._rotate(shuffled_list, -1)

                decrypted = decrypted[::-1]

                if len(tagged_list) != 0:
                    decrypted = self._parse_text(text=decrypted, revert=True, tagged_dict=tagged_list)

                del integrity_s, integrity_b, spc_key, seed, shuffled_list, tagged_list, rd_key
                gc.collect()

                if self.output_file:
                    with open('Decrypted.txt', 'w', encoding='utf-8') as dump_dcr_file:
                        dump_dcr_file.write(decrypted)

                return decrypted

            except IndexError:
                self._safe_delete("BARS.key")
                raise DecryptionError("Data Or Key Has Been Compromised Or Corrupted")
        self._safe_delete("BARS.key")
        raise IntegrityViolation("Data Or Key Has Been Compromised")


if __name__ == '__main__':
    # pass
    import time as t
    from natsort import natsorted

    test_files = []
    for files in natsorted(os.listdir()):
        if files.endswith('.txt') and not files.startswith('Model'):
            test_files.append(files)

    encr_time_logs = {}
    dcr_time_logs = {}
    total_chars_for_each_test = {}
    size_of_file = {}
    is_equal = {}
    total_time_start = t.time()
    for tests in test_files:
        size_of_file[tests] = os.path.getsize(tests)
        with open(tests, 'r', encoding='utf-8') as test_file:
            contents = test_file.read()
            total_chars_for_each_test[tests] = len(contents)
            encr_start = t.time()
            he_x = BARS(usr_key='NT))(!&#AR', _contents=contents, ecr=True, output_file=False).get
            encr_end = t.time()
            encr_time_logs[tests] = encr_end - encr_start

            dcr_start = t.time()
            he_y = BARS(usr_key='NT))(!&#AR', _contents=he_x, ecr=False, output_file=False).get
            dcr_end = t.time()
            dcr_time_logs[tests] = dcr_end - dcr_start
            if he_y == contents:
                is_equal[tests] = 'Successful'
            else:
                is_equal[tests] = 'Failed'
    total_time_end = t.time()
    final_record = f"""Model Version :: 2.00\n\n
Total Test Files :: {len(test_files)}\n
Test File Names :: {test_files}\n\n
_________________________ Size Of Files _________________________ \n
{'\n'.join(f'{key} :: {value} bytes or {value/1024} KB' for key, value in size_of_file.items())}\n\n
_________________________ Characters In Each File _________________________ \n
{'\n'.join(f'{key} :: {value} bytes' for key, value in total_chars_for_each_test.items())}\n\n
_________________________ Encryption Time Logs _________________________\n
File      Time
{'\n'.join(f'{key} :: {value} seconds' for key, value in encr_time_logs.items())}\n\n
_________________________ Decryption Time Logs _________________________\n
File      Time
{'\n'.join(f'{key} :: {value} seconds' for key, value in dcr_time_logs.items())}\n\n
Total Time Elapsed :: {total_time_end-total_time_start} seconds\n\n
_________________________ Decrypted Text == Actual Text _________________________\n
File     Is_Equal
{'\n'.join(f'{key} :: {value}' for key, value in is_equal.items())}\n\n
"""
    with open('Model-2.00.txt', 'w') as record:
        record.write(final_record)
pass
