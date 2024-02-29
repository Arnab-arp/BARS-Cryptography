"""
Model version 1.50
This model is an improved version of Model 1.00. The problem faced by the previous model is that it can not encrypt
undefined characters. So to solve this issue, what I have done is create a parse function. During encryption, the text
will be first parsed to check if there is any unknown characters or the characters not defined in the static dictionary.
If found, the character will be converted to its corresponding Order value from the ASCII table, and a start and end
tags will be added with the order value. After that, all the same characters will be replaced by this new
tagged value, and lastly, that tagged value will be inserted to the dictionary list. This causes all the characters of
the user text to be converted in to text with no unknown characters in it. The decryption will happen like previously,
but in this model, there is one extra step. The decrypted text will be passed in to the parser function, which will
replace the tagged value with the original character. Finally returning the decrypted text.

Upgrades:
> Every character under UTF-8 encoding can be encrypted.
> Code complexity slightly reduced.

Drawbacks:
> The more unknown characters, The bigger the dictionary.
> Bigger the size of dictionary, more time to encrypt and decrypt.
> More characters to encrypt, more the size of the output file, as it is encrypting every single characters.

Comment: Future improvements are still required
> Space Management
> Reduce encryption time
> Reduce Code Complexity
> Reduce List Size

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


# =============================== Error Types ==========================================
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


# =============================== Error Types ==========================================

class BARS:
    def __init__(self, usr_key, usr_text, ecr: bool = True, output_file: bool = True):
        self.key = usr_key
        self.text = usr_text
        self.output_file = output_file
        self.return_cypher = self._encrypt() if ecr else self._decrypt() if not ecr else self._raise_error()

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
    def _safe_delete(file_path):
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError('Path Does Not Exists')
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
    def _write_file(cypher_text, file_name):
        with open(file_name, "w", encoding="utf-8") as text_file:
            text_file.write(cypher_text)

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

    def _parse_text(self, text, revert=False, _dic=None):
        if revert is False:
            edit_text = text
            dictionary = self._static_list()
            for chars in text:
                if chars not in dictionary:
                    order = str(ord(chars)-9879)
                    dictionary.append(f'⌈~{order}~⌉')  # Adding a start and end tags of the order value of the unknown
                    edit_text = edit_text.replace(chars, f'⌈~{order}~⌉')  # replacing with the text to be encrypted
            for i in range(3):
                rd.shuffle(dictionary)
            return edit_text, dictionary

        if revert is True and _dic is not None:
            reverted_text = text
            for i in _dic:
                if len(i) > 1:
                    partial = i.replace('⌈~', '')
                    partial = partial.replace('~⌉', '')
                    extract_value = int(partial) + 9879
                    character = chr(extract_value)
                    reverted_text = reverted_text.replace(i, character)
            return reverted_text
        raise AttributeError('Arguments not satisfied')

    def _check_integrity(self, data, surface_level_integrity, bottom_level_integrity):
        bottom_level_integrity_sum = 0
        surface_level_integrity_sum = 0
        for items in data:
            surface_level_integrity_sum += self._seed(u_key=items, val_len=12)
            bottom_level_integrity_sum += self._seed(u_key=str(int(items, 2)), val_len=8)
        if bottom_level_integrity_sum != bottom_level_integrity or surface_level_integrity_sum != surface_level_integrity:
            return False
        return True

    def _write_key_file(self, rd_ascii, dictionary, integrity_a, integrity_b):
        static_dictionary = self._static_list()
        tup = str((rd_ascii, dictionary, integrity_a, integrity_b))
        encoded = str(" ".join(str(static_dictionary.index(_)) for _ in tup))
        compressed_key = self._compress(encoded)
        with open("Seq.key", 'wb') as key_file:
            key_file.write(compressed_key)
        return

    def _load_key_file(self):
        if "Seq.key" not in os.listdir():
            raise KeyError("Seq.key not found in directory")
        static_dictionary = self._static_list()
        with open("Seq.key", "rb") as key_file:
            key_contents = self._decompress(key_file.read())
            key_contents = key_contents.split(' ')
            decoded = ''.join(static_dictionary[int(_)] for _ in key_contents)
            ascii_key, sequence, integrity_a, integrity_b = ast.literal_eval(decoded)
            rd_key = int("".join(str(ord(_)) for _ in ascii_key))
            return rd_key, sequence, integrity_a, integrity_b

    def _encrypt(self):
        user_text, dictionary = self._parse_text(self.text)
        key_seed = self._seed(self.key, 10)
        rd_key, ascii_val = self._generate()
        new_seed = self._seed(str(rd_key * key_seed), 16) * key_seed
        bottom_level_integrity = 0
        surface_level_integrity = 0
        encrypted = ''

        for char in tqdm(user_text, desc='Encrypting'):
            dic_idx = ((dictionary.index(char)) * rd_key) + new_seed
            bottom_level_integrity += self._seed(str(dic_idx), 8)
            binary = format(int(dic_idx), 'b')
            surface_level_integrity += self._seed(str(binary), 12)
            encrypted += binary + ' '
            dictionary = self._rotate(dictionary, 1)

        self._write_key_file(ascii_val, dictionary, bottom_level_integrity, surface_level_integrity)
        del ascii_val, dictionary, bottom_level_integrity, surface_level_integrity
        gc.collect()
        if self.output_file:
            self._write_file(encrypted, "ENCRYPTED TEXT.txt")
        return encrypted

    def _decrypt(self):
        data = self.text
        if not isinstance(data, list):
            data = data.split()
            if not isinstance(data, list):
                raise DecryptionError("Required list type")

        rd_key, dictionary, bottom_level_integrity, surface_level_integrity = self._load_key_file()

        if self._check_integrity(data, surface_level_integrity, bottom_level_integrity):
            del bottom_level_integrity, surface_level_integrity
            gc.collect()
            key_seed = self._seed(self.key, 10)
            seed = self._seed(str(rd_key * key_seed), 16) * key_seed
            decrypted = ""
            data.reverse()
            dictionary = self._rotate(dictionary, -1)
            try:
                for items in tqdm(data, desc='Decrypting'):
                    decimal_index = int((int(items, 2) - seed) // rd_key)
                    decrypted += dictionary[decimal_index]
                    dictionary = self._rotate(dictionary, -1)
                decrypted = decrypted[::-1]
                if len(dictionary) != len(self._static_list()):
                    decrypted = self._parse_text(text=decrypted, revert=True, _dic=dictionary)

                if self.output_file:
                    self._write_file(decrypted, "DECRYPTED TEXT.txt")
                self._safe_delete("Seq.key")
                return decrypted
            except IndexError:
                self._safe_delete("Seq.key")
                raise DecryptionError("Data Or Key Has Been Compromised Or Corrupted")
        self._safe_delete("Seq.key")
        raise IntegrityViolation("Data Or Key Has Been Compromised")


if __name__ == '__main__':
    import time as t
    from natsort import natsorted

    test_files = []
    for files in natsorted(os.listdir()):
        if files.endswith('.txt') and not files.startswith('Model'):
            test_files.append(files)
    print(test_files)
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
            he_x = BARS(usr_key='NT))(!&#AR', usr_text=contents, ecr=True, output_file=False).return_cypher
            encr_end = t.time()
            encr_time_logs[tests] = encr_end - encr_start

            dcr_start = t.time()
            he_y = BARS(usr_key='NT))(!&#AR', usr_text=he_x, ecr=False, output_file=False).return_cypher
            dcr_end = t.time()
            dcr_time_logs[tests] = dcr_end - dcr_start
            if he_y == contents:
                is_equal[tests] = 'Successful'
            else:
                is_equal[tests] = 'Failed'
    total_time_end = t.time()
    final_record = f"""Model Version :: 1.50\n\n
Total Test Files :: {len(test_files)}\n
Test File Names :: {test_files}\n\n
_________________________ Size Of Files _________________________ \n
{'\n'.join(f'{key} :: {value} bytes or {value/1024} KB' for key, value in size_of_file.items())}\n\n
_________________________ Characters In Each File _________________________ \n
{'\n'.join(f'{key} :: {value}' for key, value in total_chars_for_each_test.items())}\n\n
_________________________ Encryption Time Logs _________________________\n
File      Time
{'\n'.join(f'{key} :: {value} seconds' for key, value in encr_time_logs.items())}\n\n
_________________________ Decryption Time Logs _________________________\n
File      Time
{'\n'.join(f'{key} :: {value} seconds' for key, value in dcr_time_logs.items())}\n\n
Total Time Elapsed :: {total_time_end - total_time_start} seconds\n\n
_________________________ Decrypted Text == Actual Text _________________________\n
File     Is_Equal
{'\n'.join(f'{key} :: {value}' for key, value in is_equal.items())}\n\n
    """
    with open('Model-1.50.txt', 'w') as record:
        record.write(final_record)
pass
