"""
Model version 1.00
This model is only capable of Encrypting and Decrypting english letters, punctuation marks and whatever symbol
is present in the defined dictionary. If any other language or characters that are not defined in the dictionary,
this model fails to encrypt, which makes it useless on a broader thinking scale, as the user takes the authority
to input data and their personal key. So, if the user tries to enter character not defines in the static dictionary
the encryption fails, which makes it unsuitable for large scale usage.

Drawbacks:
> More characters to encrypt, more the size of the output file.
> Can not encrypt undefined characters like bangla, chinese, russian, spanish etc. language characters

Comment: Future improvements are still required
> Increase languages
> Improve complexity
> Space Improvements

Code written and modified by : Arnab Pramanik
"""

import gc
import hashlib
import random as rd
import string as s
import zlib
import ast
import os


# =============================== Error Types ==========================================
class BARSDirectionError(Exception):
    def __init__(self, message):
        super().__init__(message)


class BARSError(Exception):
    def __init__(self, message):
        super().__init__(message)


class CharacterError(Exception):
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
    def __init__(self, usr_key, text, ecr: bool = True, output_file: bool = True):
        self.key = usr_key
        self.text = text
        self.output_file = output_file
        self.return_cypher = self._encrypt() if ecr else self._decrypt() if not ecr else self._raise_error()

    def _raise_error(self):
        raise BARSError("ERC Argument Can Only Take TRUE Or FALSE")

    @staticmethod
    def _generate():
        min_value = 10 ** (16 - 1)
        max_value = (10 ** 16) - 1
        rand_key = rd.randint(min_value, max_value)
        string_val = str(rand_key)
        ascii_string_val = "".join(chr(int(_)) for _ in string_val)
        return rand_key, ascii_string_val

    @staticmethod
    def _char_dict(static=None):
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
        if static is not None:
            return lst
        for _ in range(3):
            rd.shuffle(lst)
        return lst

    @staticmethod
    def _compress(string):
        return zlib.compress(string.encode())

    @staticmethod
    def _decompress(compressed):
        decompressed = zlib.decompress(compressed)
        return decompressed.decode()

    @staticmethod
    def _delete(file_path):
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
        with open(file_name, "w") as text_file:
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
        static_dictionary = self._char_dict(static=1)
        tup = str((rd_ascii, dictionary, integrity_a, integrity_b))
        encoded = str(" ".join(str(static_dictionary.index(_)) for _ in tup))
        compressed_key = self._compress(encoded)
        with open("Seq.key", 'wb') as key_file:
            key_file.write(compressed_key)
        return

    def _load_key_file(self):
        if "Seq.key" not in os.listdir():
            raise KeyError("Seq.key not found in directory")
        static_dictionary = self._char_dict(static=1)
        with open("Seq.key", "rb") as key_file:
            key_contents = self._decompress(key_file.read())
            key_contents = key_contents.split(' ')
            decoded = ''.join(static_dictionary[int(_)] for _ in key_contents)
            ascii_key, sequence, integrity_a, integrity_b = ast.literal_eval(decoded)
            rd_key = int("".join(str(ord(_)) for _ in ascii_key))
            return rd_key, sequence, integrity_a, integrity_b

    def _encrypt(self):
        key_seed = self._seed(self.key, 10)
        rd_key, ascii_val = self._generate()
        dictionary = self._char_dict()
        new_seed = self._seed(str(rd_key * key_seed), 16) * key_seed
        bottom_level_integrity = 0
        surface_level_integrity = 0
        encrypted = ''
        for char in self.text:
            if char in dictionary:
                dic_idx = ((dictionary.index(char)) * rd_key) + new_seed
                bottom_level_integrity += self._seed(str(dic_idx), 8)
                binary = format(int(dic_idx), 'b')
                surface_level_integrity += self._seed(str(binary), 12)
                encrypted += binary + ' '
                dictionary = self._rotate(dictionary, 1)
            else:
                # encrypted += char + ' '
                raise CharacterError(f"BARS can not understand this character: {char}")
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
                for items in data:
                    decimal_index = int((int(items, 2) - seed) // rd_key)
                    decrypted += dictionary[decimal_index]
                    dictionary = self._rotate(dictionary, -1)
                decrypted = decrypted[::-1]
                if self.output_file:
                    self._write_file(decrypted, "DECRYPTED TEXT.txt")
                self._delete("Seq.key")
                return decrypted
            except IndexError:
                self._delete("Seq.key")
                raise DecryptionError("Data Or Key Has Been Compromised Or Corrupted")
        self._delete("Seq.key")
        raise IntegrityViolation("Data Or Key Has Been Compromised")


if __name__ == '__main__':
    with open("text_file.txt", "r", encoding="utf-8") as file:
        my_text = file.read()
        x = BARS(usr_key='key', text=my_text, output_file=False)
