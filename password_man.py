#!/.venv/Scripts/python.exe

# Change path according to your distribution
# obviosly needs cryptography module to be installed

import secrets
import base64
import string
import os
from os.path import isfile
from argparse import ArgumentParser
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken


class PasswordManager:

    filepath = ''
    public_file = ''
    public_key = ''
    fernet = None

    def __init__(self,
                 password: str,
                 filepath=os.path.join(os.path.expanduser('~'),
                                       'usr_passwords')
                 ):
        self.public_file = os.path.join(os.path.expanduser('~'),
                                        'password_manager.public')
        self.filepath = filepath
        self.load_key(password)

    def append_line(self, line: bytes):
        with open(self.filepath, 'ab') as f:
            token = self.fernet.encrypt(line)
            f.write(token)
            f.write('\n'.encode())

    def delete_line(self, line_num: int):
        final_content = b''
        with open(self.filepath, 'rb') as f:
            counter = 1
            for line in f:
                if counter == line_num:
                    counter += 1
                    continue
                final_content += line
                counter += 1
        with open(self.filepath, 'wb') as f:
            f.write(final_content)

    def print_file(self):
        n = 1
        with open(self.filepath, 'rb') as f:
            for line in f:
                try:
                    decrypted = self.fernet.decrypt(line)
                    print(str(n) + '. ' + decrypted.decode('utf-8'))
                except InvalidToken:
                    print('Введен неправильный пароль')
                finally:
                    n += 1

    def load_key(self, password: str):
        if not isfile(self.public_file):
            with open(self.public_file, 'wb') as f:
                salt = os.urandom(16)
                f.write(salt)
                self.public_key = salt
        else:
            with open(self.public_file, 'rb') as f:
                self.public_key = f.read()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                         length=32,
                         salt=self.public_key,
                         iterations=100000
                         )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.fernet = Fernet(key)

    def gen_pass(length: int, use_spec: bool) -> str:
        if use_spec:
            sym_set = string.ascii_letters + string.digits + \
                string.punctuation
        else:
            sym_set = string.ascii_letters + string.digits
        return ''.join(secrets.choice(sym_set) for i in range(length))


if __name__ == '__main__':
    arg_parser = ArgumentParser()
    arg_parser.add_argument('-s', '--special', action='store_true',
                            help='Use special characters')
    arg_parser.add_argument('-l', '--length', default=32,
                            help='Length of generated password')
    arg_parser.add_argument('-p', '--pass_man', action='store_true',
                            help='Enter password manager mode')
    args = arg_parser.parse_args()
    if args.pass_man:
        password = input(
            'Введите пароль (если первый раз, то любой подойдет):').encode()
        pass_man = PasswordManager(password)
        option = input('Выберите действие:\na: добавить строку' +
                       '\nd: удалить строку' +
                       '\ns: показать содержимое\n')
        if option == 'a':
            line = input('Введите, что вы ходите добавить:').encode()
            pass_man.append_line(line)
        if option == 'd':
            pass_man.print_file()
            num = input('Введите номер строки которую хотите удалить:')
            pass_man.delete_line(int(num))
        if option == 's':
            pass_man.print_file()
    else:
        passwd = PasswordManager.gen_pass(int(args.length), args.special)
        print(passwd)
    input('Press Enter to continue...')
