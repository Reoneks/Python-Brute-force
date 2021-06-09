import hashlib
import itertools
import click
import re
import time
import keyboard
import sys
import os
import threading
from multiprocessing.pool import ThreadPool

l = "abcdefghijklmnopqrstuvwxyz"
u = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
d = "0123456789"
h = "0123456789abcdef"
H = "0123456789ABCDEF"
s =  "!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~"
a = l + u + d + s
close_prog = False

def flush_input():
    try:
        import msvcrt
        while msvcrt.kbhit():
            msvcrt.getch()
    except ImportError:
        import sys, termios
        termios.tcflush(sys.stdin, termios.TCIOFLUSH)

def check_mask(ctx, param, value):
    if not re.match(r'^((\?[1lauHdhs]){1,40})$', value):
        raise click.BadParameter('Не подходящий формат маски. В маске разрешено использовать только символы 1lauHdhs')
    else:
        return value

def check_user_mask(ctx, param, value):
    if not re.match(r'^((\?[lauHdhs]){1,40})$', value):
        raise click.BadParameter('Не подходящий формат маски пользователя. В маске пользователя разрешено использовать только символы lauHdhs')
    else:
        return value

def md5_hash(char_sequence):
    return hashlib.md5(char_sequence.encode())

def sha1_hash(char_sequence):
    return hashlib.sha1(char_sequence.encode())

def sha224_hash(char_sequence):
    return hashlib.sha224(char_sequence.encode())

def sha256_hash(char_sequence):
    return hashlib.sha256(char_sequence.encode())

def sha384_hash(char_sequence):
    return hashlib.sha384(char_sequence.encode())

def sha512_hash(char_sequence):
    return hashlib.sha512(char_sequence.encode())

def parse_function(function_number):
    if function_number == 0:
        return md5_hash
    elif function_number == 1:
        return sha1_hash
    elif function_number == 2:
        return sha224_hash
    elif function_number == 3:
        return sha256_hash
    elif function_number == 4:
        return sha384_hash
    elif function_number == 5:
        return sha512_hash

def parse_item(char):
    if (char == "a"):
        return a
    elif (char == "l"):
        return l
    elif (char == "u"):
        return u
    elif (char == "d"):
        return d
    elif (char == "h"):
        return h
    elif (char == "H"):
        return H
    elif (char == "s"):
        return s

def keyboard_check(close_event, main_mask, hash_func, user_hash, print_status):
    password = "не найден"
    for word in itertools.product(*main_mask):
        if print_status.is_set():
            print("Текущее состояние: \n\tТекущий статус перебора: " + ''.join(word) + "\n\tКоличество символов: " + str(len(main_mask)))
            print_status.clear()
        generated_hash = hash_func(''.join(word)).hexdigest()
        if generated_hash.upper() == user_hash.upper():
            password = ''.join(word)
            if not os.path.isdir("data"):
                os.mkdir("data")
            text_file = open("data\\found_passwords.txt", "a")
            text_file.write(password + " " + generated_hash.upper() + "\n")
            text_file.close()
            break
    close_event.set()
    return password

def brute_force_by_mask(user_hash, mask, hash_func):
    rainbow_result = brute_force_by_rainbow_table("data\\found_passwords.txt", user_hash)
    if rainbow_result != "не найден":
        print("\tПароль хэша " + user_hash + " найден в базе ранее найденых паролей. Пароль: " + rainbow_result)
        return True
    main_mask = mask.split('?')[1:]
    for item in range(len(main_mask)):
        new_item = ""
        for char in main_mask[item]:
            new_item += parse_item(char)
        main_mask[item] = new_item
    e1 = threading.Event()
    e2 = threading.Event()
    pool = ThreadPool(processes=1)
    keyboard.is_pressed('q')
    async_result = pool.apply_async(keyboard_check, (e1, main_mask, hash_func, user_hash, e2))
    while not e1.is_set():
        try:
            if keyboard.is_pressed('q'):
                flush_input()
                global close_prog
                close_prog = True
                return
            elif keyboard.is_pressed('s'):
                e2.set()
                flush_input()
                time.sleep(0.1)
        except:
            break
    password = async_result.get()
    print("\tХэш: " + user_hash + " пароль: " + password)
    if (password == "не найден"):
        return False
    else:
        return True

def brute_force_by_dict(dictionary_path, user_hash, hash_func):
    if not os.path.isdir("data"):
        os.mkdir("data")
    text_file = open("data\\found_passwords.txt", "r")
    text = text_file.read()
    text_file.close()
    text_file = open("data\\found_passwords.txt", "a")
    with open(dictionary_path, 'r') as f:
        nums = f.read().splitlines()
        password = "не найден"
        for file_password in nums:
            generated_hash = hash_func(''.join(file_password)).hexdigest()
            if not (file_password + " " + generated_hash.upper()) in text:
                text_file.write(file_password + " " + generated_hash.upper() + "\n")
            if generated_hash.upper() == user_hash.upper():
                password = file_password
                break
        print("\tХэш: " + user_hash + " пароль: " + password)

def brute_force_by_rainbow_table(rainbow_table_path, user_hash):
    if not os.path.isdir("data"):
        os.mkdir("data")
    text_file = open("data\\found_passwords.txt", "r")
    text = text_file.read()
    text_file.close()
    text_file = open("data\\found_passwords.txt", "a")
    with open(rainbow_table_path, 'r') as f:
        nums = f.read().splitlines()
        password = "не найден"
        for file_password in nums:
            if not (file_password.split(" ")[0] + " " + file_password.split(" ")[1].upper()) in text:
                text_file.write(file_password.split(" ")[0] + " " + file_password.split(" ")[1].upper() + "\n")
            if file_password.split(" ")[1].upper() == user_hash.upper():
                password = file_password.split(" ")[0]
                break
        return password
    text_file.close()

@click.command(context_settings={"ignore_unknown_options": True})
@click.option('-a', default=3, help='Режим взлома:                        ' +
                                    '1)Брутфорс по словарю                ' +
                                    '2)Брутфорс по радужной таблице       ' +
                                    '3)Брутфорс по маске                  ', type=click.IntRange(1, 3), show_default=True)
@click.option('-i', is_flag=True, help='Включить инкрементирование')
@click.option('--increment-min', default=1, type=click.IntRange(1, 40, clamp=True), help='Начать прирост на X', show_default=True)
@click.option('--increment-max', default=5, type=click.IntRange(1, 40, clamp=True), help='Остановить прирост на X', show_default=True)
@click.option('--dictionary', '-d', help='Словарь / Радужная таблица', nargs=1, type=click.Path(exists=True))
@click.option('-m1', default="?l?u?d", help='Пользовательская маска', callback=check_user_mask, show_default=True)
@click.option('--hash-type', '-m', default=0, type=click.IntRange(0, 5), help='Хэш функция', show_default=True)
@click.argument('filename', nargs=1, type=click.Path(exists=True))
@click.argument('mask', nargs=1, default="?1?1?1?1?1", callback=check_mask)
def start(a, increment_min, increment_max, i, filename, mask, m1, dictionary, hash_type):
    if a == 1:
        with open(filename, 'r') as f:
                nums = f.read().splitlines()
                for user_hash in nums:
                    brute_force_by_dict(dictionary, user_hash, parse_function(hash_type))
    elif a == 2:
        with open(filename, 'r') as f:
                nums = f.read().splitlines()
                for user_hash in nums:
                   print("\tХэш: " + user_hash + " пароль: " + brute_force_by_rainbow_table(dictionary, user_hash))
    elif a == 3:
        print("q - выход из программы\ts - вывод текущего статуса перебора")
        time.sleep(2)
        if i:
            with open(filename, 'r') as f:
                nums = f.read().splitlines()
                password_found = []
                for i in range(len(nums)):
                    password_found.append(False)
                for u in range(increment_min, increment_max + 1):
                    true_count = 0
                    for item in password_found:
                        if item:
                            true_count += 1
                    if true_count == len(password_found):
                        break
                    print(str(u) + " символа:")
                    for user_hash_id in range(len(nums)):
                        if not password_found[user_hash_id]:
                            new_mask = mask[0:u*2]
                            new_mask = new_mask.replace("?1","?" + ''.join(m1.split('?')))
                            password_found[user_hash_id] = brute_force_by_mask(nums[user_hash_id], new_mask, parse_function(hash_type))
                            if close_prog:
                                return
        else:
            with open(filename, 'r') as f:
                nums = f.read().splitlines()
                for user_hash in nums:
                    new_mask = mask.replace("?1","?" + ''.join(m1.split('?')))
                    brute_force_by_mask(user_hash, new_mask, parse_function(hash_type))
                    if close_prog:
                        return

if __name__ == '__main__':
    start()